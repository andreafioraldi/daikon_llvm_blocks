#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <climits>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <fstream>

#include "RangeAnalysis.h"
#include "SourceMapping.h"

#define MAX_DEPTH 3
#define WRONG_IDX 101

using namespace llvm;
using namespace RangeAnalysis;


static size_t TypeSizeToSizeIndex(uint32_t TypeSize) {
  if (TypeSize == 1) TypeSize = 8;
  size_t Res = countTrailingZeros(TypeSize / 8);
  return Res;
}

static void ReplaceAll(std::string& S, std::string P, std::string R) {
  size_t pos = S.find(P);
  while(pos != std::string::npos) {
    S.replace(pos, P.size(), R);
    pos = S.find(P, pos + R.size());
  }
}


static std::string GetVarName(Value* V) {

  std::string name;
  if (V->hasName())
    return "_" + V->getName().str();
  return "";
}

	
static Instruction *IRBSplitBlockAndInsertIfThen(IRBuilder<>& IRB, Value *Cond,
                                          Instruction *SplitBefore,
                                          BasicBlock *ThenTarget = nullptr,
                                          bool Unreachable = false) {
   BasicBlock *Head = SplitBefore->getParent();
   BasicBlock *Tail = Head->splitBasicBlock(SplitBefore->getIterator());
   Instruction *HeadOldTerm = Head->getTerminator();
   LLVMContext &C = Head->getContext();
   Instruction *CheckTerm;
   BasicBlock *ThenBlock = BasicBlock::Create(C, "", Head->getParent(), Tail);
   if (Unreachable)
     CheckTerm = new UnreachableInst(C, ThenBlock);
   else if (ThenTarget)
     CheckTerm = BranchInst::Create(ThenTarget, ThenBlock);
   else
     CheckTerm = BranchInst::Create(Tail, ThenBlock);
   CheckTerm->setDebugLoc(SplitBefore->getDebugLoc());
   BranchInst *HeadNewTerm =
     BranchInst::Create(/*ifTrue*/ThenBlock, /*ifFalse*/Tail, Cond);
   ReplaceInstWithInst(HeadOldTerm, HeadNewTerm);
   IRB.SetInsertPoint(&*Tail->getFirstInsertionPt());
   return CheckTerm;
}


static void IRBSplitBlockAndInsertIfThenElse(IRBuilder<>& IRB, Value *Cond,
                                      Instruction *SplitBefore,
                                      Instruction **ThenTerm,
                                      Instruction **ElseTerm) {
  BasicBlock *Head = SplitBefore->getParent();
  BasicBlock *Tail = Head->splitBasicBlock(SplitBefore->getIterator());
  Instruction *HeadOldTerm = Head->getTerminator();
  LLVMContext &C = Head->getContext();
  BasicBlock *ThenBlock = BasicBlock::Create(C, "", Head->getParent(), Tail);
  BasicBlock *ElseBlock = BasicBlock::Create(C, "", Head->getParent(), Tail);
  *ThenTerm = BranchInst::Create(Tail, ThenBlock);
  (*ThenTerm)->setDebugLoc(SplitBefore->getDebugLoc());
  *ElseTerm = BranchInst::Create(Tail, ElseBlock);
  (*ElseTerm)->setDebugLoc(SplitBefore->getDebugLoc());
  BranchInst *HeadNewTerm =
   BranchInst::Create(/*ifTrue*/ThenBlock, /*ifFalse*/ElseBlock, Cond);
  ReplaceInstWithInst(HeadOldTerm, HeadNewTerm);
  IRB.SetInsertPoint(&*Tail->getFirstInsertionPt());
}


struct BBInfo {

  std::string Name;

  std::vector< Value* > Locals;
  std::vector< std::vector<Value*> > GEPs;
  std::vector< std::vector<Value*> > LDs;
  std::vector< std::vector<Value*> > STs;

};


struct LLVMDaikonDump {

  LLVMDaikonDump(Module& _M, Function &_F, LoopInfo &_LI, IntraProceduralRA<Cousot> &_RA) : M(_M), F(_F), LI(_LI), RA(_RA) {
    initialize();
  }
  
  static bool isBlacklisted(const Function *F) {

    static const char *Blacklist[] = {

        "asan.", "llvm.", "sancov.", "__ubsan_handle_", "ign.", "__afl_",
        "_fini", "__libc_csu", "__asan",  "__msan", "msan."

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) return true;

    }
    
    if (F->getName() == "_start") return true;

    return false;

  }
  
  void initialize();
  bool instrumentFunction();
  
  bool dumpVariable(IRBuilder<>& IRB, std::map<Value*, int>& Comp, std::string prefix_name, Value* V, SourceVarRecovery*);

  Type *VoidTy, *Int8Ty, *Int16Ty, *Int32Ty, *Int64Ty, *FloatTy, *DoubleTy,
       *StructTy, *Int8PTy, *Int16PTy, *Int32PTy, *Int64PTy, *FloatPTy,
       *DoublePTy, *StructPTy, *FuncTy;
  Type *IntTypeSized[4];

  Function* dbgDeclareFn;

  FunctionCallee llvmdaikonDumpSignedIntFns[4];
  FunctionCallee llvmdaikonDumpUnsignedIntFns[4];
  FunctionCallee llvmdaikonDumpFloatFn, llvmdaikonDumpDoubleFn;
  FunctionCallee llvmdaikonDumpNosenseFn;
  
  FunctionCallee llvmdaikonDumpLockFn, llvmdaikonDumpUnlockFn;
  FunctionCallee llvmdaikonDumpEnterPrologueFn, llvmdaikonDumpExitPrologueFn,
                 llvmdaikonDumpEpilogueFn, llvmdaikonDumpLoopPrologueFn;
  
  FunctionCallee llvmdaikonAreaIsMappedFn, llvmdaikonAreaIsValidFn;
  
  FunctionCallee randFn;
  
  LLVMContext *C;
  Module& M;
  Function &F;
  LoopInfo &LI;
  IntraProceduralRA<Cousot> &RA;
  int LongSize;
  
  bool hasCalls;
  std::map< Type*, std::set<unsigned> > usedFields;
  std::map< Type*, MDNode* > structMDs;
  std::map< Type*, bool > usedForCalls;
  
  std::vector<DILocalVariable*> DbgVars;
  
  std::string funcname;
  std::ofstream decls;
	std::ofstream sym_decls;
  std::string llvmdaikon_output_path;

};

void LLVMDaikonDump::initialize() {

  if (getenv("LLVMDAIKON_OUTPUT_PATH"))
    llvmdaikon_output_path = getenv("LLVMDAIKON_OUTPUT_PATH");
  else
    llvmdaikon_output_path = "llvmdaikon_output";

  
  funcname = M.getModuleIdentifier() + ":" + F.getName().str();
  if (funcname.size() >= 2 && funcname[0] == '.' && funcname[1] == '/')
    funcname.erase(0, 2);
  ReplaceAll(funcname, "\\", "\\\\"); // llvmdaikon naming convention
  ReplaceAll(funcname, " ", "\\_");
  ReplaceAll(funcname, "/", "_");

  C = &(M.getContext());
  
  LongSize = M.getDataLayout().getPointerSizeInBits();

  VoidTy = Type::getVoidTy(*C);

  Int8Ty = IntegerType::get(*C, 8);
  Int16Ty = IntegerType::get(*C, 16);
  Int32Ty = IntegerType::get(*C, 32);
  Int64Ty = IntegerType::get(*C, 64);

  FloatTy = Type::getFloatTy(*C);
  DoubleTy = Type::getDoubleTy(*C);

  StructTy = StructType::create(*C);
  
  Int8PTy  = PointerType::get(Int8Ty, 0);
  Int16PTy = PointerType::get(Int16Ty, 0);
  Int32PTy = PointerType::get(Int32Ty, 0);
  Int64PTy = PointerType::get(Int64Ty, 0);

  FloatPTy = PointerType::get(FloatTy, 0);
  DoublePTy = PointerType::get(DoubleTy, 0);

  StructPTy = PointerType::get(StructTy, 0);

  FuncTy = FunctionType::get(VoidTy, true);

  dbgDeclareFn = M.getFunction("llvm.dbg.declare");
  
  IntTypeSized[0] = Int8Ty;
  IntTypeSized[1] = Int16Ty;
  IntTypeSized[2] = Int32Ty;
  IntTypeSized[3] = Int64Ty;
  
  llvmdaikonDumpSignedIntFns[0] = M.getOrInsertFunction("__llvmdaikon_dump_i8", VoidTy, Int8PTy, Int8Ty);
  llvmdaikonDumpSignedIntFns[1] = M.getOrInsertFunction("__llvmdaikon_dump_i16", VoidTy, Int8PTy, Int16Ty);
  llvmdaikonDumpSignedIntFns[2] = M.getOrInsertFunction("__llvmdaikon_dump_i32", VoidTy, Int8PTy, Int32Ty);
  llvmdaikonDumpSignedIntFns[3] = M.getOrInsertFunction("__llvmdaikon_dump_i64", VoidTy, Int8PTy, Int64Ty);
  
  llvmdaikonDumpUnsignedIntFns[0] = M.getOrInsertFunction("__llvmdaikon_dump_u8", VoidTy, Int8PTy, Int8Ty);
  llvmdaikonDumpUnsignedIntFns[1] = M.getOrInsertFunction("__llvmdaikon_dump_u16", VoidTy, Int8PTy, Int16Ty);
  llvmdaikonDumpUnsignedIntFns[2] = M.getOrInsertFunction("__llvmdaikon_dump_u32", VoidTy, Int8PTy, Int32Ty);
  llvmdaikonDumpUnsignedIntFns[3] = M.getOrInsertFunction("__llvmdaikon_dump_u64", VoidTy, Int8PTy, Int64Ty);
  
  llvmdaikonDumpFloatFn = M.getOrInsertFunction("__llvmdaikon_dump_f", VoidTy, Int8PTy, FloatTy);
  llvmdaikonDumpDoubleFn = M.getOrInsertFunction("__llvmdaikon_dump_d", VoidTy, Int8PTy, DoublePTy);
  
  llvmdaikonDumpNosenseFn = M.getOrInsertFunction("__llvmdaikon_dump_nosense", VoidTy, Int8PTy);
  
  llvmdaikonDumpLockFn = M.getOrInsertFunction("__llvmdaikon_dump_lock", VoidTy);
  llvmdaikonDumpUnlockFn = M.getOrInsertFunction("__llvmdaikon_dump_unlock", VoidTy);
  
  Type* SizeTTy = IntTypeSized[TypeSizeToSizeIndex(LongSize)];
  llvmdaikonDumpEnterPrologueFn = M.getOrInsertFunction("__llvmdaikon_dump_enter_prologue", SizeTTy, Int8PTy);
  llvmdaikonDumpExitPrologueFn = M.getOrInsertFunction("__llvmdaikon_dump_exit_prologue", VoidTy, Int8PTy, Int32Ty, SizeTTy);
  llvmdaikonDumpEpilogueFn = M.getOrInsertFunction("__llvmdaikon_dump_epilogue", VoidTy);
  llvmdaikonDumpLoopPrologueFn = M.getOrInsertFunction("__llvmdaikon_dump_loop_prologue", SizeTTy, Int8PTy, Int32Ty);
  
  llvmdaikonAreaIsMappedFn = M.getOrInsertFunction("__llvmdaikon_area_is_mapped", Int8Ty, Int8PTy, SizeTTy);
  llvmdaikonAreaIsValidFn = M.getOrInsertFunction("__llvmdaikon_area_is_valid", Int8Ty, Int8PTy, SizeTTy);
  
  randFn = M.getOrInsertFunction("rand", Int32Ty);

}

bool LLVMDaikonDump::dumpVariable(IRBuilder<>& IRB, std::map<Value*, int>& Comp, std::string prefix_name, Value* V, SourceVarRecovery* svr) {

  bool FunctionModified = false;
  Type *T = V->getType();
  
  std::string name = prefix_name + GetVarName(V);
  int CompID = -1;
  if (Comp.find(V) != Comp.end())
    CompID = Comp[V];
  
  Range Rng = RA.getRange(V);
  
   switch (T->getTypeID()) {
    case Type::IntegerTyID: {
      TypeSize BitsNum = T->getPrimitiveSizeInBits();
      if (BitsNum > 64) break;
      
      if (BitsNum == 1)
        V = IRB.CreateIntCast(V, Int8Ty, true);
      
      size_t SizeIndex = TypeSizeToSizeIndex(BitsNum);
      
      decls << "      {\"name\": \"" << name << "\", \"kind\": "
            << "\"var\", \"comp\": " << CompID << ", \"addr\": " << V;

	  	if (svr) {
	  		sym_decls << "{\"name\": \"" << svr->src_symbol << "\", \"line\" : \"" << svr->line 
				<< "\", \"col\": \"" << svr->col << "\", \"file\": \"" 
				<< svr->file << "\", \"ir_name\": \"" << name;
	  	}	

      bool Signed = true; // min >= 0 false
      if (BitsNum > 1 && !Rng.isUnknown() && !Rng.isEmpty()) {
        bool HasMin = !Rng.getLower().eq(RA.getMin()) && Rng.getLower().getActiveBits() <= 64;
        bool HasMax = !Rng.getUpper().eq(RA.getMax()) && Rng.getUpper().getActiveBits() <= 64;
        if (HasMin && HasMax) {
          switch(SizeIndex) {
            case 0: {
              int8_t A = (int8_t)Rng.getLower().getSExtValue();
              int8_t B = (int8_t)Rng.getUpper().getSExtValue();
              if (B < A) {
                uint8_t UA = (uint8_t)Rng.getLower().getZExtValue();
                uint8_t UB = (uint8_t)Rng.getUpper().getZExtValue();
                if (B >= A) {
                  decls << ", \"min\": " << (unsigned)UA;
                  if (UB < UCHAR_MAX) decls << ", \"max\": " << (unsigned)UB;
                  Signed = false;
                }
              } else {
                if (A >= 0) Signed = false;
                if (A > SCHAR_MIN) decls << ", \"min\": " << (int)A;
                if (B < SCHAR_MAX) decls << ", \"max\": " << (int)B;
              }
              break;
            }
            case 1: {
              int16_t A = (int16_t)Rng.getLower().getSExtValue();
              int16_t B = (int16_t)Rng.getUpper().getSExtValue();
              if (B < A) {
                uint16_t UA = (uint16_t)Rng.getLower().getZExtValue();
                uint16_t UB = (uint16_t)Rng.getUpper().getZExtValue();
                if (B >= A) {
                  decls << ", \"min\": " << UA;
                  if (UB < USHRT_MAX) decls << ", \"max\": " << UB;
                  Signed = false;
                }
              } else {
                if (A >= 0) Signed = false;
                if (A > SHRT_MIN) decls << ", \"min\": " << A;
                if (B < SHRT_MAX) decls << ", \"max\": " << B;
              }
              break;
            }
            case 2: {
              int32_t A = (int32_t)Rng.getLower().getSExtValue();
              int32_t B = (int32_t)Rng.getUpper().getSExtValue();
              if (B < A) {
                uint32_t UA = (uint32_t)Rng.getLower().getZExtValue();
                uint32_t UB = (uint32_t)Rng.getUpper().getZExtValue();
                if (B >= A) {
                  decls << ", \"min\": " << UA;
                  if (UB < UINT_MAX) decls << ", \"max\": " << UB;
                  Signed = false;
                }
              } else {
                if (A >= 0) Signed = false;
                if (A > INT_MIN) decls << ", \"min\": " << A;
                if (B < INT_MAX) decls << ", \"max\": " << B;
              }
              break;
            }
            case 3: {
              int64_t A = (int64_t)Rng.getLower().getSExtValue();
              int64_t B = (int64_t)Rng.getUpper().getSExtValue();
              if (B < A) {
                uint64_t UA = (uint64_t)Rng.getLower().getZExtValue();
                uint64_t UB = (uint64_t)Rng.getUpper().getZExtValue();
                if (B >= A) {
                  decls << ", \"min\": " << UA;
                  if (UB < UINT_MAX) decls << ", \"max\": " << UB;
                  Signed = false;
                }
              } else {
                if (A >= 0) Signed = false;
                if (A > INT_MIN) decls << ", \"min\": " << A;
                if (B < INT_MAX) decls << ", \"max\": " << B;
              }
              break;
            }
          }
        } else if (HasMin) {
          int64_t A = (int64_t)Rng.getLower().getSExtValue();
          if (A >= 0) Signed = false;
          switch(SizeIndex) {
            case 0:
            decls << ", \"min\": " << (int)(int8_t)Rng.getLower().getSExtValue();
            break;
            case 1:
            decls << ", \"max\": " << (int16_t)Rng.getLower().getSExtValue();
            break;
            case 2:
            decls << ", \"max\": " << (int32_t)Rng.getLower().getSExtValue();
            break;
            case 3:
            decls << ", \"max\": " << (int64_t)Rng.getLower().getSExtValue();
            break;
          }
        } else if (HasMax) {
          switch(SizeIndex) {
            case 0:
            decls << ", \"max\": " << (int)(int8_t)Rng.getUpper().getSExtValue();
            break;
            case 1:
            decls << ", \"max\": " << (int16_t)Rng.getUpper().getSExtValue();
            break;
            case 2:
            decls << ", \"max\": " << (int32_t)Rng.getUpper().getSExtValue();
            break;
            case 3:
            decls << ", \"max\": " << (int64_t)Rng.getUpper().getSExtValue();
            break;
          }
        }
      }
      decls << ", \"signed\": " << Signed <<  ", \"type\": \""
            << (Signed ? "i" : "u") << BitsNum << "\"},\n";
			if (svr)
      	sym_decls <<  "\"},\n";
      
      Value *N = IRB.CreateGlobalStringPtr(name);
      Value *I = IRB.CreateBitCast(V, IntTypeSized[SizeIndex]);
      CallInst* CI;
      if (Signed)
        CI = IRB.CreateCall(llvmdaikonDumpSignedIntFns[SizeIndex], ArrayRef<Value*>{N, I});
      else
        CI = IRB.CreateCall(llvmdaikonDumpUnsignedIntFns[SizeIndex], ArrayRef<Value*>{N, I});
      CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
      
      FunctionModified = true;
      break;
    }
    //case Type::FloatTyID: {

    //  decls << "      {\"name\": \"" << name << "\", \"type\": \"" << "float"
    //        << "\", \"kind\": " << "\"var\", \"comp\": " << CompID
    //        << ", \"addr\": " << V << "},\n";
		//	if (svr) {
	  //		sym_decls << "{\"name\": \"" << svr->src_symbol << "\", \"line\" : \"" << svr->line 
		//		<< "\", \"col\": \"" << svr->col << "\", \"file\": \"" 
		//		<< svr->file << "\", \"ir_name\": \"" << name << "\"},\n";
	  //	}	
    //
    //  Value *N = IRB.CreateGlobalStringPtr(name);
    //  Value *I = IRB.CreateBitCast(V, FloatTy);
    //  CallInst* CI = IRB.CreateCall(llvmdaikonDumpFloatFn, ArrayRef<Value*>{N, I});
    //  CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    //  
    //  FunctionModified = true;
    //  break;
    //}
    //case Type::DoubleTyID: {

    //  decls << "      {\"name\": \"" << name << "\", \"type\": \"" << "double"
    //        << "\", \"kind\": " << "\"var\", \"comp\": " << CompID
    //        << ", \"addr\": " << V << "},\n";
		//	if (svr) {
	  //		sym_decls << "{\"name\": \"" << svr->src_symbol << "\", \"line\" : \"" << svr->line 
		//		<< "\", \"col\": \"" << svr->col << "\", \"file\": \"" 
		//		<< svr->file << "\", \"ir_name\": \"" << name << "\"},\n";
	  //	}

    //  Value *N = IRB.CreateGlobalStringPtr(name);
    //  Value *I = IRB.CreateBitCast(V, DoubleTy);
    //  CallInst* CI = IRB.CreateCall(llvmdaikonDumpDoubleFn, ArrayRef<Value*>{N, I});
    //  CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));

    //  FunctionModified = true;
    //  break;
    //}
    case Type::PointerTyID: {

      break;
    }


    default:
      break;
  }

  return FunctionModified;

}

static void AddComp(std::map<Value*, int>& Comp, int& CompID, Value* A) {

  bool hasA = Comp.find(A) != Comp.end();

  if (!hasA) {
    Comp[A] = CompID;
    ++CompID;
  }

}

static void MergeComp(std::map<Value*, int>& Comp, int& CompID, Value* A, Value* B) {

  bool hasA = Comp.find(A) != Comp.end();
  bool hasB = Comp.find(B) != Comp.end();

  if (hasA && !hasB)
    Comp[B] = Comp[A];
  else if(!hasA && hasB)
    Comp[A] = Comp[B];
  else if (!hasA && !hasB) {
    Comp[A] = CompID;
    Comp[B] = CompID;
    ++CompID;
  } else {
    int AID = Comp[A];
    int BID = Comp[B];
    for (auto& K : Comp) {
      if (K.second == BID)
        K.second = AID;
    }
  }

}

bool LLVMDaikonDump::instrumentFunction() {

  bool FunctionModified = false;

  if (isBlacklisted(&F)) return FunctionModified; // not supported

  std::string decls_name = funcname;
  if (decls_name.size() > 200) {
    decls_name = decls_name.substr(0, 200) + "<" + std::to_string((uintptr_t)&F) + ">";
  }

  decls.open(llvmdaikon_output_path + "/" + decls_name + "_decls.literal.part");
	sym_decls.open(llvmdaikon_output_path + "/" + decls_name + "_symbols");
  if (!decls.good()) {
    errs() << "FATAL: Failed to open (w) the file '" << llvmdaikon_output_path + "/" + decls_name + "_decls.literal.part" << "'\n";
    abort();
  }

	if (!sym_decls.good()) {
    errs() << "FATAL: Failed to open (w) the file '" << llvmdaikon_output_path + "/" + decls_name + "_symbols.literal.part" << "'\n";
    abort();
	}
 
  
  std::map<Value*, Symbol*> Symbols;
  std::vector<BasicBlock*> BBs;
  std::set<Value*> DbgVals;
  std::map<Value*, SourceVarRecovery> DbgVals2Symbol;
  std::map<Value*, SourceExpr*> InstructionMapper;

  std::map<Value*, int> Comp;
  int CompID = 0;

	std::string s = F.getName();
	
	DISubprogram* sub_program = F.getSubprogram();
    if (sub_program) {
	    Metadata* md_func_type = sub_program->getType();  
	    if (auto sub_type = dyn_cast<DISubroutineType>(md_func_type)) {
 	    	unsigned arg_type_counter = 1; 
  	    for(Function::arg_iterator it = F.arg_begin(); it != F.arg_end(); ++it) {
  	      Argument *A = &*it;
  	      Value *V = static_cast<Value*>(A);

  	      if (DbgVals.find(V) == DbgVals.end()) {
  	        DbgVals.insert(V);
            DITypeRefArray type_array = sub_type->getTypeArray();
            if (arg_type_counter >= type_array.size())
              continue;
            DIType* arg_type = type_array[arg_type_counter];
	    			arg_type_counter++;
	    			
	    			std::string _src_symbol = A->getName().str();
	    			std::string _file = sub_program->getFile()->getFilename().str();
	    			unsigned int _line = sub_program->getLine();

	    			//errs() << "Found arg with name " << _src_symbol << "\n";
	    			SourceType* source_type = new SourceType;

	    			std::vector<DIType*> v;
	    			buildTypeSystem(arg_type, source_type, v);	
	    			Symbol* sym = new Symbol;
	    			sym->sym_name = _src_symbol;
	    			sym->type = source_type;
	    			
	    			std::map<Value*, Symbol*>::iterator it = Symbols.find(V);
	    			if (it == Symbols.end()) {
	    				Symbols[V] = sym;
	    			}
            SourceVarRecovery svr = SourceVarRecovery(_src_symbol, _file, _line, 0);
	    			DbgVals2Symbol[V] = svr;

            //SourceExpr tt = SourceExpr(source_type, svr);
            //errs() << tt.type->name << "\n";
            //errs() << tt.SVR.src_symbol << "\n";
            InstructionMapper[V] = new SourceExpr(source_type, new SourceVarRecovery(_src_symbol, _file, _line, 0)); 

	    		}
  	      
  	    }
	    }
    }

  for (auto &BB : F) {
    BBs.push_back(&BB);
    for (auto &Inst : BB) {
    
      if (UnaryOperator* O = dyn_cast<UnaryOperator>(&Inst)) {
        MergeComp(Comp, CompID, O, O->getOperand(0));
      } else if (BinaryOperator* O = dyn_cast<BinaryOperator>(&Inst)) {
        MergeComp(Comp, CompID, O->getOperand(0), O->getOperand(1));
        MergeComp(Comp, CompID, O, O->getOperand(1));
      } else if (CastInst* C = dyn_cast<CastInst>(&Inst)) {
        MergeComp(Comp, CompID, C, C->getOperand(0));
      } else if (GetElementPtrInst* G = dyn_cast<GetElementPtrInst>(&Inst)) {
        MergeComp(Comp, CompID, G, G->getPointerOperand());
        Value* First = nullptr;
        for (auto Idx = G->idx_begin(); Idx != G->idx_end(); ++Idx) {
          if (Idx->get() && !isa<ConstantInt>(Idx->get())) {
            if (First) MergeComp(Comp, CompID, First, Idx->get());
            else First = Idx->get();
          }
        }
      } else if (LoadInst* L = dyn_cast<LoadInst>(&Inst)) {
        AddComp(Comp, CompID, L);
      }
    
      if (DbgValueInst* DbgValue = dyn_cast<DbgValueInst>(&Inst)) {
        if (DbgValue->getValue()&& !isa<Constant>(DbgValue->getValue()) && 
            DbgVals.find(DbgValue->getValue()) == DbgVals.end()) {
					Value* V = DbgValue->getValue();
          DbgVals.insert(V);
					Value* operand_1 = DbgValue->getOperand(1);
					if (auto md_as_val = dyn_cast<MetadataAsValue>(operand_1)) {
						Metadata* md = md_as_val->getMetadata();
						if (auto local_var = dyn_cast<DIVariable>(md)) {
							DILocation* loc = DbgValue->getDebugLoc();
              SourceVarRecovery svr = SourceVarRecovery(local_var->getName(), loc->getFilename(), local_var->getLine(), 0);
							DbgVals2Symbol[V] = svr;
							DIType* base_type = local_var->getType();
							SourceType* source_type = new SourceType;
							//errs() << "Source Code Symbol: " << local_var->getName();
							std::vector<DIType*> v;
							buildTypeSystem(base_type, source_type, v);
							//debug_type(source_type);
							Symbol* sym = new Symbol;
							sym->sym_name = local_var->getName();
							sym->type = source_type;
							
							std::map<Value*, Symbol*>::iterator it = Symbols.find(operand_1);

              InstructionMapper[V] = new SourceExpr(source_type, new SourceVarRecovery(local_var->getName(), loc->getFilename(), local_var->getLine(), 0));

							if (it == Symbols.end()) {
								Symbols[operand_1] = sym;

							}

						}
						else {
						}
					}
				}

      } else if(ReturnInst* RI = dyn_cast<ReturnInst>(&Inst)) {
      
        Value* RV = RI->getReturnValue();
        if (RV && DbgVals.find(RV) == DbgVals.end()) {
          DbgVals.insert(RV);
					DILocation* loc = RI->getDebugLoc();
          SourceVarRecovery svr = SourceVarRecovery("__retval__", loc->getFilename(), loc->getLine(), loc->getColumn());
					DbgVals2Symbol[RV] = svr;
          Symbol* sym = new Symbol;
          sym->sym_name = "__retval__";
          SourceType *sym_type = new SourceType("int", "");
          sym->type = nullptr;
          InstructionMapper[RV] = new SourceExpr(sym_type, new SourceVarRecovery( "__retval__", loc->getFilename(), loc->getLine(), loc->getColumn())); //TODO Fix return type
				}
     
      }
		
    }
  }
  
  std::map<BasicBlock*, BBInfo> Infos;
	std::map<BasicBlock*, BBLocations> Locs;
	std::map<LoadInst*, SourceVarRecovery> LoadsSrc;
	std::map<StoreInst*, SourceVarRecovery> StoresSrc;
	std::map<GetElementPtrInst*, SourceVarRecovery> GEPsSrc;

	  
  for (auto BB : BBs) {
  
    std::string BBp;
    raw_string_ostream OS(BBp);
    BB->printAsOperand(OS, false);
    auto BBname = funcname + "#" + OS.str();
  
    Infos[BB].Name = BBname;
    
    for (auto &Inst : *BB) {

			//else if (DbgAddrIntrinsic* dbg_addr = dyn_cast<DbgAddrIntrinsic>(&Inst)) {
			//	errs() << "Debug Addr Intrinsic\n";
			//}
			//else if (DbgLabelInst* dbg_label = dyn_cast<DbgLabelInst>(&Inst)) {
			//	errs() << "Debug Label Inst\n";
			//}
			if (DbgDeclareInst* dbg_decl = dyn_cast<DbgDeclareInst>(&Inst)) {
				Metadata* md_ref_var = cast<MetadataAsValue>(dbg_decl->getOperand(0))->getMetadata();
				Value* operand_1 = dbg_decl->getArgOperand(1);
				if (auto md_as_val = dyn_cast<MetadataAsValue>(operand_1)) {
					Metadata* md_src_var = md_as_val->getMetadata();
					Value* referenced_var = cast<ValueAsMetadata>(md_ref_var)->getValue();
					AllocaInst* alloc_inst = dyn_cast<AllocaInst>(referenced_var);
					if (alloc_inst == NULL)
						continue;	//TODO investigate what happens in these cases;
					std::string ir_var = alloc_inst->getName().str();

					if (auto di_node = dyn_cast<DIVariable>(md_src_var)) {
		
						std::string sym_name = di_node->getName();

						SourceType* source_type = new SourceType;
						//errs() << "\tSource Code Variable: " << sym_name << "\n";
						DIType* base_type = di_node->getType();	
						std::vector<DIType*> v;
						buildTypeSystem(base_type, source_type, v);
						//debug_type(source_type);
						Symbol* sym = new Symbol;
						sym->sym_name = sym_name;
						sym->type = source_type;
						
						std::map<Value*, Symbol*>::iterator it = Symbols.find(referenced_var);
						if (it == Symbols.end()) {
							Symbols[referenced_var] = sym;
						}

            InstructionMapper[referenced_var] = new SourceExpr(source_type, new SourceVarRecovery(sym_name, "", 0, 0));

						for (const Use &U : alloc_inst->uses()) {
							///errs() << "Found Use of Local Var\n";
							User* u = U.getUser();
							std::string _file("");
							unsigned int _line = 0;
							unsigned int _col = 0;
							if (Instruction* I = dyn_cast<Instruction>(u)) {
								DILocation* loc = I->getDebugLoc();
								if (loc) {
									_file = loc->getFilename();
									_line = loc->getLine();
									_col = loc->getColumn();
								}
							}			

							if (LoadInst* L = dyn_cast<LoadInst>(u)) {
								LoadsSrc[L] =  SourceVarRecovery(sym_name, _file, _line, _col);

							}
							else if (StoreInst* S = dyn_cast<StoreInst>(u)) {
								StoresSrc[S] =  SourceVarRecovery(sym_name, _file, _line, _col);
							}
							else if (GetElementPtrInst* G = dyn_cast<GetElementPtrInst>(u)) {
								GEPsSrc[G] = SourceVarRecovery(sym_name, _file, _line, _col);
							}
						}
					}
				}
				
			}
      // We extract GLOBAL variables
      else {
        for (auto operand = Inst.operands().begin(); operand != Inst.operands().end(); ++operand) {
          Value* op_val = operand->get();

          GlobalVariable* GV = nullptr;
          DIGlobalVariable* DebugGlobal = nullptr;
          Value* Var = nullptr;
          Symbol* sym = nullptr;
          SourceType* source_type = nullptr;
          bool isExternalLinkage = false;

          if((GV = dyn_cast<GlobalVariable>(op_val))){
            DebugGlobal = RetrieveDebugInfoFromGlobalVar(GV, &isExternalLinkage);
            Var = op_val;
          }
          else if (GEPOperator* gepo = dyn_cast<GEPOperator>(op_val)) {
        		if ((GV = dyn_cast<GlobalVariable>(gepo->getPointerOperand()))) {
              DebugGlobal = RetrieveDebugInfoFromGlobalVar(GV, &isExternalLinkage);
              Var = gepo->getPointerOperand();
        		}
        		for (auto it = gepo->idx_begin(), et = gepo->idx_end(); it != et; ++it)
        		{
            	if ((GV = dyn_cast<GlobalVariable>(*it))) {
                DebugGlobal = RetrieveDebugInfoFromGlobalVar(GV, &isExternalLinkage);
                Var = *it;
            	}
        		}

          }
          else if (isa<Instruction>(op_val)) {
            if(Instruction* NestedInstr = dyn_cast<Instruction>(op_val)) {
              for (auto nested_operand = NestedInstr->operands().begin(); nested_operand != NestedInstr->operands().end(); ++nested_operand) {
                Value* OperandValue = operand->get();
                DebugGlobal = RetrieveDebugInfoFromGlobalVar(GV, &isExternalLinkage);
                Var = OperandValue;
              }
            }
          }

          if (DebugGlobal) {
            DIType* base_type = DebugGlobal->getType();
            source_type = new SourceType;
            std::vector<DIType*> v;
            buildTypeSystem(base_type, source_type, v);
            sym = new Symbol;
            sym->sym_name = DebugGlobal->getName();
            sym->type = source_type; 
            InstructionMapper[Var] = new SourceExpr(source_type, new SourceVarRecovery(DebugGlobal->getName(),"",0,0));
          }
          //else if (isExternalLinkage) {
          //  source_type = new SourceType();
          //  sym = new Symbol;
          //  sym->sym_name = Var->getName();
          //  if (GV)
          //    buildTypeSystemHeuristic(GV->getValueType(), source_type);
          //  else
          //    source_type->name = "__EXTERNAL__"; 
          //  sym->type = source_type;
          //  InstructionMapper[Var] = new SourceExpr(source_type, new SourceVarRecovery(Var->getName(),"",0,0));
          //  //debug_type(source_type);
          //}
          std::map<Value*, Symbol*>::iterator it = Symbols.find(Var);
          if (it == Symbols.end() && Var && sym && source_type) {
            Symbols[Var] = sym;

          }

          //InstructionMapper[Var] = new SourceExpr(source_type, new SourceVarRecovery());

        }
      }
		}

  //debug_mapper(&InstructionMapper);

	for (auto &Inst : *BB) {

      if (Inst.getMetadata(M.getMDKindID("nosanitize")))
        continue;
      
      if (isa<PHINode>(&Inst)) continue;			

      if (! isa<DbgValueInst>(&Inst) && ! isa<ReturnInst>(&Inst)) {
        Value* Val = dynamic_cast<Value*>(&Inst);
        //errs() << "Instruction: " << Inst.getOpcodeName() << "\n";
				DILocation* l = Inst.getDebugLoc();
        //debug_location(l);
        SourceExpr* res = new SourceExpr();
        BuildExpressionForInstruction(&Inst, &InstructionMapper, &Symbols, res, l);
        std::map<Value*, SourceExpr*>::iterator it = InstructionMapper.find(Val);
        if (res) {

          //errs() << "+++++{" << res->SVR.src_symbol << "}\n";
        }
        if (it == InstructionMapper.end() && res) {
          //errs() << "+++++{" << res->SVR.src_symbol << "}\n";
          if (res->type) {
            //debug_type(res->type);
          }
          InstructionMapper[Val] = res;
        }
        //else if (it != InstructionMapper.end())
        //  errs() << "Already inserted\n";

      }
      
      for (auto op = Inst.op_begin(); op != Inst.op_end(); ++op) {
        Value* V = op->get();
        if (DbgVals.find(V) != DbgVals.end()) {
          if (std::find(Infos[BB].Locals.begin(), Infos[BB].Locals.end(), V) == Infos[BB].Locals.end()) {
            Infos[BB].Locals.push_back(V);
						std::map<Value*, SourceVarRecovery>::iterator it;
						it = DbgVals2Symbol.find(V);
						if (it != DbgVals2Symbol.end())
							Locs[BB].Locals.push_back(&it->second);	
						else {
							Locs[BB].Locals.push_back(NULL);	
						}
					}
        }
      }
    
      if(auto GEP = dyn_cast<GetElementPtrInst>(&Inst)) {

        if(!isa<PointerType>(GEP->getSourceElementType()))
          continue;
        if (!GEP->hasIndices())
          continue;

        std::vector<Value*> OP;
        OP.push_back(GEP->getPointerOperand());
        for (auto Idx = GEP->idx_begin(); Idx != GEP->idx_end(); ++Idx) {
          if (Idx->get() && !isa<ConstantInt>(Idx->get()))
            OP.push_back(Idx->get());
        }
        
        if (OP.size() > 1) {
          Infos[BB].GEPs.push_back(OP);
					std::map<GetElementPtrInst*, SourceVarRecovery>::iterator it;
					it = GEPsSrc.find(GEP);
					if (it != GEPsSrc.end())
						Locs[BB].GEPs.push_back(&it->second);
					else {
						DILocation* l = GEP->getDebugLoc();
            Value* ToSearch = static_cast<Value*>(GEP);
            SourceExpr* E = RecoverExpression(ToSearch, &InstructionMapper, &Symbols);
            if (E && l) {
              UpdateLocation(E, l);
              Locs[BB].GEPs.push_back(&(E->SVR));
            }
            else {
							//errs() << "GEP Location was null\n";
							Locs[BB].GEPs.push_back(NULL);

            }
 					}
				}

      } else if (auto LD = dyn_cast<LoadInst>(&Inst)) {

        std::vector<Value*> OP;
        OP.push_back(LD->getPointerOperand());
        OP.push_back(LD);
        
        Infos[BB].LDs.push_back(OP);
				std::map<LoadInst*, SourceVarRecovery>::iterator it;
				it = LoadsSrc.find(LD);
				if (it != LoadsSrc.end()) 
						Locs[BB].LDs.push_back(&it->second);
				else {

						DILocation* l = LD->getDebugLoc();
	          Value* ToSearch = static_cast<Value*>(LD);
            SourceExpr* E = RecoverExpression(ToSearch, &InstructionMapper, &Symbols);
            if (E && l) {
              UpdateLocation(E, l);
              Locs[BB].LDs.push_back(&(E->SVR));
            }
            else {
							//errs() << "LD Location was null\n";
							Locs[BB].LDs.push_back(NULL);
            }
        
			  }
        
      } else if (auto ST = dyn_cast<StoreInst>(&Inst)) {
        
        std::vector<Value*> OP;
        OP.push_back(ST->getPointerOperand());
        OP.push_back(ST->getValueOperand());
        
        Infos[BB].STs.push_back(OP);
				std::map<StoreInst*, SourceVarRecovery>::iterator it;
				it = StoresSrc.find(ST);
				if (it != StoresSrc.end()) {
					Locs[BB].STs.push_back(&it->second);
				}
				else {
						DILocation* l = ST->getDebugLoc();
	          Value* ToSearch = static_cast<Value*>(ST);
            SourceExpr* E = RecoverExpression(ToSearch, &InstructionMapper, &Symbols);
            if (E && l) {
              UpdateLocation(E, l);
              Locs[BB].STs.push_back(&(E->SVR));
            }
            else {
							//errs() << "ST Location was null\n";
							Locs[BB].STs.push_back(NULL);
            }
        }
      }
    }
  
  }


  
  for (auto BB : BBs) {
  
    std::string BBname = Infos[BB].Name;
    
    M.getOrInsertGlobal(BBname + "__cnt", Int64Ty);
    GlobalVariable* CntGbl = M.getNamedGlobal(BBname + "__cnt");
    CntGbl->setLinkage(GlobalValue::CommonLinkage);
    CntGbl->setInitializer(ConstantInt::get(Int64Ty, 0, true));
    
    IRBuilder<> CntIRB(BB->getTerminator());
    LoadInst* CntL = CntIRB.CreateLoad(CntGbl);
    CntL->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    StoreInst* CntS = CntIRB.CreateStore(CntIRB.CreateAdd(CntL, ConstantInt::get(Int64Ty, 1, true)), CntGbl);
    CntS->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    Instruction* Cmp = CntIRB.Insert(new ICmpInst(ICmpInst::ICMP_ULT, CntL, ConstantInt::get(Int64Ty, 128, true)));
    Instruction* ThenBlock, *ElseBlock;
    IRBSplitBlockAndInsertIfThenElse(CntIRB, Cmp, Cmp->getNextNode(), &ThenBlock, &ElseBlock);
    
    IRBuilder<> RndIRB(ElseBlock);
    CallInst* Rnd = RndIRB.CreateCall(randFn);
    Rnd->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    // rnd & 31
    Value* Guard = RndIRB.CreateAnd(Rnd, ConstantInt::get(Int32Ty, 31, true));
    Instruction* Cmp1 = RndIRB.Insert(new ICmpInst(ICmpInst::ICMP_EQ, Guard, ConstantInt::get(Int32Ty, 0, true)));
    IRBSplitBlockAndInsertIfThen(CntIRB, Cmp1, Cmp1->getNextNode(), ThenBlock->getParent());
    
    IRBuilder<> IRB(ThenBlock);
    
    CallInst* CI = IRB.CreateCall(llvmdaikonDumpLockFn);
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    std::set<Value*> Dumpeds;
    
    std::string BBname1 = BBname;
    ReplaceAll(BBname1, "\"", "\\\"");
    decls << "{\n  \"name\": \"" << BBname1 << "\",\n";
    decls << "  \"ppts\": {\n    \"ENTER\": [\n";


    sym_decls << "{\n  \"name\": \"" << BBname1 << "\",\n";

    sym_decls << "  \"ppts\": {\n    \"ENTER\": [\n";

    Value *N = IRB.CreateGlobalStringPtr(BBname);
    CallInst *InvNonce = IRB.CreateCall(llvmdaikonDumpEnterPrologueFn, ArrayRef<Value*>{N});
    InvNonce->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    for (size_t i = 0; i < Infos[BB].Locals.size(); ++i) {
    
      if (Dumpeds.find(Infos[BB].Locals[i]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LOC_" + std::to_string(i), Infos[BB].Locals[i], Locs[BB].Locals[i]);
        Dumpeds.insert(Infos[BB].Locals[i]);
      }
    
    }
    
    for (size_t i = 0; i < Infos[BB].GEPs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].GEPs[i][0]) &&
          Dumpeds.find(Infos[BB].GEPs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "GEPPtr_" + std::to_string(i), Infos[BB].GEPs[i][0], Locs[BB].GEPs[i]);
        Dumpeds.insert(Infos[BB].GEPs[i][0]);
      }

      for (size_t j = 1; j < Infos[BB].GEPs[i].size(); ++j) {
        if (Dumpeds.find(Infos[BB].GEPs[i][j]) == Dumpeds.end()) {
          dumpVariable(IRB, Comp, "GEPIdx_" + std::to_string(i) + "_" + std::to_string(j), Infos[BB].GEPs[i][j], Locs[BB].GEPs[i]);
          Dumpeds.insert(Infos[BB].GEPs[i][j]);
        }
      }

    }
    
    for (size_t i = 0; i < Infos[BB].LDs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].LDs[i][0]) &&
          Dumpeds.find(Infos[BB].LDs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LDPtr_" + std::to_string(i), Infos[BB].LDs[i][0], Locs[BB].LDs[i]);
        Dumpeds.insert(Infos[BB].LDs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].LDs[i][1]) &&
          Dumpeds.find(Infos[BB].LDs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LDVal_" + std::to_string(i), Infos[BB].LDs[i][1], Locs[BB].LDs[i]);
        Dumpeds.insert(Infos[BB].LDs[i][1]);
      }

    }
    
    for (size_t i = 0; i < Infos[BB].STs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].STs[i][0]) &&
          Dumpeds.find(Infos[BB].STs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "STPtr_" + std::to_string(i), Infos[BB].STs[i][0], Locs[BB].STs[i]);
        Dumpeds.insert(Infos[BB].STs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].STs[i][1]) &&
          Dumpeds.find(Infos[BB].STs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "STVal_" + std::to_string(i), Infos[BB].STs[i][1], Locs[BB].STs[i]);
        Dumpeds.insert(Infos[BB].STs[i][1]);
      }

    }
    
    decls << "    ],\n";
    sym_decls << "    ]\n";


    CI = IRB.CreateCall(llvmdaikonDumpEpilogueFn);
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    decls << "    \"EXIT0" << "\": [\n";
    
    Value *I = ConstantInt::get(Int32Ty, 0, true);
    CI = IRB.CreateCall(llvmdaikonDumpExitPrologueFn, ArrayRef<Value*>{N, I, InvNonce});
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    Dumpeds.clear();
     for (size_t i = 0; i < Infos[BB].Locals.size(); ++i) {
    
      if (Dumpeds.find(Infos[BB].Locals[i]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LOC_" + std::to_string(i), Infos[BB].Locals[i], NULL);
        Dumpeds.insert(Infos[BB].Locals[i]);
      }
    
    }
    
    for (size_t i = 0; i < Infos[BB].GEPs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].GEPs[i][0]) &&
          Dumpeds.find(Infos[BB].GEPs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "GEPPtr_" + std::to_string(i), Infos[BB].GEPs[i][0], NULL);
        Dumpeds.insert(Infos[BB].GEPs[i][0]);
      }

      for (size_t j = 1; j < Infos[BB].GEPs[i].size(); ++j) {
        if (Dumpeds.find(Infos[BB].GEPs[i][j]) == Dumpeds.end()) {
          dumpVariable(IRB, Comp, "GEPIdx_" + std::to_string(i) + "_" + std::to_string(j), Infos[BB].GEPs[i][j], NULL);
          Dumpeds.insert(Infos[BB].GEPs[i][j]);
        }
      }

    }
    
    for (size_t i = 0; i < Infos[BB].LDs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].LDs[i][0]) &&
          Dumpeds.find(Infos[BB].LDs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LDPtr_" + std::to_string(i), Infos[BB].LDs[i][0], NULL);
        Dumpeds.insert(Infos[BB].LDs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].LDs[i][1]) &&
          Dumpeds.find(Infos[BB].LDs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "LDVal_" + std::to_string(i), Infos[BB].LDs[i][1], NULL);
        Dumpeds.insert(Infos[BB].LDs[i][1]);
      }

    }
    
    for (size_t i = 0; i < Infos[BB].STs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].STs[i][0]) &&
          Dumpeds.find(Infos[BB].STs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "STPtr_" + std::to_string(i), Infos[BB].STs[i][0], NULL);
        Dumpeds.insert(Infos[BB].STs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].STs[i][1]) &&
          Dumpeds.find(Infos[BB].STs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, Comp, "STVal_" + std::to_string(i), Infos[BB].STs[i][1], NULL);
        Dumpeds.insert(Infos[BB].STs[i][1]);
      }

    }
    
    decls << "    ]";
    decls << "\n  }\n},\n";
    sym_decls << "\n  }\n},\n";

    
    CI = IRB.CreateCall(llvmdaikonDumpEpilogueFn);
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    CI = IRB.CreateCall(llvmdaikonDumpUnlockFn);
    CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));

  }

  decls.close();
  sym_decls.close();
  
  return FunctionModified;
  
}

class LLVMDaikonDumpFunctionPass : public FunctionPass {
public:
  static char ID;

  explicit LLVMDaikonDumpFunctionPass() : FunctionPass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<IntraProceduralRA<Cousot>>();
  }

  StringRef getPassName() const override {
    return "LLVMDaikonDumpPass";
  }

  bool runOnFunction(Function &F) override {
    Module &M = *F.getParent();
    LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
    IntraProceduralRA<Cousot> &RA = getAnalysis<IntraProceduralRA<Cousot>>();
    LLVMDaikonDump DI(M, F, LI, RA);
    bool r = DI.instrumentFunction();
    verifyFunction(F);
    return r;
  }
};


char LLVMDaikonDumpFunctionPass::ID = 0;

static void registerLLVMDaikonPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {

  PM.add(new LLVMDaikonDumpFunctionPass());

}

static RegisterStandardPasses RegisterLLVMDaikonPass(
    PassManagerBuilder::EP_OptimizerLast, registerLLVMDaikonPass);

static RegisterStandardPasses RegisterLLVMDaikonPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerLLVMDaikonPass);

static RegisterPass<LLVMDaikonDumpFunctionPass>
    X("llvmdaikon-dump", "LLVMDaikonDumpPass",
      false,
      false
    );

