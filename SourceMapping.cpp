#include "llvm/IR/Function.h"
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
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <limits>



#include "SourceMapping.h"

#define MAX_DEPTH 3
#define WRONG_IDX UINT_MAX

using namespace llvm;

//Debug 

void debug_type( SourceType* t) {
	errs() << "\nType: \n\tname {" << t->name << "}\n\tfield name{" << t->field_name <<  "}\n\tno fields {" << std::to_string(t->fields.size()) << "}\n\t ptr {" << t->ptr << "}\n\t is array {" << t->is_array << "}\n";
  if (t->fields.size() != 0) {
    for (std::vector<SourceType*>::iterator it = t->fields.begin(); it != t->fields.end(); it++) {
      SourceType* sub_t = *it;
      errs() << "\nsub type: {" << sub_t->name << "}\n";;
    }
  }
}

void debug_map(std::map<Value*, Symbol*> Symbols) {
	std::map<Value*, Symbol*>::iterator it;
	errs() << "Recovered SYmbols so far\n";
	for (it = Symbols.begin(); it != Symbols.end() ; it++) {
		Symbol* s = it->second;
		errs() << "Sym name {" << s->sym_name << "} , type {" << s->type->name << "\n";
	}
}

void debug_location(DILocation* L) {
  if (L) {
    errs() << "Location:\n\t" << L->getFilename() << "\n\t" << L->getLine() << "\n";
  }
  else
    errs() << "Location was null\n";
}


static const char* TypeIDEnum2String[] = {
    "Void",
    "Half",
    "Float",
    "Double",
    "X86_FP80",
    "FP128",
    "PPC_FP128",
    "Label",
    "Metadata",
    "X86_MMX",
    "Token",
    // Derived types... see DerivedTypes.h file.
    "Integer",
    "Function",
    "Struct",
    "Array",
    "Pointer",
    "Vector"
  };



// Expression and Types Recovery

std::string getMathsFromOpcode(const char* opcode) {
	std::string op(opcode);
	if (op.compare("add") == 0) {
		return "+";
	}
	else if (op.compare("sub") == 0) {
		return "-";
	}
	else {
		//TODO: implement other cases
		return op;
	}
}


SourceType* getFieldFromOffset(SourceType ty, long offset) {
	if (ty.fields.size() > offset) {		
		return ty.fields[offset];
	}

	return NULL;
}


const std::vector<std::string> explode(const std::string& s, const char& c) {
	std::string buff{""};
	std::vector<std::string> v;
	
	for(auto n:s)
	{
		if(n != c) buff+=n; else
		if(n == c && buff != "") { v.push_back(buff); buff = ""; }
	}
	if(buff != "") v.push_back(buff);
	
	return v;
}


unsigned getUnionFieldFromOffset(SourceType ty, std::string s) {

	std::vector<SourceType*>::iterator it;
	unsigned c = 0;
	for (it = ty.fields.begin(); it != ty.fields.end(); ++it) {
		SourceType* st = *it;
    //debug_type(st);
		if (st->name.compare(s) == 0) 
			return c;
		c++;
	}
	return WRONG_IDX;
}

SourceType* BaseUpdated = nullptr;

void copyTypes(SourceType* dst, SourceType* src) {
  if (! dst) {
    dst = new SourceType();
    errs() << "dst was null\n";
  }
  if (!src) {
    errs() << "src was null\n";
    return;
  }
	dst->name = src->name;
	dst->field_name = src->field_name;
	dst->fields = src->fields;
	dst->ptr = src->ptr;
	dst->is_array = src->is_array;
	dst->is_fcn_ptr = src->is_fcn_ptr;
  dst->kind = src->kind;
  
  //debug_type(dst);
  //if (BaseUpdated) {
  //  errs() << "///////////// START\n";
  //  debug_type(BaseUpdated);
  //}
  //else 
  //  errs() << "//////////// NO START\n";
}


//std::string ParseGepOperator(GEPOperator* gepo, std::map<Value*, Symbol*> Syms, SourceType* out_ty) {
//	std::string expr = "";
//	std::string access_field = "->";
//	Value* operand = gepo->getPointerOperand();
//  if (GlobalVariable* gv = dyn_cast<GlobalVariable>(operand))
//  {
//		 expr += runOnOperand(operand, Syms, out_ty);
//  }
//	unsigned counter = 0;
//  for (auto it = gepo->idx_begin(), et = gepo->idx_end(); it != et; ++it)
//  {
//      //if (GlobalVariable* gv = dyn_cast<GlobalVariable>(*it))
//      //{
//      //    errs() << "GVi - " << *gv <<  "\n";
//      //}
//			if (*it == operand) {
//				errs() << "First gep operand, skipping\n";
//			}
//			else {
//				Value* GEPoperand = *it;
//				if 
//			}
//			counter++;
//  }
//  return "";
//}



void debug_src_expr(SourceExpr* S) { 
  errs() << S->SVR.src_symbol << "\n";
  errs() << S->type->name << "\n";
}

void debug_mapper(std::map<Value*, SourceExpr*>* Mapper) {

  std::map<Value*, SourceExpr*>::iterator src_iterator;
  for(src_iterator = Mapper->begin(); src_iterator != Mapper->end(); src_iterator++) {
    Value* V = src_iterator->first;
    SourceExpr* S = src_iterator->second;
    if (V)
      errs() << "Value key {" << V->getName() << "}\n";
    else
      errs() << "Value without Name\n";
    if (S)
      errs() << "DATA {" << S->type->name << "} {" << S->SVR.src_symbol <<"}\n";
    else
      errs() << "S was null\n";
  }
}




SourceExpr* RecoverExpression(Value* ValToSearch, std::map<Value*, SourceExpr*>* Mapper, std::map<Value*, Symbol*>* Syms) {
  std::string expr = "";

  std::map<Value*, SourceExpr*>::iterator src_iterator;
  std::map<Value*, Symbol*>::iterator sym_iterator;
  SourceExpr* SourceOperand = nullptr;
  
  src_iterator = Mapper->find(ValToSearch);
  if (src_iterator != Mapper->end()) {
    SourceOperand = src_iterator->second;
  }
  if (!SourceOperand)
    return nullptr;
  if (!SourceOperand->type && SourceOperand->SVR.src_symbol == "")
    return nullptr;
  return SourceOperand;
}

void CopySrcExpr(SourceExpr* Dst, SourceExpr* Src) {
  if (Dst->type == nullptr)
    Dst->type = new SourceType();
  copyTypes(Dst->type, Src->type);
  Dst->SVR = Src->SVR;
}

void UpdateLocation(SourceExpr* Dst, DILocation* Loc) {
  if (Loc) {
    Dst->SVR.line = Loc->getLine();
    Dst->SVR.col = Loc->getColumn();
    Dst->SVR.file = Loc->getFilename();
  }
}


void PropagateType(SourceType* Dst, SourceType* BaseType, bool array, bool ptr, bool is_union, int field) {
  if (field == -1) {
    copyTypes(Dst, BaseType);
  }
  
  if (array)
    Dst->is_array = false;
  if (ptr)
    Dst->ptr -= 1;
  if (field != -1) {
    //if (! is_union) {

      //debug_type(BaseType);
      SourceType* tmp = new SourceType;
      tmp = getFieldFromOffset(*BaseType, field);
      //debug_type(tmp);
      if (tmp) {
        copyTypes(Dst, tmp);
      }

      //debug_type(Dst);
    //}
    //else {
      // What in case of unions and structs
    //}
  }
  //errs() << "**************\n";
  //debug_type(Dst);
  //errs() << "**************\n";
}
SourceType* OriginalAfterCopy;
void BuildExpressionForInstruction(llvm::User *instruction, std::map<Value*, SourceExpr*>* Mapper, std::map<Value*, Symbol*>* Syms, SourceExpr* expr, DILocation* Loc) {    
    if (instruction == NULL) {
        return;
    }
    if (BinaryOperator* O = dyn_cast<BinaryOperator>(instruction)) {
      Value* Op0 = O->getOperand(0);
      Value* Op1 = O->getOperand(1);
      SourceExpr* tmp_0 = nullptr;
      SourceExpr* tmp_1 = nullptr;
      std::string part_0 = "";
      std::string part_1 = "";
      if (ConstantInt* Const = dyn_cast<ConstantInt>(Op0))  {
        part_0 += std::to_string(Const->getSExtValue());
      }
      else if (Constant* Const = dyn_cast<Constant>(Op0)) {
        part_0 += "__const__";
      }
      else {
		    tmp_0 = RecoverExpression(Op0, Mapper, Syms);
        if (tmp_0)
          part_0 += tmp_0->SVR.src_symbol;
        
      }

      
      if (ConstantInt* Const = dyn_cast<ConstantInt>(Op1)) {
        part_1 += std::to_string(Const->getSExtValue());
      }
      else if (Constant* Const = dyn_cast<Constant>(Op1)) {
        part_1 += "__const__";
      }
      else {
        tmp_1 = RecoverExpression(Op1, Mapper, Syms);
        if (tmp_1)
          part_1 = tmp_1->SVR.src_symbol;
      } 

		  std::string opcode = getMathsFromOpcode(O->getOpcodeName()); 

      if (tmp_1) {
        tmp_1->SVR.src_symbol = part_0 + " " + opcode + " " + part_1;
        CopySrcExpr(expr, tmp_1);
        UpdateLocation(expr, Loc);
        return;
      }
      else if (tmp_0) {
        tmp_0->SVR.src_symbol = part_0 + " " + opcode + " " + part_1;
        CopySrcExpr(expr, tmp_0);
        UpdateLocation(expr, Loc);
        return;
      }      
      else {
        //errs() << "BinaryOperator uncorrect\n";
      }

    }
    else if (LoadInst* LI = dyn_cast<LoadInst>(instruction)) {
      Value* PtrOperand = LI->getPointerOperand(); 
      SourceExpr* tmp = RecoverExpression(LI->getPointerOperand(), Mapper, Syms);
      //debug_src_expr(tmp); 
      if (tmp != NULL) {

        //debug_type(tmp->type);
        CopySrcExpr(expr, tmp);
        UpdateLocation(expr, Loc);
        //debug_src_expr(tmp); 

        //debug_type(tmp->type);
        return;
      }
      else if ( GEPOperator* gepo = dyn_cast<GEPOperator>(PtrOperand)) {
        //errs() << "GEPOPERATOR to implement\n";
        BuildExpressionForInstruction(gepo, Mapper, Syms, expr, Loc);
        //errs() << "Return from nested GEPoperator\n";
        //if (expr)
        //  errs() << "----" << expr->SVR.src_symbol << "\n";
      }
    }
    else if (UnaryOperator* O = dyn_cast<UnaryOperator>(instruction)) {
      SourceExpr* tmp = RecoverExpression(O->getOperand(0), Mapper, Syms);
      tmp->SVR.src_symbol = getMathsFromOpcode(O->getOpcodeName()) + "(" + tmp->SVR.src_symbol + ")";
      if (tmp != NULL) {
        CopySrcExpr(expr, tmp);
        UpdateLocation(expr, Loc);
        return;
      }
    }
    else if (StoreInst* SI = dyn_cast<StoreInst>(instruction)) {
      SourceExpr* tmp = RecoverExpression(SI->getPointerOperand(), Mapper, Syms);
      if (tmp != NULL) {
        CopySrcExpr(expr, tmp);
        UpdateLocation(expr, Loc);
        return;
      }
      
    }
	  else if (GEPOperator* GEP = dyn_cast<GEPOperator>(instruction)) {
      unsigned gep_counter = 0;
      std::string gep_expr = "";
      SourceExpr* Base = nullptr;
      SourceType* BaseType = new SourceType;

      SourceExpr* Idx = nullptr;
      std::string IdxStr;

      SourceExpr* Field = nullptr;
      std::string FieldStr;

      SourceType* ResType = new SourceType;
		  for (auto operand = instruction->operands().begin(); operand != instruction->operands().end(); ++operand) {
        
			  Value* op_val = operand->get();
        
        if (gep_counter == 0) {
          Base = RecoverExpression(op_val, Mapper, Syms);
          if (Base != NULL && Base->type != NULL) {
            BaseType = Base->type;
            //debug_type(BaseType);
          }
          else
            return;
        }
        else if (gep_counter == 1) {


          if (ConstantInt* Const = dyn_cast<ConstantInt>(op_val))
            IdxStr = std::to_string(Const->getSExtValue());
          else {
            Idx = RecoverExpression(op_val, Mapper, Syms);          
            if (Idx != NULL) {
              IdxStr = Idx->SVR.src_symbol;
            }
          }
        }
        else if (gep_counter == 2) {


          if (ConstantInt* Const = dyn_cast<ConstantInt>(op_val))
            FieldStr = std::to_string(Const->getSExtValue());
          else {
            Field = RecoverExpression(op_val, Mapper, Syms);          
            if (Field != NULL) {
              FieldStr = Field->SVR.src_symbol;
            }
          }
          
        }
        else {
          errs() << "Unsupported GEP for now\n";
        }
        gep_counter += 1;
      }
      // Here we put the pieces together
      
      if (BaseType->is_array) {
        gep_expr = Base->SVR.src_symbol;
        if (IdxStr.compare("0") != 0) {
          gep_expr += "[" + IdxStr + "]";
          gep_expr += "." + FieldStr;
        }
        else {
          gep_expr += "[" + FieldStr + "]";
          PropagateType(ResType, BaseType, true, false, false, -1);
          expr->SVR.src_symbol = gep_expr;
          expr->type = new SourceType;
          copyTypes(expr->type, ResType);
          UpdateLocation(expr, Loc);
        }
      }
      else if (BaseType->ptr != 0) {

        //debug_type(BaseType);
        gep_expr = Base->SVR.src_symbol;
        if (IdxStr.compare("0") != 0) {
          gep_expr += "[" + IdxStr + "]";
          gep_expr += "->" + FieldStr; //TODO
        }
        else {

          if (BaseType->kind == llvm::dwarf::DW_TAG_structure_type || 
				      BaseType->kind == llvm::dwarf::DW_TAG_class_type || 
				      BaseType->kind == llvm::dwarf::DW_TAG_union_type ) {
            char* p;
				    long offset = strtol(FieldStr.c_str(), &p, 10);
            PropagateType(ResType, BaseType, false, true, false, offset);
            //debug_type(BaseType);

            gep_expr += "->" + ResType->field_name;
            expr->SVR.src_symbol = gep_expr;
            expr->type = new SourceType;
            copyTypes(expr->type, ResType);
            UpdateLocation(expr, Loc);
          }
          else {

            PropagateType(ResType, BaseType, false, true, false, -1);
            //debug_type(BaseType);
            gep_expr += "[" + IdxStr + "]";
            expr->SVR.src_symbol = gep_expr;
            expr->type = new SourceType;
            copyTypes(expr->type, ResType);
            UpdateLocation(expr, Loc);
          }
        }
      }
      else {
        // Normal struct/union/class
        gep_expr = Base->SVR.src_symbol;
        if (IdxStr.compare("0") != 0) {
          gep_expr += "[" + IdxStr + "]";
          gep_expr += "." + FieldStr; //TODO
        }
        else {

          char* p;
				  long offset = strtol(FieldStr.c_str(), &p, 10);
          PropagateType(ResType, BaseType, false, false, false, offset);

          gep_expr += "." + ResType->field_name;

          expr->SVR.src_symbol = gep_expr;
          expr->type = new SourceType;
          copyTypes(expr->type, ResType);
          UpdateLocation(expr, Loc);
        }


      }
      //debug_type(BaseType); 
      BaseUpdated = BaseType;

    }
    else if (AllocaInst* AI = dyn_cast<AllocaInst>(instruction)) {
      Value* RetAlloca = static_cast<Value*>(AI);
      SourceExpr* tmp = RecoverExpression(RetAlloca, Mapper, Syms);
      if (tmp != NULL) {
        CopySrcExpr(expr, tmp);
        UpdateLocation(expr, Loc);
      } 
      return;
    }

	  else if (CastInst* CI = dyn_cast<CastInst>(instruction)) {
		  if (isa<BitCastInst>(CI)) {
        SourceType* ResType = new SourceType;
        std::string union_subfield;
        SourceExpr* tmp = RecoverExpression(CI->getOperand(0), Mapper, Syms);
        std::string StringExpr;
        if (!tmp)
          return;
        SourceType* ty = tmp->type;
        if (!ty)
          return;
			  //std::string field = runOnOperand(CI->getOperand(0), Syms, &ty);
			  std::string access = "->";
			  if (ty->ptr == 0)
			  		access = ".";
			  if (ty->field_name.compare("") != 0) {// it means its a union/struct
			  		Type* dst_ty = CI->getDestTy();
			  		if (dst_ty) {
			  		  for (Type::subtype_iterator it = dst_ty->subtype_begin(); it != dst_ty->subtype_end(); ++it) {
			  			  Type* t = *it;
			  				if (t->isStructTy()) {
			  				  union_subfield = t->getStructName();
			  				}
			  			}
			  		}
			  }

			  if (union_subfield.compare("") != 0) {
			  	std::vector<std::string> v{explode(union_subfield, '.')};
			  	std::string token = v[v.size() - 1];
          //debug_type(ty);
			  	int tmp_idx = getUnionFieldFromOffset(ty, token);
			  	if (tmp_idx != WRONG_IDX) {
            PropagateType(ResType, ty, false, false, true, tmp_idx);
			  		StringExpr = tmp->SVR.src_symbol + access + ResType->field_name;
            expr->SVR.src_symbol = StringExpr;
            expr->type = new SourceType;
            copyTypes(expr->type, ResType);
            UpdateLocation(expr, Loc);

			  	}
			  	else {
			  		StringExpr = tmp->SVR.src_symbol + access + union_subfield;
            expr->SVR.src_symbol = StringExpr;
            expr->type = new SourceType;
            copyTypes(expr->type, ResType);
            UpdateLocation(expr, Loc);
			  	}

			  }
			  else {
          CopySrcExpr(expr, tmp);
          UpdateLocation(expr, Loc);
          return;
        }
        
      
      }
      else { 
        SourceExpr* tmp = RecoverExpression(CI->getOperand(0), Mapper, Syms);
        if (tmp != NULL) {
          //debug_type(tmp->type);
          CopySrcExpr(expr, tmp);
          UpdateLocation(expr, Loc);
          return;
        }
      }

    }

    else if (CallInst* CI = dyn_cast<CallInst>(instruction)) {
  		Function * f = CI->getCalledFunction();
      if (!f)
        return;
      DISubprogram* sub_program = f->getSubprogram();
      SourceType* source_type = new SourceType;
      if (sub_program) {
        std::string src_string = "";
        Metadata* md_func_type = sub_program->getType();
        if (auto sub_type = dyn_cast<DISubroutineType>(md_func_type)) {
          DITypeRefArray type_array = sub_type->getTypeArray();
          DIType* ret_type = type_array[0];
          std::vector<DIType*> v;
          buildTypeSystem(ret_type, source_type, v);
        }      
      }
      else {
        //source_type->name = "int";
        return;
        //TODO: maybe we need to reconstruct the expression even for library functions ??
        // for now skipping it
      }

      std::string tmp_expr = f->getName().str() + "(";
      SourceExpr* tmp = nullptr;
      for (unsigned i = 0; i < CI->getNumArgOperands(); i++) {
        Value* V = CI->getArgOperand(i);
        tmp = RecoverExpression(V, Mapper, Syms);
        if (!tmp)
          continue;
        if (i != 0)
          tmp_expr += ", ";
        tmp_expr += tmp->SVR.src_symbol;
        
      }
      if (tmp) {
        tmp_expr += ")";
        tmp->SVR.src_symbol = tmp_expr;
        CopySrcExpr(expr, tmp);
        copyTypes(expr->type, source_type);
        UpdateLocation(expr, Loc);
      }
      else {
        tmp_expr += ")";
        expr->SVR.src_symbol = tmp_expr;
        copyTypes(expr->type, source_type);
        UpdateLocation(expr, Loc);
        

      }


      return;
    }
    else if (isa<BranchInst>(instruction) || isa<CmpInst>(instruction)) {
      //Nothing to do
    }
    else {
      Instruction* Inst = dyn_cast<Instruction>(instruction);
      errs() << "Instruction to implement yet\n";
      errs() << "Instruction: " << Inst->getOpcodeName() << "\n";
    }

}



/*
 * Invariants:
 * 1) For 'member' types, we have both type and field name
 * 2) For 'struct/union' we just have the struct name store in 'field_name'
 * 3) For basic type we just have the type name in 'name'
 */

void buildTypeSystem(DIType* base_type, SourceType* source_type, std::vector<DIType*> comp_visited) {

	if (base_type == NULL) {
		return;
	}
	
	if (DIBasicType* basic = dyn_cast<DIBasicType>(base_type)) {
		if (source_type->name.empty()) {
			source_type->name = base_type->getName().str();
		}
	}
	else if (DICompositeType* comp = dyn_cast<DICompositeType>(base_type)) {
		unsigned tag = comp->getTag();
		if (tag == llvm::dwarf::DW_TAG_structure_type || 
				tag == llvm::dwarf::DW_TAG_class_type || 
				tag == llvm::dwarf::DW_TAG_union_type) {
      
      source_type->kind = tag;
      source_type->name = comp->getName();    //<- Probably introduced a bug with this
			if (!(base_type->getName().str().empty()) && (source_type->field_name.empty())) {
				source_type->field_name = base_type->getName().str();
			}
			int num_elements = comp->getElements().size();
			for (int i = 0; i < num_elements; i++) {
				DINode* n = comp->getElements()[i];
				if (auto derived = dyn_cast<DIType>(n)) {
					auto it = std::find(comp_visited.begin(), comp_visited.end(), derived);
					if(it != comp_visited.end()) 
							continue;
					comp_visited.push_back(derived);
					buildTypeSystem(derived, source_type, comp_visited);
				}
				// For classes we will go here, but probably we dont need to store the methods etc..
			}
		}
		else if (tag == llvm::dwarf::DW_TAG_array_type) {
			source_type->is_array = true;
			buildTypeSystem(comp->getBaseType(), source_type, comp_visited);
		}
    else if (tag == llvm::dwarf::DW_TAG_enumeration_type ) {
      buildTypeSystem(comp->getBaseType(), source_type, comp_visited);
    }
		else {
			errs() << "Composite type, unsopported tag " << std::to_string(tag) << "\n";
		}
	}	
	else if (DIDerivedType* derived = dyn_cast<DIDerivedType>(base_type)) {
		unsigned tag = derived->getTag();
		DIType* derived_base_type = derived->getBaseType();
		if (tag == llvm::dwarf::DW_TAG_pointer_type ) {
			source_type->ptr++;
			buildTypeSystem(derived_base_type, source_type, comp_visited);				
		}
		else if (	tag == llvm::dwarf::DW_TAG_const_type ) {	
			buildTypeSystem(derived_base_type, source_type, comp_visited);	
		}
		else if (tag == llvm::dwarf::DW_TAG_typedef ) {
			if (!derived->getName().empty() && source_type->field_name.empty())
				source_type->field_name = derived->getName();
			buildTypeSystem(derived_base_type, source_type, comp_visited);	
		}
		else if (tag == llvm::dwarf::DW_TAG_member) {
			SourceType* member_type = new SourceType;
			member_type->field_name = derived->getName();
			buildTypeSystem(derived_base_type, member_type, comp_visited);
			source_type->fields.push_back(member_type);
		}
		
		else {
			// Consider to implement: reference, ptr_to_member_type
			// https://llvm.org/docs/LangRef.html#diderivedtype
			//errs() << "Derived type, unsopported tag " << std::to_string(tag) << "\n";
		}
	}	
	else if (DISubroutineType* subroutine = dyn_cast<DISubroutineType>(base_type)) {
		source_type->field_name = "fcn_pointer";
		source_type->is_fcn_ptr = true;
	}
	else {
		errs() << "Other debug types not implemented yet, analysis wont be precise\n";
	}
}


void buildTypeSystemHeuristic(Type* T, SourceType* source_type) {
  unsigned id = T->getTypeID();
  std::string name = TypeIDEnum2String[id] + std::string("__heuristic__");
  if (T->isStructTy()) {
    StructType* StructTy = dyn_cast<StructType>(T);
    std::string struct_name = StructTy->getName().str();
    source_type->field_name = struct_name;
    for (unsigned i = 0; i < StructTy->getNumElements(); i++) {
      SourceType* member_type = new SourceType;
      //buildTypeSystemHeuristic(StructTy->getElementType(i), member_type);
      source_type->fields.push_back(member_type);
    }
  }
  else if (T->isFunctionTy()) {
    source_type->is_fcn_ptr = true;
    source_type->name = name;
  }
  else if (T->isArrayTy()) {
    source_type->is_array = true;
    ArrayType* ArrayTy = dyn_cast<ArrayType>(T);
    buildTypeSystemHeuristic(ArrayTy->getElementType(), source_type);
  }
  else if (T->isPointerTy()) {
    source_type->ptr++;
    PointerType* PtrTy = dyn_cast<PointerType>(T);
    buildTypeSystemHeuristic(PtrTy->getElementType(), source_type);
  }
  else
    source_type->name = name;

}


DIGlobalVariable* RetrieveDebugInfoFromGlobalVar(GlobalVariable* GV, bool* isExternalLinkage) {
  if (!GV)
    return nullptr;
  if (GV->hasExternalLinkage()) {
    *isExternalLinkage = true;
    return nullptr;
  }
  SmallVector<DIGlobalVariableExpression *, 1> GVExpr;
  GV->getDebugInfo(GVExpr);
  if (GVExpr.size() != 0) {
    *isExternalLinkage = false;
    return GVExpr[0]->getVariable();
  }
  return nullptr;
}
//void BuildSymbolFromGlobalVariable(GlobalVariable* GV) {
//  SmallVector<DIGlobalVariableExpression *, 1> GVExpr;
//  GV->getDebugInfo(GVExpr);
//  if (GVExpr.size() != 0) {
//    DIGlobalVariable* DebugGlobal = GVExpr[0]->getVariable();
//    errs() << "GlobalVariable " << DebugGlobal->getName() << "\n";
//    DIType* base_type = DebugGlobal->getType();
//    SourceType* source_type = new SourceType;
//    errs() << "Source Code Symbol: " << DebugGlobal->getName();
//    std::vector<DIType*> v;
//    buildTypeSystem(base_type, source_type, v);
//    debug_type(source_type);
//    Symbol* sym = new Symbol;
//    sym->sym_name = DebugGlobal->getName();
//    sym->type = source_type;
//
//    std::map<Value*, Symbol*>::iterator it = Symbols.find(op_val);
//    if (it == Symbols.end()) {
//      Symbols[op_val] = sym;
//    }
//
//
//}
