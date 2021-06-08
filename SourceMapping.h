#include <vector>
#include <string>

using namespace llvm;

// Structs

struct SourceType {
	std::string name;
	std::string field_name; // Dirty hack: if `name` is set, this is a standard type, if `field` is set, it represents the field name
	std::vector<SourceType*> fields;
	short int ptr;	// 1 - normal pointer, 2 - double pointer
	bool is_array;
	bool is_fcn_ptr;
    unsigned kind; // 1 - struct, 2 - union, 3 - class c++
	
	SourceType() : name (""), field_name ("") {ptr = 0; is_array = false; is_fcn_ptr = false; kind = 0; }

    SourceType(std::string _name, std::string _field_name) : name(_name), field_name(_field_name)
                {ptr = 0; is_array = false; is_fcn_ptr = false; kind = 0;  }

	SourceType(SourceType* S) {
		name = S->name;
		field_name = S->field_name;
		fields = S->fields;
		ptr = S->ptr;
		is_array = S->is_array;
		is_fcn_ptr = S->is_fcn_ptr;	
        kind = S->kind;
	}

	SourceType& operator= (const SourceType& S)  {
		name = S.name;
		fields = S.fields;
		ptr = S.ptr;
		is_array = S.is_array;
		field_name = S.field_name;
		is_fcn_ptr = S.is_fcn_ptr;
        kind = S.kind;
		return *this;	
	}
};

struct Symbol {
	std::string sym_name;
	SourceType* type;
};


struct SourceVarRecovery {

	std::string src_symbol;
	std::string file;
	unsigned int line;
	unsigned int col;

	SourceVarRecovery() {
		line = 0;
		col = 0;
	}

	SourceVarRecovery(std::string _src_symbol, std::string _file, unsigned _line, unsigned _col) : src_symbol(_src_symbol), file(_file) {
		line = _line;
		col = _col;
	}

	SourceVarRecovery& operator=(const SourceVarRecovery& S) {
		src_symbol = S.src_symbol;
		file = S.file;
		line = S.line;
		col = S.col;
		return *this;
	}

};

struct SourceExpr {
    SourceType* type;
    SourceVarRecovery SVR;

    SourceExpr() {
        type = nullptr;
        SVR = SourceVarRecovery("", "", 0, 0);
    }

    SourceExpr(SourceType* _type, SourceVarRecovery* _svr) : type(_type) {
        SVR = *_svr;

    }

    SourceExpr(SourceType* _type) : type(_type) {}

    SourceExpr(const SourceExpr& S) {
        type = S.type;
        SVR = S.SVR;
    }

    SourceExpr& operator=(const SourceExpr& S) {
        type = S.type;
        SVR = S.SVR;
        return *this;
    }
    
};

struct BBLocations {

	std::vector< SourceVarRecovery* > Locals;
	std::vector< SourceVarRecovery* > GEPs;
	std::vector< SourceVarRecovery* > LDs;
	std::vector< SourceVarRecovery* > STs;
	
};

//const char* TypeIDEnum2String[] = {
//    "Void",  
//    "Half", 
//    "Float",       
//    "Double",      
//    "X86_FP80",    
//    "FP128",       
//    "PPC_FP128",   
//    "Label",       
//    "Metadata",   
//    "X86_MMX",    
//    "Token",       
//    // Derived types... see DerivedTypes.h file.
//    "Integer",   
//    "Function",  
//    "Struct",    
//    "Array",     
//    "Pointer",   
//    "Vector"     
//  };



void debug_type(SourceType* t);
void debug_location(DILocation* L);
unsigned getUnionFieldFromOffset(SourceType ty, std::string s);
const std::vector<std::string> explode(const std::string& s, const char& c);
SourceType* getFieldFromOffset(SourceType ty, long offset);
std::string getMathsFromOpcode(const char* opcode);
//std::string RetrieveOperandsDef(llvm::Instruction *, std::map<Value*, Symbol*>);
std::string RetrieveOperandsDef(llvm::User *, std::map<Value*, Symbol*>);
std::string runOnOperand(llvm::Value *, std::map<Value*, Symbol*>, SourceType* out_type);
void buildTypeSystem(DIType* base_type, SourceType* source_type, std::vector<DIType*> comp_visited);
void buildTypeSystemHeuristic(Type* T, SourceType* source_type);
std::string ParseGepOperator(GEPOperator* gepo);
DIGlobalVariable* RetrieveDebugInfoFromGlobalVar(GlobalVariable* GV, bool* isExternalLinkage);
SourceExpr* RecoverExpression(Value* ValToSearch, std::map<Value*, SourceExpr*>* Mapper, std::map<Value*, Symbol*>* Syms);
void BuildExpressionForInstruction(llvm::User * instruction, std::map<Value*, SourceExpr*>* Mapper, std::map<Value*, Symbol*> *Syms, SourceExpr* expr, DILocation* Loc);
void debug_mapper(std::map<Value*, SourceExpr*>* Mapper);
void debug_src_expr(SourceExpr* S);
void PropagateType(SourceType* Dst, SourceType* BaseType, bool array, bool ptr, bool is_union, int field);
void UpdateLocation(SourceExpr* E, DILocation* l);
