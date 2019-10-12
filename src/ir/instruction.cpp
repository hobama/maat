#include "instruction.hpp"
#include "exception.hpp"
#include <iostream>

/* ===================================== */
bool iroperation_is_assignment(IROperation& op){
    return  op == IROperation::ADD || 
            op == IROperation::SUB || 
            op == IROperation::MUL ||
            op == IROperation::MULH ||
            op == IROperation::SMULL ||
            op == IROperation::SMULH || 
            op == IROperation::DIV || 
            op == IROperation::SDIV ||
            op == IROperation::SHL ||
            op == IROperation::SHR ||  
            op == IROperation::NEG || 
            op == IROperation::AND || 
            op == IROperation::OR || 
            op == IROperation::XOR ||
            op == IROperation::NOT ||
            op == IROperation::MOD ||
            op == IROperation::SMOD ||
            op == IROperation::MOV ||
            op == IROperation::CONCAT;
}
bool iroperation_is_memory(IROperation& op){
    return  op == IROperation::STM ||
            op == IROperation::LDM ;
}
ostream& operator<<(ostream& os, IROperation& op){
    switch(op){
        case IROperation::ADD: os << "ADD"; break;
        case IROperation::SUB: os << "SUB"; break;
        case IROperation::MUL: os << "MUL"; break;
        case IROperation::MULH: os << "MUL(h)"; break;
        case IROperation::SMULL: os << "SMUL(l)"; break;
        case IROperation::SMULH: os << "SMUL(h)"; break;
        case IROperation::DIV: os << "DIV"; break;
        case IROperation::SDIV: os << "SDIV"; break;
        case IROperation::SHL: os << "SHL"; break;
        case IROperation::SHR: os << "SHR"; break;
        case IROperation::NEG: os << "NEG"; break;
        case IROperation::AND: os << "AND"; break;
        case IROperation::OR: os << "OR"; break;
        case IROperation::XOR: os << "XOR"; break;
        case IROperation::NOT: os << "NOT"; break;
        case IROperation::MOV: os << "MOV"; break;
        case IROperation::MOD: os << "MOD"; break;
        case IROperation::SMOD: os << "MOD"; break;
        case IROperation::STM: os << "STM"; break;
        case IROperation::LDM: os << "LDM"; break;
        case IROperation::BCC: os << "BCC"; break;
        case IROperation::JCC: os << "JCC"; break;
        case IROperation::BISZ: os << "BISZ"; break;
        case IROperation::CONCAT: os << "CONCAT"; break;
        case IROperation::INT: os << "INT"; break;
        case IROperation::SYSCALL: os << "SYSCALL"; break;
        default: os << "???"; break;
    }
    return os;
}

/* ===================================== */
IROperand::IROperand(): type(IROperandType::NONE), _val(0), high(0), low(0), size(0){}
IROperand::IROperand(IROperandType t, cst_t cst, exprsize_t h, exprsize_t l): 
    type(t), _val(cst_sign_extend(sizeof(cst_t)*8, cst)), high(h), low(l), size(h-l+1){}

bool IROperand::is_cst(){ return type == IROperandType::CST; }
bool IROperand::is_var(){ return type == IROperandType::VAR; }
bool IROperand::is_tmp(){ return type == IROperandType::TMP; }
bool IROperand::is_none(){ return type == IROperandType::NONE; }

cst_t IROperand::cst(){ return _val; }
IRVar IROperand::var(){ return (IRVar)_val;}
IRVar IROperand::tmp(){return (IRVar)_val;}

ostream& operator<<(ostream& os, IROperand& op){
    switch(op.type){
        case IROperandType::CST: os << op.cst(); break;
        case IROperandType::TMP: os << "TMP_" << op.tmp(); break;
        case IROperandType::VAR: os << "VAR_" << op.var(); break;
        case IROperandType::NONE: os << "_" ; break;
    }
    os << "[" << op.high << ":" << op.low << "]";
    return os;
}

/* Helpers to create operands */
IROperand ir_cst(cst_t val, exprsize_t high, exprsize_t low){
    return IROperand(IROperandType::CST, val, high, low);
}
IROperand ir_var(cst_t num, exprsize_t high, exprsize_t low){
    return IROperand(IROperandType::VAR, num, high, low);
}
IROperand ir_tmp(cst_t num, exprsize_t high, exprsize_t low){
    return IROperand(IROperandType::TMP, num, high, low);
}
IROperand ir_none(){
    return IROperand();
}

/* ===================================== */
IRInstruction::IRInstruction(IROperation _op, IROperand _dst, IROperand _src1, addr_t a){
    op = _op;
    dst = _dst;
    src1 = _src1;
    src2 = IROperand();
    addr = a;
}
IRInstruction::IRInstruction(IROperation _op, IROperand _dst, IROperand _src1, IROperand _src2, addr_t a){
    op = _op;
    dst = _dst;
    src1 = _src1;
    src2 = _src2;
    addr = a;
}

bool IRInstruction::reads_var(IRVar var){
    if( iroperation_is_assignment(op)){
        return  (src1.is_var() && src1.var() == var) || 
                (src2.is_var() && src2.var() == var);
    }else if( iroperation_is_memory(op)){
        return  (dst.is_var() && dst.var() == var) ||
                (src1.is_var() && src1.var() == var) || 
                (src2.is_var() && src2.var() == var);
    }else if( op == IROperation::BCC || op == IROperation::JCC){
        return (dst.is_var() && dst.var() == var) ||
                (src1.is_var() && src1.var() == var) || 
                (src2.is_var() && src2.var() == var);
    }else if( op == IROperation::BISZ ){
        return src1.is_var() && src1.var() == var;
    }else{
        throw runtime_exception("IRInstruction::reads_var() got unknown IROperation");
    }
}

bool IRInstruction::writes_var(IRVar var){
    if( iroperation_is_assignment(op)){
        return  (dst.is_var() && dst.var() == var);
    }else if( iroperation_is_memory(op)){
        return  false;
    }else if( op == IROperation::BCC || op == IROperation::JCC){
        return false;
    }else if( op == IROperation::BISZ){
        return (dst.is_var() && dst.var() == var);
    }else{
        throw runtime_exception("IRInstruction::writes_var() got unknown IROperation");
    }
}

bool IRInstruction::uses_var(IRVar var){
    return reads_var(var) || writes_var(var);
}

bool IRInstruction::reads_tmp(IRVar tmp){
    if( iroperation_is_assignment(op)){
        return  (src1.is_tmp() && src1.tmp() == tmp) || 
                (src2.is_tmp() && src2.tmp() == tmp);
    }else if( iroperation_is_memory(op)){
        return  (dst.is_tmp() && dst.tmp() == tmp) ||
                (src1.is_tmp() && src1.tmp() == tmp) || 
                (src2.is_tmp() && src2.tmp() == tmp);
    }else if( op == IROperation::BCC || op == IROperation::JCC){
        return (dst.is_tmp() && dst.tmp() == tmp) ||
                (src1.is_tmp() && src1.tmp() == tmp) || 
                (src2.is_tmp() && src2.tmp() == tmp);
    }else if( op == IROperation::BISZ ){
        return src1.is_tmp() && src1.tmp() == tmp;
    }else{
        throw runtime_exception("IRInstruction::reads_tmp() got unknown IROperation");
    }
}

bool IRInstruction::writes_tmp(IRVar tmp){
    if( iroperation_is_assignment(op)){
        return  (dst.is_tmp() && dst.tmp() == tmp);
    }else if( iroperation_is_memory(op)){
        return  false;
    }else if( op == IROperation::BCC || op == IROperation::JCC){
        return false;
    }else if( op == IROperation::BISZ){
        return (dst.is_tmp() && dst.tmp() == tmp);
    }else{
        throw runtime_exception("IRInstruction::writes_tmp() got unknown IROperation");
    }
}

vector<IROperand> IRInstruction::used_vars_read(){
    vector<IROperand> res;
    if( iroperation_is_assignment(op)){
        if(src1.is_var())
            res.push_back(src1);
        if( src2.is_var())
            res.push_back(src2);
    }else if( iroperation_is_memory(op) || op == IROperation::BCC || op == IROperation::JCC ){
        if(src1.is_var())
            res.push_back(src1);
        if( src2.is_var())
            res.push_back(src2);
        if( dst.is_var() )
            res.push_back(dst);
    }else if( op == IROperation::BISZ ){
        if(src1.is_var())
            res.push_back(src1);
    }else if( op == IROperation::INT || op == IROperation::SYSCALL){
        // Ignore
    }else{
        throw runtime_exception("IRInstruction::used_vars_read() got unknown IROperation");
    }
    return res;
}

vector<IROperand> IRInstruction::used_vars_write(){
    vector<IROperand> res;
    if( iroperation_is_assignment(op) || op == IROperation::LDM || op == IROperation::BISZ){
        if(dst.is_var())
            res.push_back(dst);
    }else if( op == IROperation::STM || op == IROperation::BCC || op == IROperation::JCC || op == IROperation::INT || op == IROperation::SYSCALL ){
        // Ignore those even if they rewrite pc
    }else{
        throw runtime_exception("IRInstruction::used_vars_write() got unknown IROperation");
    }
    return res;
}

vector<IROperand> IRInstruction::used_tmps_read(){
    vector<IROperand> res;
    if( iroperation_is_assignment(op)){
        if(src1.is_tmp())
            res.push_back(src1);
        if( src2.is_tmp())
            res.push_back(src2);
    }else if( iroperation_is_memory(op) || op == IROperation::BCC || op == IROperation::JCC || op == IROperation::INT ){
        if(src1.is_tmp())
            res.push_back(src1);
        if( src2.is_tmp())
            res.push_back(src2);
        if( dst.is_tmp() )
            res.push_back(dst);
    }else if( op == IROperation::BISZ ){
        if(src1.is_tmp())
            res.push_back(src1);
    }else if( op == IROperation::SYSCALL ){
        if( src1.is_tmp() )
            res.push_back(src1);
    }else{
        throw runtime_exception("IRInstruction::used_tmps_read() got unknown IROperation");
    }
    return res;
}

vector<IROperand> IRInstruction::used_tmps_write(){
    vector<IROperand> res;
    if( iroperation_is_assignment(op)){
        if(dst.is_tmp())
            res.push_back(dst);
    }else if( iroperation_is_memory(op) || op == IROperation::BCC || op == IROperation::JCC 
              || op == IROperation::INT || op == IROperation::SYSCALL){
        // Ignore 
    }else if( op == IROperation::BISZ ){
        if(dst.is_tmp())
            res.push_back(dst);
    }else{
        throw runtime_exception("IRInstruction::used_tmps_write() got unknown IROperation");
    }
    return res;
}

ostream& operator<<(ostream& os, IRInstruction& ins){
    os << "(0x" << std::hex << ins.addr << ")";
    os << "\t" << ins.op << "\t";
    if( ins.op == IROperation::BCC ){
        os << ins.dst << ",\tbblk_" << ins.src1.cst();
        if( !ins.src2.is_none()){
            os << ",\t\tbblk_" << ins.src2.cst();
        }
    }else{
        os << ins.dst << ",\t" << ins.src1;
        if( !ins.src2.is_none()){
            os << ",\t" << ins.src2;
        }
    }
    os << std::endl;
    return os;
}

/* Helpers to create instructions */
IRInstruction ir_add(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::ADD, dst, src1, src2, addr);
}
IRInstruction ir_sub(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::SUB, dst, src1, src2, addr);
}
IRInstruction ir_mul(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::MUL, dst, src1, src2, addr);
}
IRInstruction ir_mulh(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::MULH, dst, src1, src2, addr);
}
IRInstruction ir_smull(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::SMULL, dst, src1, src2, addr);
}
IRInstruction ir_smulh(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::SMULH, dst, src1, src2, addr);
}
IRInstruction ir_div(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::DIV, dst, src1, src2, addr);
}
IRInstruction ir_sdiv(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::SDIV, dst, src1, src2, addr);
}
IRInstruction ir_and(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::AND, dst, src1, src2, addr);
}
IRInstruction ir_or(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::OR, dst, src1, src2, addr);
}
IRInstruction ir_xor(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::XOR, dst, src1, src2, addr);
}
IRInstruction ir_shl(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::SHL, dst, src1, src2, addr);
}
IRInstruction ir_shr(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::SHR, dst, src1, src2, addr);
}
IRInstruction ir_mod(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::MOD, dst, src1, src2, addr);
}
IRInstruction ir_smod(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::SMOD, dst, src1, src2, addr);
}
IRInstruction ir_neg(IROperand dst, IROperand src1, addr_t addr){
    return IRInstruction(IROperation::NEG, dst, src1, addr);
}
IRInstruction ir_not(IROperand dst, IROperand src1, addr_t addr){
    return IRInstruction(IROperation::NOT, dst, src1, addr);
}
IRInstruction ir_ldm(IROperand dst, IROperand src1, addr_t addr){
    return IRInstruction(IROperation::LDM, dst, src1, addr);
}
IRInstruction ir_stm(IROperand dst, IROperand src1, addr_t addr){
    return IRInstruction(IROperation::STM, dst, src1, addr);
}
IRInstruction ir_mov(IROperand dst, IROperand src1, addr_t addr){
    return IRInstruction(IROperation::MOV, dst, src1, addr);
}
IRInstruction ir_bcc(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::BCC, dst, src1, src2, addr);
}
IRInstruction ir_jcc(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::JCC, dst, src1, src2, addr);
}
IRInstruction ir_bisz(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::BISZ, dst, src1, src2, addr);
}
IRInstruction ir_concat(IROperand dst, IROperand src1, IROperand src2, addr_t addr){
    return IRInstruction(IROperation::CONCAT, dst, src1, src2, addr);
}
IRInstruction ir_int(IROperand num, IROperand ret, addr_t addr){
    return IRInstruction(IROperation::INT, num, ret, addr);
}
IRInstruction ir_syscall(IROperand type, IROperand ret, addr_t addr){
    return IRInstruction(IROperation::SYSCALL, type, ret, addr);
}

/* ====================================== */
IRContext::IRContext(VarContext* varctx):_var(nullptr), _nb_var(0), _varctx(varctx){}
IRContext::IRContext(IRVar nb_var, VarContext* varctx){
    _var = new Expr[nb_var]{nullptr};
    _nb_var = nb_var;
    _varctx = varctx;
}
IRContext::~IRContext(){
    delete [] _var; _var = nullptr;
}
int IRContext::nb_vars(){
    return _nb_var;
}
void IRContext::set(IRVar num, Expr e){
    if( num >= _nb_var ){
        throw ir_exception("IRContext::set(): Invalid register argument");
    }
    _var[num] = e;
}
Expr IRContext::get(IRVar num){
    if( num >= _nb_var ){
        throw ir_exception("IRContext::get(): Invalid register argument");
    }
    return _var[num];
}

cst_t IRContext::concretize(IRVar num, VarContext* varctx){
    if( num >= _nb_var ){
        throw ir_exception("IRContext::concretize(): Invalid register argument");
    }
    
    if( varctx == nullptr ){
        if( _varctx == nullptr ){
            throw runtime_exception("IRContext::concretize(): called with null VarContext");
        }
        return _var[num]->concretize(_varctx);
    }else{
        return _var[num]->concretize(varctx);
    }
}

cst_t IRContext::as_signed(IRVar num, VarContext* varctx){
    return concretize(num, varctx);
}

cst_t IRContext::as_unsigned(IRVar num, VarContext* varctx){
    if( num >= _nb_var ){
        throw ir_exception("IRContext::as_unsigned(): Invalid register argument");
    }
    
    if( varctx == nullptr ){
        if( _varctx == nullptr ){
            throw runtime_exception("IRContext::as_unsigned(): called with null VarContext");
        }
        return cst_sign_trunc(_var[num]->size, _var[num]->concretize(_varctx));
    }else{
        return cst_sign_trunc(_var[num]->size, _var[num]->concretize(varctx));
    }
}

// Make purely symbolic (replace the expression)
string IRContext::make_symbolic(IRVar num, string name){
    if( num >= _nb_var ){
        throw ir_exception("IRContext::make_symbolic(): Invalid register argument");
    } else if( _varctx == nullptr ){
        throw runtime_exception("IRContext::make_symbolic(): called with null VarContext");
    }
    // We don't want the supplied name to correspond to an existing variable so use
    // new_name_from :)
    string new_name = _varctx->new_name_from(name);
    _var[num] = exprvar(_var[num]->size, new_name);
    return new_name;
}

// Make the expression tainted :)
void IRContext::make_tainted(IRVar num){
    if( num >= _nb_var ){
        throw ir_exception("IRContext::make_tainted(): Invalid register argument");
    }
    _var[num]->make_tainted();
}

// Represent the register by a simple var (but keep its concrete value)
string IRContext::make_var(IRVar num, string name){
    if( num >= _nb_var ){
        throw ir_exception("IRContext::make_var(): Invalid register argument");
    } else if( _varctx == nullptr ){
        throw runtime_exception("IRContext::make_var(): called with null VarContext");
    }
    // We don't want the supplied name to correspond to an existing variable so use
    // new_name_from :)
    string new_name = _varctx->new_name_from(name);
    // First we save the concrete value of the register in the VarContext
    _varctx->set(new_name, _var[num]->concretize(_varctx));
    _var[num] = exprvar(_var[num]->size, new_name);
    return new_name;
}


void IRContext::copy_from(IRContext& other){
    for( int i = 0; i < _nb_var; i++){
        _var[i] = other._var[i];
    }
}
IRContext* IRContext::copy(){
    IRContext* res = new IRContext(_nb_var);
    res->copy_from(*this);
    return res;
}

ostream& operator<<(ostream& os, IRContext& ctx){
    for( int i = 0; i < ctx.nb_vars(); i++){
        os << "Var_" << i << " : " << ctx.get(i) << std::endl;
    }
    return os;
}
/* ====================================== */
