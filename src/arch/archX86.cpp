#include "expression.hpp"
#include "arch.hpp"
#include "disassembler.hpp"
#include "exception.hpp"
#include "instruction.hpp"
#include <cstring>
#include <sstream>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <iostream>

using std::stringstream;

/* =================================== */
ArchX86::ArchX86(): Arch(32, 4, X86_NB_REGS, CPUMode::X86, new DisassemblerX86(CPUMode::X86)){
}

string ArchX86::reg_name(reg_t num){
    switch(num){
        case X86_EAX: return "eax";
        case X86_EBX: return "ebx";
        case X86_ECX: return "ecx";
        case X86_EDX: return "edx";
        case X86_EDI: return "edi";
        case X86_ESI: return "esi";
        case X86_EBP: return "ebp";
        case X86_ESP: return "esp";
        case X86_EIP: return "eip";
        case X86_CS: return "cs";
        case X86_DS: return "ds";
        case X86_ES: return "es";
        case X86_FS: return "fs";
        case X86_GS: return "gs";
        case X86_SS: return "ss";
        case X86_CF: return "cf";
        case X86_PF: return "pf";
        case X86_AF: return "af";
        case X86_ZF: return "zf";
        case X86_SF: return "sf";
        case X86_TF: return "tf";
        case X86_IF: return "if";
        case X86_DF: return "df";
        case X86_OF: return "of";
        case X86_IOPL: return "iopl";
        case X86_VM: return "vm";
        case X86_NT: return "nt";
        case X86_RF: return "rf";
        case X86_AC: return "ac";
        case X86_VIP: return "vip";
        case X86_VIF: return "vif";
        case X86_ID: return "id";
        default:
            throw runtime_exception("ArchX86::reg_name() got unknown reg num");
    }
    
}
reg_t ArchX86::reg_num(string name){
    if( !name.compare("eax")) return X86_EAX;
    else if( !name.compare("ebx")) return X86_EBX;
    else if( !name.compare("ecx")) return X86_ECX;
    else if( !name.compare("edx")) return X86_EDX;
    else if( !name.compare("edi")) return X86_EDI;
    else if( !name.compare("esi")) return X86_ESI;
    else if( !name.compare("ebp")) return X86_EBP;
    else if( !name.compare("esp")) return X86_ESP;
    else if( !name.compare("eip")) return X86_EIP;
    else if( !name.compare("cs")) return X86_CS;
    else if( !name.compare("ds")) return X86_DS;
    else if( !name.compare("es")) return X86_ES;
    else if( !name.compare("fs")) return X86_FS;
    else if( !name.compare("gs")) return X86_GS;
    else if( !name.compare("ss")) return X86_SS;
    else if( !name.compare("cf")) return X86_CF;
    else if( !name.compare("pf")) return X86_PF;
    else if( !name.compare("af")) return X86_AF;
    else if( !name.compare("zf")) return X86_ZF;
    else if( !name.compare("sf")) return X86_SF;
    else if( !name.compare("tf")) return X86_TF;
    else if( !name.compare("if")) return X86_IF;
    else if( !name.compare("df")) return X86_DF;
    else if( !name.compare("of")) return X86_OF;
    else if( !name.compare("iopl")) return X86_IOPL;
    else if( !name.compare("vm")) return X86_VM;
    else if( !name.compare("nt")) return X86_NT;
    else if( !name.compare("rf")) return X86_RF;
    else if( !name.compare("ac")) return X86_AC;
    else if( !name.compare("vip")) return X86_VIP;
    else if( !name.compare("vif")) return X86_VIF;
    else if( !name.compare("id")) return X86_ID;
    else throw runtime_exception(ExceptionFormatter () << "ArchX86::reg_num() got unknown reg name: " << name >> ExceptionFormatter::to_str);
}

reg_t ArchX86::sp(){
    return X86_ESP;
}

reg_t ArchX86::pc(){
    return X86_EIP;
}

/* ===================================================== */
DisassemblerX86::DisassemblerX86(CPUMode mode){
    _mode = mode;
    if( mode == CPUMode::X86 ){
        cs_open(CS_ARCH_X86, CS_MODE_32, &_handle);
    }else if( mode == CPUMode::X64 ){
        cs_open(CS_ARCH_X86, CS_MODE_64, &_handle);
    }else{
        throw runtime_exception("DisassemblerX86: got unsupported mode");
    }
    // Ask for detailed instructions
    cs_option(_handle, CS_OPT_DETAIL, CS_OPT_ON);
    // allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
    // (will be freed in destructor)
    _insn = cs_malloc(_handle);
}

inline IROperand x86_32_reg_translate(x86_reg reg){
    switch(reg){
        case X86_REG_AL: return IROperand(IROperandType::VAR, X86_EAX, 7, 0);
        case X86_REG_AH: return IROperand(IROperandType::VAR, X86_EAX, 15, 8);
        case X86_REG_AX: return IROperand(IROperandType::VAR, X86_EAX, 15, 0);
        case X86_REG_EAX: return IROperand(IROperandType::VAR, X86_EAX, 31, 0);
        case X86_REG_BL: return IROperand(IROperandType::VAR, X86_EBX, 7, 0);
        case X86_REG_BH: return IROperand(IROperandType::VAR, X86_EBX, 15, 8);
        case X86_REG_BX: return IROperand(IROperandType::VAR, X86_EBX, 15, 0);
        case X86_REG_EBX: return IROperand(IROperandType::VAR, X86_EBX , 31, 0);
        case X86_REG_CL: return IROperand(IROperandType::VAR, X86_ECX, 7, 0);
        case X86_REG_CH: return IROperand(IROperandType::VAR, X86_ECX, 15, 8);
        case X86_REG_CX: return IROperand(IROperandType::VAR, X86_ECX, 15, 0);
        case X86_REG_ECX: return IROperand(IROperandType::VAR, X86_ECX, 31, 0);
        case X86_REG_DL: return IROperand(IROperandType::VAR, X86_EDX, 7, 0);
        case X86_REG_DH: return IROperand(IROperandType::VAR, X86_EDX, 15, 8);
        case X86_REG_DX: return IROperand(IROperandType::VAR, X86_EDX, 15, 0);
        case X86_REG_EDX: return IROperand(IROperandType::VAR, X86_EDX, 31, 0);
        case X86_REG_DI: return IROperand(IROperandType::VAR, X86_EDI, 15, 0);
        case X86_REG_EDI: return IROperand(IROperandType::VAR, X86_EDI, 31, 0);
        case X86_REG_SI: return IROperand(IROperandType::VAR, X86_ESI, 15, 0);
        case X86_REG_ESI: return IROperand(IROperandType::VAR, X86_ESI, 31, 0);
        case X86_REG_BP: return IROperand(IROperandType::VAR, X86_EBP, 15, 0);
        case X86_REG_EBP: return IROperand(IROperandType::VAR, X86_EBP, 31, 0);
        case X86_REG_SP: return IROperand(IROperandType::VAR, X86_ESP, 15, 0);
        case X86_REG_ESP: return IROperand(IROperandType::VAR, X86_ESP, 31, 0);
        case X86_REG_IP: return IROperand(IROperandType::VAR, X86_EIP, 15, 0);
        case X86_REG_EIP: return IROperand(IROperandType::VAR, X86_EIP, 31, 0);
        case X86_REG_CS: return IROperand(IROperandType::VAR, X86_CS, 31, 0);
        case X86_REG_DS: return IROperand(IROperandType::VAR, X86_DS, 31, 0);
        case X86_REG_ES: return IROperand(IROperandType::VAR, X86_ES, 31, 0);
        case X86_REG_GS: return IROperand(IROperandType::VAR, X86_GS, 31, 0);
        case X86_REG_FS: return IROperand(IROperandType::VAR, X86_FS, 31, 0);
        case X86_REG_SS: return IROperand(IROperandType::VAR, X86_SS, 31, 0);
        default: throw runtime_exception( ExceptionFormatter() <<
        "Disassembler X86: unknown capstone register " << reg 
        >> ExceptionFormatter::to_str);
    }
}
// DEBUG TODO !!! 
inline IROperand x86_64_reg_translate(x86_reg reg){
    switch(reg){
        case X86_REG_AL: return IROperand(IROperandType::VAR, X64_RAX, 7, 0);
        case X86_REG_AH: return IROperand(IROperandType::VAR, X64_RAX, 15, 8);
        case X86_REG_AX: return IROperand(IROperandType::VAR, X64_RAX, 15, 0);
        case X86_REG_EAX: return IROperand(IROperandType::VAR, X64_RAX, 31, 0);
        case X86_REG_RAX: return IROperand(IROperandType::VAR, X64_RAX, 63, 0);
        case X86_REG_BL: return IROperand(IROperandType::VAR, X64_RBX, 7, 0);
        case X86_REG_BH: return IROperand(IROperandType::VAR, X64_RBX, 15, 8);
        case X86_REG_BX: return IROperand(IROperandType::VAR, X64_RBX, 15, 0);
        case X86_REG_EBX: return IROperand(IROperandType::VAR, X64_RBX , 31, 0);
        case X86_REG_RBX: return IROperand(IROperandType::VAR, X64_RBX , 63, 0);
        case X86_REG_CL: return IROperand(IROperandType::VAR, X64_RCX, 7, 0);
        case X86_REG_CH: return IROperand(IROperandType::VAR, X64_RCX, 15, 8);
        case X86_REG_CX: return IROperand(IROperandType::VAR, X64_RCX, 15, 0);
        case X86_REG_ECX: return IROperand(IROperandType::VAR, X64_RCX, 31, 0);
        case X86_REG_RCX: return IROperand(IROperandType::VAR, X64_RCX, 63, 0);
        case X86_REG_DL: return IROperand(IROperandType::VAR, X64_RDX, 7, 0);
        case X86_REG_DH: return IROperand(IROperandType::VAR, X64_RDX, 15, 8);
        case X86_REG_DX: return IROperand(IROperandType::VAR, X64_RDX, 15, 0);
        case X86_REG_EDX: return IROperand(IROperandType::VAR, X64_RDX, 31, 0);
        case X86_REG_RDX: return IROperand(IROperandType::VAR, X64_RDX, 63, 0);
        case X86_REG_DI: return IROperand(IROperandType::VAR, X64_RDI, 15, 0);
        case X86_REG_EDI: return IROperand(IROperandType::VAR, X64_RDI, 31, 0);
        case X86_REG_RDI: return IROperand(IROperandType::VAR, X64_RDI, 63, 0);
        case X86_REG_SI: return IROperand(IROperandType::VAR, X64_RSI, 15, 0);
        case X86_REG_ESI: return IROperand(IROperandType::VAR, X64_RSI, 31, 0);
        case X86_REG_RSI: return IROperand(IROperandType::VAR, X64_RSI, 63, 0);
        case X86_REG_BP: return IROperand(IROperandType::VAR, X64_RBP, 15, 0);
        case X86_REG_EBP: return IROperand(IROperandType::VAR, X64_RBP, 31, 0);
        case X86_REG_RBP: return IROperand(IROperandType::VAR, X64_RBP, 63, 0);
        case X86_REG_SP: return IROperand(IROperandType::VAR, X64_RSP, 15, 0);
        case X86_REG_ESP: return IROperand(IROperandType::VAR, X64_RSP, 31, 0);
        case X86_REG_RSP: return IROperand(IROperandType::VAR, X64_RSP, 63, 0);
        case X86_REG_IP: return IROperand(IROperandType::VAR, X64_RIP, 15, 0);
        case X86_REG_EIP: return IROperand(IROperandType::VAR, X64_RIP, 31, 0);
        case X86_REG_RIP: return IROperand(IROperandType::VAR, X64_RIP, 63, 0);
        default: throw runtime_exception( ExceptionFormatter() <<
        "Disassembler X86: unknown capstone register " << reg 
        >> ExceptionFormatter::to_str);
    }
}

inline IROperand x86_reg_translate(CPUMode mode, x86_reg reg){
    if( mode == CPUMode::X86 ){
        return x86_32_reg_translate(reg);
    }else{
        return x86_64_reg_translate(reg);
    }
}

inline IROperand x86_arg_extract(IROperand& arg, exprsize_t high, exprsize_t low){
    switch(arg.type){
        case IROperandType::CST: return IROperand(IROperandType::CST, arg.cst(), high, low);
        case IROperandType::VAR: return IROperand(IROperandType::VAR, arg.var(), high, low);
        case IROperandType::TMP: return IROperand(IROperandType::TMP, arg.tmp(), high, low);
        case IROperandType::NONE: return IROperand();
        default: throw runtime_exception("x86_arg_extract(): got unknown IROperandType!");
    }
}

/* Translate capstone argument to maat IR argument 
 * Arguments:
 *      mode - the current CPU mode for registers translation 
 *      addr - the address of the instruction being translated
 *      arg - the capstone operand 
 *      block/bblkid - block and basicblockid where to add instructions if needed 
 *      tmp_var_count - the counter of the tmp variables used in the current IRBlock
 *      load_mem - if TRUE then load memory operands (dereference), else only return the operand (pointer) 
 */
inline IROperand x86_arg_translate(CPUMode mode, addr_t addr, cs_x86_op* arg, IRBlock* block, IRBasicBlockId bblkid, int& tmp_vars_count, bool load_mem=false){
    IROperand base, index, res, disp, segment;
    exprsize_t size = arg->size*8, addr_size = 0, reg_size = (mode==CPUMode::X86)? 32:64;
    switch(arg->type){
        /* Register */
        case X86_OP_REG:
            return x86_reg_translate(mode, arg->reg);
        /* Immediate */
        case X86_OP_IMM:
            return IROperand(IROperandType::CST, arg->imm, size-1, 0);
        /* Memory */
        case X86_OP_MEM:
            // Arg = segment + base + (index*scale) + disp
            // Get index*scale
            if( arg->mem.index != X86_OP_INVALID ){
                index = x86_reg_translate(mode, (x86_reg)arg->mem.index);
                if( arg->mem.scale != 1 ){
                    block->add_instr(bblkid, IRInstruction(IROperation::MUL, ir_tmp(tmp_vars_count++, index.size-1, 0), 
                        ir_cst(arg->mem.scale, index.size-1, 0), index, addr));
                    index = ir_tmp(tmp_vars_count-1, index.size-1, 0);
                }
                addr_size = index.size;
            }
            // Get base
            if( arg->mem.base != X86_OP_INVALID ){
                base = x86_reg_translate(mode, (x86_reg)arg->mem.base);
                // If too small adjust
                if( base.size < index.size ){
                    block->add_instr(bblkid, ir_mov(ir_tmp(tmp_vars_count++, index.size-1, 0), ir_cst(0, index.size-1, 0), addr));
                    block->add_instr(bblkid, ir_mov(ir_tmp(tmp_vars_count-1, base.size-1, 0), base, addr));
                    base = ir_tmp(tmp_vars_count-1, base.size-1, 0);
                }
                addr_size = base.size;
            }else{
                //base = ir_cst(0, index.size-1, 0);
                base = ir_none();
                //throw runtime_exception("Disassembler X86: didn't expect X86_OP_INVALID base for mem operand in capstone");
            }
            
            // Get displacement
            if( addr_size == 0 )
                addr_size = reg_size;
            if( arg->mem.disp != 0 ){
                disp = IROperand(IROperandType::CST, arg->mem.disp, addr_size-1, 0);
            }else{
                disp = ir_none();
            }
            
            // Get segment selector (here we consider that the segment selector symbolic register holds the address
            // of the segment, not the index in the GDT
            if( arg->mem.segment != X86_OP_INVALID ){
                segment = x86_reg_translate(mode, (x86_reg)arg->mem.segment);
                // If too big, adjust
                if( segment.size > addr_size ){
                    block->add_instr(bblkid, ir_mov(ir_tmp(tmp_vars_count++, addr_size-1, 0), x86_arg_extract(segment, addr_size-1, 0), addr));
                    segment = ir_tmp(tmp_vars_count-1, addr_size-1, 0);
                }
            }else{
                segment = ir_none();
            }
            
            // === Build the operand now ===  
            // Add base and index if any 
            if( !index.is_none() ){
                if( !base.is_none() ){
                    block->add_instr(bblkid, ir_add(ir_tmp(tmp_vars_count++, index.size-1, 0), base, index, addr));
                    res = IROperand(IROperandType::TMP, tmp_vars_count-1, index.size-1, 0);
                }else{
                    res = index;
                }
            }else if (!base.is_none()){
                res = base;
            }else{
                res = ir_none();
            }
            // Add displacement if any 
            if( !disp.is_none() ){
                if( !res.is_none()){
                    block->add_instr(bblkid, ir_add( ir_tmp(tmp_vars_count++, res.size-1, 0), disp, res, addr));
                    res = IROperand(IROperandType::TMP, tmp_vars_count-1, res.size-1, 0);
                }else{
                    res = disp;
                }
            }
            // Add segment if any
            if( !segment.is_none() ){
                if( !res.is_none() ){
                    block->add_instr(bblkid, ir_add( ir_tmp(tmp_vars_count++, res.size-1, 0), segment, res, addr));
                    res = IROperand(IROperandType::TMP, tmp_vars_count-1, res.size-1, 0);
                }else{
                    res = segment;
                }
            }
            // Do load memory if requested
            if( load_mem ){
                block->add_instr(bblkid, IRInstruction(IROperation::LDM,
                    IROperand(IROperandType::TMP, tmp_vars_count++, size-1 , 0), res, addr));
                res = IROperand(IROperandType::TMP, tmp_vars_count-1, size-1, 0);
            }
            return res;
        default:
            throw runtime_exception("Disassembler X86: got unknown capstone operand type");
    }
    throw runtime_exception("Disassembler X86: couldn't translate operand");
}

/* ========================================= */
inline IROperand x86_get_pc(CPUMode mode ){
    if( mode == CPUMode::X86 )
        return ir_var(X86_EIP, 31, 0 );
    else if( mode == CPUMode::X64 )
        return ir_var(X64_RIP, 63, 0 );
    else
        throw runtime_exception("x86_get_pc(): got unknown CPUMode!");
}

inline void x86_set_zf(CPUMode mode, IROperand& arg, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid){
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz(ir_var(X86_ZF, 31, 0), arg, ir_cst(1, 31, 0), addr));
    else
        block->add_instr(bblkid, ir_bisz(ir_var(X64_ZF, 63, 0), arg , ir_cst(1, 63, 0), addr));
}

inline void x86_add_set_cf(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IROperand   msb0 = x86_arg_extract(op0, op0.high, op0.high),
                msb1 = x86_arg_extract(op1, op1.high, op1.high),
                msb2 = x86_arg_extract(res, res.high, res.high),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp2 = ir_tmp(tmp_var_count++, 0, 0 );
    // cf -> higher bits of both operands are already 1 
    
    block->add_instr(bblkid, ir_and(tmp0, msb0, msb1, addr));
    //       or they are 1 and 0 and result has MSB 0
    block->add_instr(bblkid, ir_xor(tmp1, msb0, msb1, addr));
    block->add_instr(bblkid, ir_not(tmp2, msb2, addr));
    block->add_instr(bblkid, ir_and(tmp2, tmp1, tmp2, addr));
    block->add_instr(bblkid, ir_or(tmp2, tmp0, tmp2, addr)); 
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz( ir_var(X86_CF, 31, 0),tmp2, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz( ir_var(X64_CF, 63, 0),tmp2, ir_cst(0, 63, 0), addr));
}

inline void x86_add_set_of(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IROperand   msb0 = x86_arg_extract(op0, op0.high, op0.high),
                msb1 = x86_arg_extract(op1, op1.high, op1.high),
                msb2 = x86_arg_extract(res, res.high, res.high),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 );     
    
    // of -> msb of both operands have the same MSB but result
    //       has different
    block->add_instr(bblkid, ir_xor(tmp0, msb0, msb1, addr));
    block->add_instr(bblkid, ir_not(tmp0, tmp0, addr));
    block->add_instr(bblkid, ir_xor(tmp1, msb0, msb2, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp0, tmp1, addr));
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz(ir_var(X86_OF, 31, 0), tmp1, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz(ir_var(X64_OF, 63, 0), tmp1, ir_cst(0, 63, 0), addr));
}

inline void x86_sub_set_cf(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IROperand   msb0 = x86_arg_extract(op0, op0.high, op0.high),
                msb1 = x86_arg_extract(op1, op1.high, op1.high),
                msb2 = x86_arg_extract(res, res.high, res.high),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 );
    // cf <- (~msb0&msb1) | (msb1&msb2) | (~msb0&msb2)
    block->add_instr(bblkid, ir_not(tmp0, msb0, addr));
    block->add_instr(bblkid, ir_and(tmp0, tmp0, msb1, addr));
    block->add_instr(bblkid, ir_and(tmp1, msb1, msb2, addr));
    block->add_instr(bblkid, ir_or(tmp1, tmp0, tmp1, addr));
    
    block->add_instr(bblkid, ir_not(tmp0, msb0, addr));
    block->add_instr(bblkid, ir_and(tmp0, tmp0, msb2, addr));
    block->add_instr(bblkid, ir_or(tmp1, tmp1, tmp0, addr)); 
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz( ir_var(X86_CF, 31, 0),tmp1, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz( ir_var(X64_CF, 63, 0),tmp1, ir_cst(0, 63, 0), addr));
}

inline void x86_sub_set_af(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    /* Like cf but for bit 3 */
    IROperand   msb0 = x86_arg_extract(op0, 3, 3),
                msb1 = x86_arg_extract(op1, 3, 3),
                msb2 = x86_arg_extract(res, 3, 3),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 );
    // cf <- (~msb0&msb1) | (msb1&msb2) | (~msb0&msb2)
    block->add_instr(bblkid, ir_not(tmp0, msb0, addr));
    block->add_instr(bblkid, ir_and(tmp0, tmp0, msb1, addr));
    block->add_instr(bblkid, ir_and(tmp1, msb1, msb2, addr));
    block->add_instr(bblkid, ir_or(tmp1, tmp0, tmp1, addr));
    
    block->add_instr(bblkid, ir_not(tmp0, msb0, addr));
    block->add_instr(bblkid, ir_and(tmp0, tmp0, msb2, addr));
    block->add_instr(bblkid, ir_or(tmp1, tmp1, tmp0, addr)); 
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz( ir_var(X86_AF, 31, 0),tmp1, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz( ir_var(X64_AF, 63, 0),tmp1, ir_cst(0, 63, 0), addr));
}

inline void x86_sub_set_of(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IROperand   msb0 = x86_arg_extract(op0, op0.high, op0.high),
                msb1 = x86_arg_extract(op1, op1.high, op1.high),
                msb2 = x86_arg_extract(res, res.high, res.high),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 );
    
    // of -> msb of both operands have different MSB and result
    //       has the same as second operand
    block->add_instr(bblkid, ir_xor(tmp0, msb0, msb1, addr));
    block->add_instr(bblkid, ir_xor(tmp1, msb1, msb2, addr));
    block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp0, tmp1, addr));
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz(ir_var(X86_OF, 31, 0), tmp1, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz(ir_var(X64_OF, 63, 0), tmp1, ir_cst(0, 63, 0), addr));
}

inline void x86_set_sf(CPUMode, IROperand arg, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid){
    block->add_instr(bblkid, ir_bisz(ir_var(X86_SF, 31, 0), x86_arg_extract(arg, arg.high, arg.high), ir_cst(0, 31, 0), addr));
}

inline void x86_add_set_af(CPUMode mode, IROperand op0, IROperand op1, IROperand res, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    // Basically like cf but for bits 3
    IROperand   msb0 = x86_arg_extract(op0, 3, 3),
                msb1 = x86_arg_extract(op1, 3, 3),
                msb2 = x86_arg_extract(res, 3, 3),
                tmp0 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp1 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp2 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp3 = ir_tmp(tmp_var_count++, 0, 0 ),
                tmp4 = ir_tmp(tmp_var_count++, 0, 0 );
    // cf -> higher bits of both operands are already 1 
    
    block->add_instr(bblkid, ir_and(tmp0, msb0, msb1, addr));
    //       or they are 1 and 0 and result has MSB 0
    block->add_instr(bblkid, ir_xor(tmp1, msb0, msb1, addr));
    block->add_instr(bblkid, ir_not(tmp2, msb2, addr));
    block->add_instr(bblkid, ir_and(tmp3, tmp1, tmp2, addr));
    block->add_instr(bblkid, ir_or(tmp4, tmp0, tmp3, addr)); 
    if( mode == CPUMode::X86 )
        block->add_instr(bblkid, ir_bisz( ir_var(X86_AF, 31, 0),tmp4, ir_cst(0, 31, 0), addr));
    else if( mode == CPUMode::X64 )
        block->add_instr(bblkid, ir_bisz( ir_var(X64_AF, 63, 0),tmp4, ir_cst(0, 63, 0), addr));
}

inline void x86_set_pf(CPUMode mode, IROperand arg, addr_t addr, IRBlock* block, IRBasicBlockId bblkid, int& tmp_var_count){
    // pf number of bits that are equal to zero in the least significant byte 
    // of the result of an operation -> xor all and set flag if zero 
    IROperand tmp =  ir_tmp(tmp_var_count++, 0, 0 );
    block->add_instr(bblkid, ir_mov(tmp, x86_arg_extract(arg, 0, 0), addr));
    for( int i = 1; i < 8; i++){
        block->add_instr(bblkid, ir_xor(tmp, tmp, x86_arg_extract(arg, i, i), addr));
    }
    if( mode == CPUMode::X86 ){
        block->add_instr(bblkid, ir_bisz(ir_var(X86_PF, 31, 0), tmp, ir_cst(1, 31, 0), addr));
    }else if( mode == CPUMode::X64 ){
        block->add_instr(bblkid, ir_bisz(ir_var(X64_PF, 63, 0), tmp, ir_cst(1, 31, 0), addr));
    }
}

/* =====================
 * Instruction prefixes 
 * =====================

*/

IRBasicBlockId _x86_init_prefix(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid){
    IRBasicBlockId start;
    if( instr->detail->x86.prefix[0] != X86_PREFIX_REP &&
        instr->detail->x86.prefix[0] != X86_PREFIX_REPNE ){
        return -1;
    }
    start = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 31, 0), ir_cst(start, 31, 0), ir_none(), addr));
    bblkid = block->new_bblock();
    return start;
}

bool inline _accepts_repe_prefix(cs_insn* instr){
    return  instr->id == X86_INS_CMPSB ||
            instr->id == X86_INS_CMPSW ||
            instr->id == X86_INS_CMPSD ||
            instr->id == X86_INS_CMPSQ ||
            instr->id == X86_INS_SCASB ||
            instr->id == X86_INS_SCASW ||
            instr->id == X86_INS_SCASD ||
            instr->id == X86_INS_SCASQ;
}   

bool inline _accepts_rep_prefix(cs_insn* instr){
    return  instr->id == X86_INS_INSB ||
            instr->id == X86_INS_INSW ||
            instr->id == X86_INS_INSD ||
            instr->id == X86_INS_MOVSB ||
            instr->id == X86_INS_MOVSW ||
            instr->id == X86_INS_MOVSD ||
            instr->id == X86_INS_MOVSQ ||
            instr->id == X86_INS_OUTSB ||
            instr->id == X86_INS_OUTSW ||
            instr->id == X86_INS_OUTSD ||
            instr->id == X86_INS_LODSB ||
            instr->id == X86_INS_LODSW ||
            instr->id == X86_INS_LODSD ||
            instr->id == X86_INS_LODSQ ||
            instr->id == X86_INS_STOSB ||
            instr->id == X86_INS_STOSW ||
            instr->id == X86_INS_STOSD ||
            instr->id == X86_INS_STOSQ;
}

/* Wraps an instruction block with a REP prefix
 * Parameters:
 *      start - the basic block where to test the terminating condition. The instruction semantics start at start+1
 *      last - the current last bblock of the instruction 
 * 
 */
 
inline void _x86_end_prefix(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId start, IRBasicBlockId& last, int& tmp_var_count){
    IROperand cx = (mode == CPUMode::X86)? ir_var(X86_ECX, 31, 0): ir_var(X64_RCX, 63, 0);
    IROperand zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0): ir_var(X64_ZF, 63, 0);  
    IROperand tmp;
    IRBasicBlockId end;
    
    if( instr->detail->x86.prefix[0] != X86_PREFIX_REP &&
        instr->detail->x86.prefix[0] != X86_PREFIX_REPNE ){
        return;
    }
    
    /* Add loop and cx decrement at the end of the instruction */
    block->add_instr(last, ir_sub(cx, cx, ir_cst(1, cx.size-1, 0), addr));
    block->add_instr(last, ir_bcc(ir_cst(1, 31, 0), ir_cst(start, 31, 0), ir_none(), addr));
    
    /* Add REP test in the beginning */
    end = block->new_bblock();
    if( instr->detail->x86.prefix[0] == X86_PREFIX_REP && _accepts_rep_prefix(instr) ){
        block->add_instr(start, ir_bcc(cx, ir_cst(start+1, 31, 0), ir_cst(end, 31, 0), addr));
    }else if( instr->detail->x86.prefix[0] == X86_PREFIX_REP && _accepts_repe_prefix(instr) ){
        tmp = ir_tmp(tmp_var_count++, 0, 0);
        block->add_instr(start, ir_bisz(tmp, cx, ir_cst(0, 0, 0), addr));
        block->add_instr(start, ir_and(tmp, tmp, x86_arg_extract(zf, 0, 0), addr));
        block->add_instr(start, ir_bcc(tmp, ir_cst(start+1, 31, 0), ir_cst(end, 31, 0), addr));
    }else if( instr->detail->x86.prefix[0] == X86_PREFIX_REPNE ){
        tmp = ir_tmp(tmp_var_count++, 0, 0);
        block->add_instr(start, ir_bisz(tmp, cx, ir_cst(1, 0, 0), addr));
        block->add_instr(start, ir_or(tmp, tmp, x86_arg_extract(zf, 0, 0), addr));
        block->add_instr(start, ir_bcc(tmp, ir_cst(end, 31, 0), ir_cst(start+1, 31, 0), addr));
    }
    
    last = end; // Update last basic block
}


/* ========================================= */
/* Instructions translation */


inline void x86_aaa_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand   af, eax, cf, tmp0, tmp1, pc;   
    if( mode == CPUMode::X86 ){
        eax = ir_var(X86_EAX, 31, 0);
        af = ir_var(X86_AF, 31, 0);
        cf = ir_var(X86_CF, 31, 0);
    }else if( mode == CPUMode::X64 ){
        throw runtime_exception("X86 AAA instruction is valid only in 32-bit mode");
    }
    tmp0 = ir_tmp(tmp_var_count++, af.size-1, 0), // Get the size from any register 
    tmp1 = ir_tmp(tmp_var_count++, af.size-1, 0);
    /* If 4 LSB are > 9 or if AF is set then adjust the unpacked BCD values */
    // (4 LSB) > 9
    block->add_instr(bblkid, ir_bisz(tmp0, x86_arg_extract(eax, 3, 3), ir_cst(0, eax.size,0), addr));
    block->add_instr(bblkid, ir_bisz(tmp1, x86_arg_extract(eax, 2, 1), ir_cst(0, eax.size,0), addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    // AF
    block->add_instr(bblkid, ir_or(tmp1, af, tmp1, addr));
    // Branch depending on condition 
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(bblkid+1, 31,0), ir_cst(bblkid+2, 31, 0), addr));
    // 1°) Branch 1 - Do the adjust 
    bblkid = block->new_bblock();
    // AL <- AL + 6
    block->add_instr(bblkid, ir_add(x86_arg_extract(eax, 7, 0), x86_arg_extract(eax, 7, 0), ir_cst(6, 7, 0), addr));
    // AH ++ 
    block->add_instr(bblkid, ir_add(x86_arg_extract(eax, 15, 8), x86_arg_extract(eax, 15, 8), ir_cst(1, 7, 0), addr));
    // CF <- 1 , AF <- 1
    block->add_instr(bblkid, ir_mov(af, ir_cst(1, af.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(1, af.size-1, 0), addr));
    // Jump to common end
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 0, 0), ir_cst(bblkid+2, 31, 0), ir_none(), addr));
    
    // 2°) Branch 2 - Just reset flags
    bblkid = block->new_bblock();
    block->add_instr(bblkid, ir_mov(af, ir_cst(0, af.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, af.size-1, 0), addr));
    // Jump to common end
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 0, 0), ir_cst(bblkid+1, 31, 0), ir_none(), addr));
    
    // 3°) Common end - Keep only 4 LSB of AL
    bblkid = block->new_bblock();
    block->add_instr(bblkid, ir_and(x86_arg_extract(eax, 7, 0), x86_arg_extract(eax, 7, 0), ir_cst(0xf, 7, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_aad_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand  tmp0, imm, al, pc;   
    if( mode != CPUMode::X86 ){
        throw runtime_exception("X86 AAD instruction is valid only in 32-bit mode");
    }
    tmp0 = ir_tmp(tmp_var_count++, 7, 0), // Get the size from any register 
    imm = ir_cst(0xa, 7, 0); // 2 byte of the encoded instruction always 0xA for AAD
    al = ir_var(X86_EAX, 7,0);
    // AL <- (AL + (AH ∗ imm8)) & 0xFF;
    // AH <- 0
    block->add_instr(bblkid, ir_mul(tmp0, ir_var(X86_EAX, 15, 8), imm, addr));
    block->add_instr(bblkid, ir_add(al, al, tmp0, addr));
    block->add_instr(bblkid, ir_mov(ir_var(X86_EAX, 15, 8), ir_cst(0, 7, 0), addr));
    
    // Set flags : SF, ZF, PF
    x86_set_sf(mode, al, addr, block, bblkid);
    x86_set_zf(mode, al, addr, block, bblkid); 
    x86_set_pf(mode, al, addr, block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    return;
}

inline void x86_aam_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand  tmp0, imm, al, pc;   
    if( mode != CPUMode::X86 ){
        throw runtime_exception("X86 AAM instruction is valid only in 32-bit mode");
    }
    tmp0 = ir_tmp(tmp_var_count++, 7, 0), // Get the size from any register 
    imm = ir_cst(0xa, 7, 0); // 2 byte of the encoded instruction always 0xA for AAM
    al = ir_var(X86_EAX, 7,0);
    // AH <- AL / 10
    // AL <- AL % 10
    block->add_instr(bblkid, ir_mov(tmp0, al, addr));
    block->add_instr(bblkid, ir_div(ir_var(X86_EAX, 15, 8), tmp0, imm, addr));
    block->add_instr(bblkid, ir_mod(al, tmp0, imm, addr));
    
    // Set flags : SF, ZF, PF
    x86_set_sf(mode, al, addr, block, bblkid);
    x86_set_zf(mode, al, addr, block, bblkid); 
    x86_set_pf(mode, al, addr, block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    return;
}


inline void x86_aas_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand   af, eax, cf, tmp0, tmp1, pc;   
    if( mode == CPUMode::X86 ){
        eax = ir_var(X86_EAX, 31, 0);
        af = ir_var(X86_AF, 31, 0);
        cf = ir_var(X86_CF, 31, 0);
    }else if( mode == CPUMode::X64 ){
        throw runtime_exception("X86 AAS instruction is valid only in 32-bit mode");
    }
    tmp0 = ir_tmp(tmp_var_count++, af.size-1, 0), // Get the size from any register 
    tmp1 = ir_tmp(tmp_var_count++, af.size-1, 0);
    /* If 4 LSB are > 9 or if AF is set then adjust the unpacked BCD values */
    // (4 LSB) > 9
    block->add_instr(bblkid, ir_bisz(tmp0, x86_arg_extract(eax, 3, 3), ir_cst(0, eax.size,0), addr));
    block->add_instr(bblkid, ir_bisz(tmp1, x86_arg_extract(eax, 2, 1), ir_cst(0, eax.size,0), addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    // AF
    block->add_instr(bblkid, ir_or(tmp1, af, tmp1, addr));
    // Branch depending on condition 
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(bblkid+1, 31,0), ir_cst(bblkid+2, 31, 0), addr));
    // 1°) Branch 1 - Do the adjust 
    bblkid = block->new_bblock();
    // AL <- AL - 6
    block->add_instr(bblkid, ir_sub(x86_arg_extract(eax, 7, 0), x86_arg_extract(eax, 7, 0), ir_cst(6, 7, 0), addr));
    // AH    
    block->add_instr(bblkid, ir_sub(x86_arg_extract(eax, 15, 8), x86_arg_extract(eax, 15, 8), ir_cst(1, 7, 0), addr));
    // CF <- 1 , AF <- 1
    block->add_instr(bblkid, ir_mov(af, ir_cst(1, af.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(1, af.size-1, 0), addr));
    // Jump to common end
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 0, 0), ir_cst(bblkid+2, 31, 0), ir_none(), addr));
    
    // 2°) Branch 2 - Just reset flags
    bblkid = block->new_bblock();
    block->add_instr(bblkid, ir_mov(af, ir_cst(0, af.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, af.size-1, 0), addr));
    // Jump to common end
    block->add_instr(bblkid, ir_bcc(ir_cst(1, 0, 0), ir_cst(bblkid+1, 31, 0), ir_none(), addr));
    
    // 3°) Common end - Keep only 4 LSB of AL
    bblkid = block->new_bblock();
    block->add_instr(bblkid, ir_and(x86_arg_extract(eax, 7, 0), x86_arg_extract(eax, 7, 0), ir_cst(0xf, 7, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}


inline void x86_adc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, prev_cf, pc;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    if( mode == CPUMode::X86 )
        prev_cf = ir_var(X86_CF, res.size-1, 0);
    else if( mode == CPUMode::X64 )
        prev_cf = ir_var(X64_CF, res.size-1, 0);
    /* Do the add */
    block->add_instr(bblkid, ir_add(res, op0, op1, addr));
    block->add_instr(bblkid, ir_add(res, res, prev_cf, addr));
    
    /* Update flags */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_add_set_cf(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_af(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_of(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    
    /* Finally assign the result to the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    /* Else direct register assign */
    }else{
        block->add_instr(bblkid, ir_mov(dest, res, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_adcx_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, prev_cf, pc;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    if( mode == CPUMode::X86 )
        prev_cf = ir_var(X86_CF, res.size-1, 0);
    else if( mode == CPUMode::X64 )
        prev_cf = ir_var(X64_CF, res.size-1, 0);
    /* Do the add */
    block->add_instr(bblkid, ir_add(res, op0, op1, addr));
    block->add_instr(bblkid, ir_add(res, res, prev_cf, addr));
    
    /* Update flags */
    x86_add_set_cf(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    
    /* Finally assign the result to the destination */ 
    /* ADCX destination is always a general purpose reg */
    block->add_instr(bblkid, ir_mov(dest, res, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_add_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, pc;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the add */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_add(res, op0, op1, addr));
    
    /* Update flags */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_add_set_cf(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_af(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_of(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    
    /* Finally assign the result to the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    /* Else direct register assign */
    }else{
        block->add_instr(bblkid, ir_mov(dest, res, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_and_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the and */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_and(res, op0, op1, addr));
    
    /* Update flags: SF, ZF, PF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    /* OF and CF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.high, cf.low), addr));
    
    /* Finally assign the result to the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    /* Else direct register assign */
    }else{
        block->add_instr(bblkid, ir_mov(dest, res, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_andn_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[2]), block, bblkid, tmp_var_count, true);
    /* Do the not then the and */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_not(res, op0, addr));
    block->add_instr(bblkid, ir_and(res, res, op1, addr));
    
    /* Update flags: SF, ZF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    /* OF and CF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.high, cf.low), addr));
    
    /* Finally assign the result to the destination */ 
    block->add_instr(bblkid, ir_mov(dest, res, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_blsi_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the not then the and */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_neg(res, op0, addr));
    block->add_instr(bblkid, ir_and(res, res, op0, addr));
    
    /* Update flags: SF, ZF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    /* CF set if op0 is source is not zero */
    block->add_instr(bblkid, ir_bisz(cf, op0, ir_cst(0, cf.size-1, 0), addr));
    /* OF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    
    /* Finally assign the result to the destination */ 
    block->add_instr(bblkid, ir_mov(dest, res, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_blsmsk_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, zf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* res <- (op0-1) XOR op0 */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(res, op0, ir_cst(1, op0.size-1, 0), addr));
    block->add_instr(bblkid, ir_xor(res, res, op0, addr));
    
    /* Update flags: SF */
    x86_set_sf(mode, res, addr, block, bblkid);
    /* CF set if op0 is source is zero */
    block->add_instr(bblkid, ir_bisz(cf, op0, ir_cst(1, cf.size-1, 0), addr));
    /* OF and ZF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(zf, ir_cst(0, of.high, of.low), addr));
    
    /* Finally assign the result to the destination */ 
    block->add_instr(bblkid, ir_mov(dest, res, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_blsr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, zf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* res <- (op0-1) AND op0 */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(res, op0, ir_cst(1, op0.size-1, 0), addr));
    block->add_instr(bblkid, ir_and(res, res, op0, addr));
    
    /* Update flags: SF, ZF */
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_zf(mode, res, addr, block, bblkid);
    /* CF set if op0 is source is zero */
    block->add_instr(bblkid, ir_bisz(cf, op0, ir_cst(1, cf.size-1, 0), addr));
    /* OF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    
    /* Finally assign the result to the destination */ 
    block->add_instr(bblkid, ir_mov(dest, res, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_bsf_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, op0, counter, tmp0, zf, pc;
    IRBasicBlockId loop_test, loop_body, loop_exit, op_is_zero, op_not_zero, end;
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0); 
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    op_not_zero = block->new_bblock();
    loop_test = block->new_bblock();
    loop_body = block->new_bblock();
    loop_exit = block->new_bblock();
    op_is_zero = block->new_bblock();
    end = block->new_bblock();
    
    // Update PC first because then we don't know what branch we take
    pc = x86_get_pc(mode);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    // op0 == 0 ??
    block->add_instr(bblkid, ir_bcc(op0, ir_cst(op_not_zero, 31, 0), ir_cst(op_is_zero, 31, 0), addr));
    // 1°) Branch1 : op_not_zero
    counter = ir_tmp(tmp_var_count++, dest.size-1, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(op_not_zero, ir_mov(counter, ir_cst(0, counter.size-1, 0), addr)); // counter <- 0
    block->add_instr(op_not_zero, ir_bcc(ir_cst(1, 31, 0) , ir_cst(loop_test, 31, 0), ir_none(), addr));
    // loop test: while ( op0[i] == 0 )
    block->add_instr(loop_test, ir_shr(tmp0, op0, counter, addr));
    block->add_instr(loop_test, ir_bcc(x86_arg_extract(tmp0,0,0) , ir_cst(loop_exit, 31, 0), ir_cst(loop_body, 31, 0), addr));
    // loop body: counter = counter + 1
    block->add_instr(loop_body, ir_add(counter, counter, ir_cst(1, counter.size-1, 0), addr));
    block->add_instr(loop_body, ir_bcc(ir_cst(1, 31, 0) , ir_cst(loop_test, 31, 0), ir_none(), addr));
    // loop exit: dest <- counter  and ZF <- 0
    block->add_instr(loop_exit, ir_mov(dest, counter, addr));
    x86_set_zf(mode, op0, addr, block, loop_exit );
    block->add_instr(loop_exit, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // 2°) Branch2: op_is_zero
    // ZF <- 1
    block->add_instr(op_is_zero, ir_mov(zf, ir_cst(1, zf.size-1, 0), addr));
    block->add_instr(op_is_zero, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    bblkid = end;
    return;
}

inline void x86_bsr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, op0, counter, tmp0, zf, pc;
    IRBasicBlockId loop_test, loop_body, loop_exit, op_is_zero, op_not_zero, end;
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0); 
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    op_not_zero = block->new_bblock();
    loop_test = block->new_bblock();
    loop_body = block->new_bblock();
    loop_exit = block->new_bblock();
    op_is_zero = block->new_bblock();
    end = block->new_bblock();
    
    // Update PC first because then we don't know what branch we take
    pc = x86_get_pc(mode);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    // op0 == 0 ??
    block->add_instr(bblkid, ir_bcc(op0, ir_cst(op_not_zero, 31, 0), ir_cst(op_is_zero, 31, 0), addr));
    // 1°) Branch1 : op_not_zero
    counter = ir_tmp(tmp_var_count++, dest.size-1, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(op_not_zero, ir_mov(counter, ir_cst((dest.size-1), counter.size-1, 0), addr)); // counter <- sizeof(op0)-1
    block->add_instr(op_not_zero, ir_bcc(ir_cst(1, 31, 0) , ir_cst(loop_test, 31, 0), ir_none(), addr));
    // loop test: while ( op0[i] == 0 )
    block->add_instr(loop_test, ir_shr(tmp0, op0, counter, addr));
    block->add_instr(loop_test, ir_bcc(x86_arg_extract(tmp0,0,0) , ir_cst(loop_exit, 31, 0), ir_cst(loop_body, 31, 0), addr));
    // loop body: counter = counter - 1
    block->add_instr(loop_body, ir_sub(counter, counter, ir_cst(1, counter.size-1, 0), addr));
    block->add_instr(loop_body, ir_bcc(ir_cst(1, 31, 0) , ir_cst(loop_test, 31, 0), ir_none(), addr));
    // loop exit: dest <- counter  and ZF <- 0
    block->add_instr(loop_exit, ir_mov(dest, counter, addr));
    x86_set_zf(mode, op0, addr, block, loop_exit );
    block->add_instr(loop_exit, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // 2°) Branch2: op0 == 0
    // ZF <- 1
    block->add_instr(op_is_zero, ir_mov(zf, ir_cst(1, zf.size-1, 0), addr));
    block->add_instr(op_is_zero, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    bblkid = end;
    return;
}

inline void x86_bswap_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, pc;
    /* Get operand */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( dest.size == 64 ){
        tmp0 = ir_tmp(tmp_var_count++, 7, 0);
        tmp1 = ir_tmp(tmp_var_count++, 7, 0);
        tmp2 = ir_tmp(tmp_var_count++, 7, 0);
        tmp3 = ir_tmp(tmp_var_count++, 7, 0);
        tmp4 = ir_tmp(tmp_var_count++, 7, 0);
        tmp5 = ir_tmp(tmp_var_count++, 7, 0);
        tmp6 = ir_tmp(tmp_var_count++, 7, 0);
        tmp7 = ir_tmp(tmp_var_count++, 7, 0);
        block->add_instr(bblkid, ir_mov(tmp0, x86_arg_extract(dest, 7, 0), addr));
        block->add_instr(bblkid, ir_mov(tmp1, x86_arg_extract(dest, 15, 8), addr));
        block->add_instr(bblkid, ir_mov(tmp2, x86_arg_extract(dest, 23, 16), addr));
        block->add_instr(bblkid, ir_mov(tmp3, x86_arg_extract(dest, 31, 24), addr));
        block->add_instr(bblkid, ir_mov(tmp4, x86_arg_extract(dest, 39,32), addr));
        block->add_instr(bblkid, ir_mov(tmp5, x86_arg_extract(dest, 47, 40), addr));
        block->add_instr(bblkid, ir_mov(tmp6, x86_arg_extract(dest, 55, 48), addr));
        block->add_instr(bblkid, ir_mov(tmp7, x86_arg_extract(dest, 63, 56), addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 63, 56), tmp0, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 55, 48), tmp1, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 47, 40), tmp2, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 39, 32), tmp3, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 31, 24), tmp4, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 23, 16), tmp5, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 15, 8), tmp6, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 7, 0), tmp7, addr));
        
    }else if( dest.size == 32 ){
        tmp0 = ir_tmp(tmp_var_count++, 7, 0);
        tmp1 = ir_tmp(tmp_var_count++, 7, 0);
        tmp2 = ir_tmp(tmp_var_count++, 7, 0);
        tmp3 = ir_tmp(tmp_var_count++, 7, 0);
        block->add_instr(bblkid, ir_mov(tmp0, x86_arg_extract(dest, 7, 0), addr));
        block->add_instr(bblkid, ir_mov(tmp1, x86_arg_extract(dest, 15, 8), addr));
        block->add_instr(bblkid, ir_mov(tmp2, x86_arg_extract(dest, 23, 16), addr));
        block->add_instr(bblkid, ir_mov(tmp3, x86_arg_extract(dest, 31, 24), addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 31, 24), tmp0, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 23, 16), tmp1, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 15, 8), tmp2, addr));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(dest, 7, 0), tmp3, addr));
        
    }else{
        throw runtime_exception("X86 BSWAP translation: needs operand of size 32 or 64 only");
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
}


inline void x86_bt_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand base, off, cf, pc, tmp0;
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    base = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    off = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, base.size-1, 0);
    
    /* cf <- bit(base, off % {16/32/64})   */
    block->add_instr(bblkid, ir_mod(tmp0, off, ir_cst(base.size, off.size-1, 0), addr));
    block->add_instr(bblkid, ir_shr(tmp0, base, tmp0, addr));
    block->add_instr(bblkid, ir_bisz(cf, x86_arg_extract(tmp0,0,0), ir_cst(0, cf.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_btc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, base, off, cf, pc, tmp0, tmp1;
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    base = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    off = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, base.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, base.size-1, 0);
    
    /* cf <- bit(base, off % {16/32/64})   */
    block->add_instr(bblkid, ir_mod(tmp0, off, ir_cst(base.size, off.size-1, 0), addr));
    block->add_instr(bblkid, ir_shr(tmp1, base, tmp0, addr));
    block->add_instr(bblkid, ir_bisz(cf, x86_arg_extract(tmp1,0,0), ir_cst(0, cf.size-1, 0), addr));
    /* invert bit(base, off % ... )*/
    block->add_instr(bblkid, ir_shl(tmp1, ir_cst(1, tmp0.size-1, 0), tmp0, addr));
    block->add_instr(bblkid, ir_xor(tmp1, base, tmp1, addr));
    
    /* Set the bit in the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp1, addr));
    /* Else direct register assign */
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp1, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_btr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, base, off, cf, pc, tmp0, tmp1;
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    base = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    off = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, base.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, base.size-1, 0);
    
    /* cf <- bit(base, off % {16/32/64})   */
    block->add_instr(bblkid, ir_mod(tmp0, off, ir_cst(base.size, off.size-1, 0), addr));
    block->add_instr(bblkid, ir_shr(tmp1, base, tmp0, addr));
    block->add_instr(bblkid, ir_bisz(cf, x86_arg_extract(tmp1,0,0), ir_cst(0, cf.size-1, 0), addr));
    /* bit(base, off % ... ) <- 0 */
    block->add_instr(bblkid, ir_shl(tmp1, ir_cst(1, tmp0.size-1, 0), tmp0, addr));
    block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
    block->add_instr(bblkid, ir_and(tmp1, base, tmp1, addr));
    
    /* Set the bit in the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp1, addr));
    /* Else direct register assign */
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp1, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_bts_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, base, off, cf, pc, tmp0, tmp1;
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    base = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    off = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, base.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, base.size-1, 0);
    
    /* cf <- bit(base, off % {16/32/64})   */
    block->add_instr(bblkid, ir_mod(tmp0, off, ir_cst(base.size, off.size-1, 0), addr));
    block->add_instr(bblkid, ir_shr(tmp1, base, tmp0, addr));
    block->add_instr(bblkid, ir_bisz(cf, x86_arg_extract(tmp1,0,0), ir_cst(0, cf.size-1, 0), addr));
    /* bit(base, off % ... ) <- 1 */
    block->add_instr(bblkid, ir_shl(tmp1, ir_cst(1, tmp0.size-1, 0), tmp0, addr));
    block->add_instr(bblkid, ir_or(tmp1, base, tmp1, addr));
    
    /* Set the bit in the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp1, addr));
    /* Else direct register assign */
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp1, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_bzhi_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand dest, op0, op1, cf, of, pc, index, tmp0, tmp1, opsize;
    IRBasicBlockId  index_too_big = block->new_bblock(), 
                    index_ok = block->new_bblock(),
                    end = block->new_bblock(); 
    /* Get operands */
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[2]), block, bblkid, tmp_var_count, true);
    index = ir_tmp(tmp_var_count++, dest.size-1, 0);
    tmp0 = ir_tmp(tmp_var_count++, dest.size-1, 0);
    
    /* index <- op1[7:0]   
     * dest <- op0
     * dest[size(dest)-1:index] <- 0 
     * cf = 1 iff index > size(dest)-1 
     */
    // Get index
    block->add_instr(bblkid, ir_mov(index, op1, addr));
    block->add_instr(bblkid, ir_and(index, index, ir_cst(0xff, index.size-1, 0), addr));
    // Compare index and size operands
    opsize = ir_cst(dest.size, dest.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp0, opsize, ir_cst(1, opsize.size-1, 0), addr));
    block->add_instr(bblkid, ir_sub(tmp0, tmp0, index, addr));
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1), 
                                    ir_cst(index_too_big, 31, 0),
                                    ir_cst(index_ok, 31, 0),
                                    addr));
    // 1°) Index > size operands -1
    block->add_instr(index_too_big, ir_mov(cf, ir_cst(1, cf.size-1, 0), addr));
    block->add_instr(index_too_big, ir_mov(dest, op0, addr));
    block->add_instr(index_too_big, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    
    // 2°) Index < size operands
    tmp1 = ir_tmp(tmp_var_count++, dest.size-1, 0);
    block->add_instr(index_ok, ir_mov(cf, ir_cst(0, cf.size-1, 0), addr ));
    // Get mask size(dest)-1 .. index
    block->add_instr(index_ok, ir_shl(tmp0, ir_cst(1, index.size-1, 0), index, addr));
    block->add_instr(index_ok, ir_neg(tmp1, tmp0, addr));
    block->add_instr(index_ok, ir_or(tmp1, tmp1, tmp0, addr));
    block->add_instr(index_ok, ir_not(tmp1, tmp1, addr));
    // Mask res 
    block->add_instr(index_ok, ir_and(dest, op0, tmp1, addr));
    block->add_instr(index_ok, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    
    // 3° ) Common end: set flags and pc
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // OF cleared 
    block->add_instr(end, ir_mov(of, ir_cst(0, of.size-1, 0), addr ));
    // Set zf, cf
    x86_set_sf(mode, dest, addr, block, end);
    x86_set_zf(mode, dest, addr, block, end);
    bblkid = end;
    return;
}

inline void x86_call_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, sp, pc, tmp;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0); 
    pc = x86_get_pc(mode);
    
    /* Get and push next instruction address */
    tmp = ir_tmp(tmp_var_count++, pc.size-1, 0);
    block->add_instr(bblkid, ir_add(tmp, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    block->add_instr(bblkid, ir_sub(sp, sp, ir_cst(pc.size/8, pc.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(sp, tmp, addr));
    
    /* Jump to called address */
    block->add_instr(bblkid, ir_jcc(ir_cst(1, pc.size-1, 0), op0, ir_none(), addr));
    
    return;
}

inline void x86_cbw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg, pc;
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg = (mode==CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* ax <- sign_extend(al)   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg, 7, 7), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    block->add_instr(ext1, ir_mov(x86_arg_extract(reg, 15, 8), ir_cst(0xff, 7, 0), addr));
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    block->add_instr(ext0, ir_mov(x86_arg_extract(reg, 15, 8), ir_cst(0x0, 7, 0), addr));
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cdq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg_a, reg_d, pc;
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg_a = (mode==CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    reg_d = (mode==CPUMode::X86)? ir_var(X86_EDX, 31, 0) : ir_var(X64_RDX, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* edx <- replicate(eax[31])   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg_a, 31, 31), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    block->add_instr(ext1, ir_mov(x86_arg_extract(reg_d, 31, 0), ir_cst(0xffffffff, 31, 0), addr));
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    block->add_instr(ext0, ir_mov(x86_arg_extract(reg_d, 31, 0), ir_cst(0x0, 31, 0), addr));
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cdqe_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg, pc;
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg = (mode==CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* rax <- sign_extend(eax)   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg, 31, 31), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    block->add_instr(ext1, ir_mov(x86_arg_extract(reg, 63, 32), ir_cst(0xffffffff, 32, 0), addr));
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    block->add_instr(ext0, ir_mov(x86_arg_extract(reg, 63, 32), ir_cst(0x0, 32, 0), addr));
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_clc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc;
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // cf <- 0
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0x0, cf.size-1, 0), addr));
    return;
}

inline void x86_cld_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand df, pc;
    df = (mode==CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // df <- 0
    block->add_instr(bblkid, ir_mov(df, ir_cst(0x0, df.size-1, 0), addr));
    return;
}

inline void x86_cli_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand if_flag, pc;
    if_flag = (mode==CPUMode::X86)? ir_var(X86_IF, 31, 0) : ir_var(X64_IF, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // if_flag <- 0
    block->add_instr(bblkid, ir_mov(if_flag, ir_cst(0x0, if_flag.size-1, 0), addr));
    return;
}

inline void x86_cmc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc;
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // complement cf
    block->add_instr(bblkid, ir_xor(cf, cf, ir_cst(0x1, cf.size-1, 0), addr));
    return;
}

inline void x86_cmova_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, zf, pc, tmp0, tmp1, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 0 and ZF = 0 
    block->add_instr(bblkid, ir_not(tmp0, cf, addr));
    block->add_instr(bblkid, ir_not(tmp1, zf, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovae_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 0
    block->add_instr(bblkid, ir_bcc(cf, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 1
    block->add_instr(bblkid, ir_bcc(cf, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovbe_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, zf, pc, tmp0, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 1 or ZF = 1 
    block->add_instr(bblkid, ir_or(tmp0, cf, zf, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmove_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand zf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if zf = 1
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, zf, pc, tmp0, tmp1, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 0 and OF = SF 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr));
    block->add_instr(bblkid, ir_not(tmp0, tmp0, addr));
    block->add_instr(bblkid, ir_not(tmp1, zf, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovge_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, zf, pc, tmp0, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = SF 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr));
    block->add_instr(bblkid, ir_not(tmp0, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovl_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, zf, pc, tmp0, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF != SF 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovle_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, zf, pc, tmp0, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 1 or OF != SF 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr));
    block->add_instr(bblkid, ir_or(tmp0, x86_arg_extract(zf, 0, 0), tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovne_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand zf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 0
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovno_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand of, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 0
    block->add_instr(bblkid, ir_bcc(of, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}


inline void x86_cmovnp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    pf = (mode==CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if PF = 0
    block->add_instr(bblkid, ir_bcc(pf, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovns_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF = 0
    block->add_instr(bblkid, ir_bcc(sf, ir_cst(dont_mov,31, 0), ir_cst(do_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}


inline void x86_cmovo_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand of, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 1
    block->add_instr(bblkid, ir_bcc(of, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    pf = (mode==CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 1
    block->add_instr(bblkid, ir_bcc(pf, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmovs_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, pc, op0, op1;
    IRBasicBlockId  do_mov = block->new_bblock(),
                    dont_mov = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF = 1
    block->add_instr(bblkid, ir_bcc(sf, ir_cst(do_mov,31, 0), ir_cst(dont_mov, 31, 0), addr));
    // do mov
    block->add_instr(do_mov, ir_mov(op0, op1, addr));
    block->add_instr(do_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont mov - do nothing
    block->add_instr(dont_mov, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cmp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    // Check if op1 is a imm and needs sign extend
    if( op1.size < op0.size && op1.is_cst()){
        op1 = ir_cst(cst_sign_extend(op1.size, op1.cst()), op0.size-1, 0);
    }
    // tmp <- op0 - op1
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp, op0, op1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp, addr, block, bblkid );
    x86_set_sf( mode, tmp, addr, block, bblkid );
    x86_sub_set_of( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
   
    return;
}

inline void x86_cmpsb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp1, tmp2, si, di, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    /* Get operands */
    si = (mode == CPUMode::X86) ? ir_var(X86_ESI, 31, 0) : ir_var(X64_RSI, 63, 0);
    di = (mode == CPUMode::X86) ? ir_var(X86_EDI, 31, 0) : ir_var(X64_RDI, 63, 0);
    df = (mode == CPUMode::X86) ? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    
    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    
    /* Read bytes from memory and compare them */
    tmp0 = ir_tmp(tmp_var_count++, 7, 0);
    tmp1 = ir_tmp(tmp_var_count++, 7, 0);
    tmp2 = ir_tmp(tmp_var_count++, 7, 0);
    
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_ldm(tmp1, di, addr));
    block->add_instr(bblkid, ir_sub(tmp2, tmp0, tmp1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp2, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp2, addr, block, bblkid );
    x86_set_sf( mode, tmp2, addr, block, bblkid );
    x86_sub_set_of( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    
    // Increment or decrement ESI/EDI according to DF
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    
    block->add_instr(inc, ir_add(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    block->add_instr(dec, ir_sub(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_cmpsd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp1, tmp2, si, di, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    /* Get operands */
    si = (mode == CPUMode::X86) ? ir_var(X86_ESI, 31, 0) : ir_var(X64_RSI, 63, 0);
    di = (mode == CPUMode::X86) ? ir_var(X86_EDI, 31, 0) : ir_var(X64_RDI, 63, 0);
    df = (mode == CPUMode::X86) ? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    
    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    
    /* Read dwords from memory and compare them */
    tmp0 = ir_tmp(tmp_var_count++, 31, 0);
    tmp1 = ir_tmp(tmp_var_count++, 31, 0);
    tmp2 = ir_tmp(tmp_var_count++, 31, 0);
    
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_ldm(tmp1, di, addr));
    block->add_instr(bblkid, ir_sub(tmp2, tmp0, tmp1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp2, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp2, addr, block, bblkid );
    x86_set_sf( mode, tmp2, addr, block, bblkid );
    x86_sub_set_of( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    
    // Increment or decrement ESI/EDI according to DF
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    
    block->add_instr(inc, ir_add(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    block->add_instr(dec, ir_sub(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_cmpsq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp1, tmp2, si, di, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    /* Get operands */
    si = (mode == CPUMode::X86) ? ir_var(X86_ESI, 31, 0) : ir_var(X64_RSI, 63, 0);
    di = (mode == CPUMode::X86) ? ir_var(X86_EDI, 31, 0) : ir_var(X64_RDI, 63, 0);
    df = (mode == CPUMode::X86) ? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    
    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    
    /* Read words from memory and compare them */
    tmp0 = ir_tmp(tmp_var_count++, 63, 0);
    tmp1 = ir_tmp(tmp_var_count++, 63, 0);
    tmp2 = ir_tmp(tmp_var_count++, 63, 0);
    
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_ldm(tmp1, di, addr));
    block->add_instr(bblkid, ir_sub(tmp2, tmp0, tmp1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp2, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp2, addr, block, bblkid );
    x86_set_sf( mode, tmp2, addr, block, bblkid );
    x86_sub_set_of( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    
    // Increment or decrement ESI/EDI according to DF
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    
    block->add_instr(inc, ir_add(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    block->add_instr(dec, ir_sub(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_cmpsw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp1, tmp2, si, di, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    /* Get operands */
    si = (mode == CPUMode::X86) ? ir_var(X86_ESI, 31, 0) : ir_var(X64_RSI, 63, 0);
    di = (mode == CPUMode::X86) ? ir_var(X86_EDI, 31, 0) : ir_var(X64_RDI, 63, 0);
    df = (mode == CPUMode::X86) ? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    
    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    
    /* Read words from memory and compare them */
    tmp0 = ir_tmp(tmp_var_count++, 15, 0);
    tmp1 = ir_tmp(tmp_var_count++, 15, 0);
    tmp2 = ir_tmp(tmp_var_count++, 15, 0);
    
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_ldm(tmp1, di, addr));
    block->add_instr(bblkid, ir_sub(tmp2, tmp0, tmp1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp2, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp2, addr, block, bblkid );
    x86_set_sf( mode, tmp2, addr, block, bblkid );
    x86_sub_set_of( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, tmp0, tmp1, tmp2, addr, block, bblkid, tmp_var_count );
    
    // Increment or decrement ESI/EDI according to DF
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    
    block->add_instr(inc, ir_add(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    block->add_instr(dec, ir_sub(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_cmpxchg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, dest, op0, op1, ax, zf, tmp;
    IRBasicBlockId eq, neq, end;
    
    eq = block->new_bblock();
    neq = block->new_bblock();
    end = block->new_bblock();
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    ax = (mode == CPUMode::X86) ? ir_var(X86_EAX, op0.size-1, 0) : ir_var(X64_RAX, op0.size-1, 0);
    zf = (mode == CPUMode::X86) ? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
   /* Compare op0 and op1 */
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp, ax, op0, addr ));
    /* Set flags */
    x86_set_pf(mode, tmp, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, tmp, addr, block, bblkid );
    x86_set_zf(mode, tmp, addr, block, bblkid );
    x86_sub_set_af(mode, ax, op0, tmp, addr, block, bblkid, tmp_var_count);
    x86_sub_set_cf(mode, ax, op0, tmp, addr, block, bblkid, tmp_var_count);
    x86_sub_set_of(mode, ax, op0, tmp, addr, block, bblkid, tmp_var_count);
    
    /* Exchange values depending on zf */
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(eq, 31, 0), ir_cst(neq, 31, 0), addr));
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(eq, ir_stm(op0, op1, addr));
    }else{
        block->add_instr(eq, ir_mov(op0, op1, addr));
    }
    block->add_instr(eq, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    block->add_instr(neq, ir_mov(ax, op0, addr));
    block->add_instr(neq, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cpuid_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid, int& tmp_var_count){
    IRBasicBlockId  leaf_0 = block->new_bblock(),
                    end = block->new_bblock();
    /* Test eax to know what cpuid leaf is requested */
    block->add_instr(bblkid, ir_bcc(ir_var(X86_EAX, 31, 0), ir_cst(end, 31, 0), ir_cst(leaf_0, 31, 0), addr));
    
    /* Leaf 0
     * Return the CPU's manufacturer ID string in ebx, edx and ecx
     * Set EAX to the higher supported leaf */
    // Set registers to "GenuineIntel" 
    block->add_instr(leaf_0, ir_mov(ir_var(X86_EBX, 31, 0), ir_cst(0x756e6547, 31, 0), addr));
    block->add_instr(leaf_0, ir_mov(ir_var(X86_EDX, 31, 0), ir_cst(0x49656e69, 31, 0), addr));
    block->add_instr(leaf_0, ir_mov(ir_var(X86_ECX, 31, 0), ir_cst(0x6c65746e, 31, 0), addr));
    // Set eax to 0 because other leafs are not supported yet
    block->add_instr(leaf_0, ir_mov(ir_var(X86_EAX, 31, 0), ir_cst(0, 31, 0), addr));
    block->add_instr(leaf_0, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));

    bblkid = end;
    return;
}


inline void x86_cwd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg_a, reg_d, pc;
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg_a = (mode==CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    reg_d = (mode==CPUMode::X86)? ir_var(X86_EDX, 31, 0) : ir_var(X64_RDX, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* dx <- replicate(ax[15])   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg_a, 15, 15), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    block->add_instr(ext1, ir_mov(x86_arg_extract(reg_d, 15, 0), ir_cst(0xffff, 15, 0), addr));
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    block->add_instr(ext0, ir_mov(x86_arg_extract(reg_d, 15, 0), ir_cst(0x0, 15, 0), addr));
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_cwde_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand tmp0, reg, pc;
    IRBasicBlockId ext0 = block->new_bblock(), 
                 ext1 = block->new_bblock(),
                 end = block->new_bblock();
    reg = (mode==CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* eax <- sign_extend(ax)   */
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(reg, 15, 15), ir_cst(ext1, 31, 0), ir_cst(ext0, 31, 0), addr));
    // extend 1
    block->add_instr(ext1, ir_mov(x86_arg_extract(reg, 31, 16), ir_cst(0xffff, 15, 0), addr));
    block->add_instr(ext1, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // extend 0
    block->add_instr(ext0, ir_mov(x86_arg_extract(reg, 31, 16), ir_cst(0x0, 15, 0), addr));
    block->add_instr(ext0, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_dec_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, dest, op0, tmp;
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    
    /* Decrement op0 */
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0); 
    block->add_instr(bblkid, ir_sub(tmp, op0, ir_cst(1, op0.size-1, 0), addr ));
    
    /* Set flags (except CF) */
    x86_set_pf(mode, tmp, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, tmp, addr, block, bblkid );
    x86_set_zf(mode, tmp, addr, block, bblkid );
    x86_sub_set_af(mode, op0, ir_cst(1, op0.size-1, 0), tmp, addr, block, bblkid, tmp_var_count);
    x86_sub_set_of(mode, op0, ir_cst(1, op0.size-1, 0), tmp, addr, block, bblkid, tmp_var_count);
    
    /* Store result */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp, addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}


inline void x86_div_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, dividend, remainder, tmp, ax, dx;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    dx = (mode == CPUMode::X86)? ir_var(X86_EDX, 31, 0) : ir_var(X64_RDX, 63, 0);
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    if( op0.size == 8 ){
        dividend = x86_arg_extract(ax, 7, 0);
        remainder = x86_arg_extract(ax, 15, 8);
    }else{
        dividend = x86_arg_extract(ax, op0.size-1, 0);
        remainder = x86_arg_extract(dx, op0.size-1, 0);
    }
    
    /* Do the div */
    block->add_instr(bblkid, ir_mov(tmp, x86_arg_extract(ax, op0.size-1, 0), addr));
    block->add_instr(bblkid, ir_div(dividend, tmp , op0, addr ));
    block->add_instr(bblkid, ir_mod(remainder, tmp , op0, addr ));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_idiv_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, ax, dx, tmp, dividend, remainder;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    dx = (mode == CPUMode::X86)? ir_var(X86_EDX, 31, 0) : ir_var(X64_RDX, 63, 0);
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    if( op0.size == 8 ){
        dividend = x86_arg_extract(ax, 7, 0);
        remainder = x86_arg_extract(ax, 15, 8);
    }else{
        dividend = x86_arg_extract(ax, op0.size-1, 0);
        remainder = x86_arg_extract(dx, op0.size-1, 0);
    }
    
    /* Quotient in *ax, remainder in *dx */
    block->add_instr(bblkid, ir_mov(tmp, x86_arg_extract(ax, op0.size-1, 0), addr));
    block->add_instr(bblkid, ir_sdiv(dividend, tmp , op0, addr ));
    block->add_instr(bblkid, ir_smod(remainder, tmp , op0, addr ));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_imul_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, op2, lower, higher, tmp0, tmp1, ax, tmp2, tmp3, tmp4, cf, of;
    
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0): ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0): ir_var(X64_OF, 63, 0);
    
    /* One-operand form */
    if( instr->detail->x86.op_count == 1 ){
        /* Get operands */
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
        ax = (mode == CPUMode::X86)? ir_var(X86_EAX, op0.size-1, 0): ir_var(X64_RAX, op0.size-1, 0);
        if( op0.size == 8 ){
            lower = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 15, 0);
            higher = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 8): ir_var(X64_RAX, 15, 8);
        }else{
            lower = (mode == CPUMode::X86)? ir_var(X86_EAX, op0.size-1, 0): ir_var(X64_RAX, op0.size-1, 0);
            higher = (mode == CPUMode::X86)? ir_var(X86_EDX, op0.size-1, 0): ir_var(X64_RDX, op0.size-1, 0);
        }
        tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp2 = ir_tmp(tmp_var_count++, 0, 0);
        tmp3 = ir_tmp(tmp_var_count++, 0, 0);
        
        /* Do the multiplication */
        block->add_instr(bblkid, ir_smull(tmp0, ax, op0, addr));
        block->add_instr(bblkid, ir_smulh(tmp1, ax, op0, addr));
        block->add_instr(bblkid, ir_mov(lower, tmp0, addr));
        block->add_instr(bblkid, ir_mov(higher, tmp1, addr));
        
        /* Set OF and CF iff the higher:lower != signextend(lower) 
         * SO we do 
         *      higher==0 && lower[n-1] == 0 
         *  OR  higher==0xfff.... && lower[n-1] == 1 */
        block->add_instr(bblkid, ir_bisz(tmp2, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_not(tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1), addr));
        block->add_instr(bblkid, ir_and(tmp2, tmp2, tmp3, addr));
        block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
        block->add_instr(bblkid, ir_bisz(tmp3, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_and(tmp3, tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1),  addr));
        block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr));
        
        block->add_instr(bblkid, ir_bisz(cf, tmp3, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_bisz(of, tmp3, ir_cst(1, 0, 0), addr));
    
    /* Two-operands form */
    }else if( instr->detail->x86.op_count == 2){
        /* Get operands */
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
        op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
        tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp2 = ir_tmp(tmp_var_count++, 0, 0);
        tmp3 = ir_tmp(tmp_var_count++, 0, 0);
        
        /* Do the multiplication */
        block->add_instr(bblkid, ir_smull(tmp0, op0, op1, addr));
        block->add_instr(bblkid, ir_smulh(tmp1, op0, op1, addr));
        block->add_instr(bblkid, ir_mov(op0, tmp0, addr));
        
        /* Set OF and CF iff the higher:lower != signextend(lower) 
         * SO we do 
         *      higher==0 && lower[n-1] == 0 
         *  OR  higher==0xfff.... && lower[n-1] == 1 */
        block->add_instr(bblkid, ir_bisz(tmp2, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_not(tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1), addr));
        block->add_instr(bblkid, ir_and(tmp2, tmp2, tmp3, addr));
        block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
        block->add_instr(bblkid, ir_bisz(tmp3, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_and(tmp3, tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1),  addr));
        block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr));
        
        block->add_instr(bblkid, ir_bisz(cf, tmp3, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_bisz(of, tmp3, ir_cst(1, 0, 0), addr));
         
        
    /* Three-operands form */
    }else{
        /* Get operands */
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
        op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
        op2 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[2]), block, bblkid, tmp_var_count, true);
        if( op2.size == 8 )
            op2 = ir_cst(op2.cst(), op1.size-1, 0); // Already sign extended in IROperand() constructor
        tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        tmp2 = ir_tmp(tmp_var_count++, 0, 0);
        tmp3 = ir_tmp(tmp_var_count++, 0, 0);
        
        /* Do the multiplication */
        block->add_instr(bblkid, ir_smull(tmp0, op1, op2, addr));
        block->add_instr(bblkid, ir_smulh(tmp1, op1, op2, addr));
        block->add_instr(bblkid, ir_mov(op0, tmp0, addr));
        
        /* Set OF and CF iff the higher:lower != signextend(lower) 
         * SO we do 
         *      higher==0 && lower[n-1] == 0 
         *  OR  higher==0xfff.... && lower[n-1] == 1 */
        block->add_instr(bblkid, ir_bisz(tmp2, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_not(tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1), addr));
        block->add_instr(bblkid, ir_and(tmp2, tmp2, tmp3, addr));
        block->add_instr(bblkid, ir_not(tmp1, tmp1, addr));
        block->add_instr(bblkid, ir_bisz(tmp3, tmp1, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_and(tmp3, tmp3, x86_arg_extract(tmp0, tmp0.size-1, tmp0.size-1),  addr));
        block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr));
        
        block->add_instr(bblkid, ir_bisz(cf, tmp3, ir_cst(1, 0, 0), addr));
        block->add_instr(bblkid, ir_bisz(of, tmp3, ir_cst(1, 0, 0), addr));
        
    }
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_inc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, dest, op0, tmp;
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    
    /* Increment op0 */
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0); 
    block->add_instr(bblkid, ir_add(tmp, op0, ir_cst(1, op0.size-1, 0), addr ));
    
    /* Set flags (except CF) */
    x86_set_pf(mode, tmp, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, tmp, addr, block, bblkid );
    x86_set_zf(mode, tmp, addr, block, bblkid );
    x86_sub_set_af(mode, op0, ir_cst(1, op0.size-1, 0), tmp, addr, block, bblkid, tmp_var_count);
    x86_sub_set_of(mode, op0, ir_cst(1, op0.size-1, 0), tmp, addr, block, bblkid, tmp_var_count);
    
    /* Store result */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp, addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_int_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, num, next_pc;
    
    /* Get operands */
    pc = x86_get_pc(mode);
    next_pc = ir_tmp(tmp_var_count++, pc.size-1, 0); 
    block->add_instr(bblkid, ir_add(next_pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    num = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    /* Create interrupt */
    block->add_instr(bblkid, ir_int(num, next_pc, addr));
    return;
}

inline void x86_int3_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, num, next_pc;
    
    /* Get operands */
    pc = x86_get_pc(mode);
    next_pc = ir_tmp(tmp_var_count++, pc.size-1, 0);
    block->add_instr(bblkid, ir_add(next_pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* Create interrupt 3 */
    block->add_instr(bblkid, ir_int(ir_cst(3, 7, 0), next_pc, addr));
    return;
}

inline void x86_leave_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, bp, sp;
    
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0) : ir_var(X64_RSP, 63, 0);
    bp = (mode == CPUMode::X86)? ir_var(X86_EBP, 31, 0) : ir_var(X64_RBP, 63, 0);    
       
    /* esp <- ebp
     * ebp <- pop() */ 
    block->add_instr(bblkid, ir_mov(sp, bp, addr ));
    block->add_instr(bblkid, ir_ldm(bp, sp, addr ));
    block->add_instr(bblkid, ir_add(sp, sp, ir_cst(bp.size/8, sp.size-1, 0), addr ));
    
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_ja_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, tmp2, zf, cf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, cf.size-1, 0);

    /* Condition CF = ZF = 0 */ 
    block->add_instr(bblkid, ir_or(tmp0, cf, zf, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr));
    
    return;
}

inline void x86_jae_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, cf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Condition CF = 0 */ 
    block->add_instr(bblkid, ir_jcc(cf, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr));
    
    return;
}

inline void x86_jb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, cf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);

    /* Condition CF = 1 */ 
    block->add_instr(bblkid, ir_jcc(cf, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr));
    
    return;
}

inline void x86_jbe_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, zf, cf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, cf.size-1, 0);
    
    /* Condition CF = 1 or ZF = 1 */ 
    block->add_instr(bblkid, ir_or(tmp0, cf, zf, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jcxz_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, cx, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    cx = (mode == CPUMode::X86)? ir_var(X86_ECX, 15, 0) : ir_var(X64_RCX, 15, 0);
    
    /* Condition CX = 0 */ 
    block->add_instr(bblkid, ir_jcc(cx, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_je_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, zf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);

    /* Condition ZF = 1 */ 
    block->add_instr(bblkid, ir_jcc(zf, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr));
    
    return;
}

inline void x86_jecxz_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, ecx, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    ecx = (mode == CPUMode::X86)? ir_var(X86_ECX, 31, 0) : ir_var(X64_RCX, 31, 0);
    
    /* Condition ECX = 0 */ 
    block->add_instr(bblkid, ir_jcc(ecx, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, zf, sf, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, sf.size-1, 0);

    /* Condition ZF = 0 and SF = OF */ 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr ));
    block->add_instr(bblkid, ir_or(tmp0, tmp0, zf, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jge_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, sf, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, sf.size-1, 0);
    
    /* Condition SF = OF */ 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jl_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, sf, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, sf.size-1, 0);

    /* Condition SF != OF */ 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jle_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, zf, sf, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, sf.size-1, 0);

    /* Condition ZF = 1 or SF != OF */ 
    block->add_instr(bblkid, ir_xor(tmp0, sf, of, addr ));
    block->add_instr(bblkid, ir_or(tmp0, tmp0, zf, addr ));
    
    /* Two possible values */
    block->add_instr(bblkid, ir_jcc(tmp0, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jmp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    block->add_instr(bblkid, ir_jcc(ir_cst(1, pc.size-1, 0), op0, ir_none(), addr ));
    
    return;
}

inline void x86_jne_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, zf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);

    /* Condition ZF = 0 */ 
    block->add_instr(bblkid, ir_jcc(zf, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jno_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Condition OF = 0 */ 
    block->add_instr(bblkid, ir_jcc(of, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jnp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, pf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    pf = (mode == CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Condition PF = 0 */ 
    block->add_instr(bblkid, ir_jcc(pf, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jns_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, sf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);

    /* Condition SF = 0 */ 
    block->add_instr(bblkid, ir_jcc(sf, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jo_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, of, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Condition OF = 1 */ 
    block->add_instr(bblkid, ir_jcc(of, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, pf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    pf = (mode == CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Condition PF = 1 */ 
    block->add_instr(bblkid, ir_jcc(pf, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}

inline void x86_jrcxz_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, rcx, tmp0, op0;
    
    if( mode == CPUMode::X86 )
        throw runtime_exception("JRCXZ: invalid instruction in X86 mode");
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = ir_var(X64_RIP, 63, 0);
    rcx = ir_var(X64_RCX, 63, 0);
    
    /* Condition RCX = 0 */ 
    block->add_instr(bblkid, ir_jcc(rcx, ir_cst(instr->size+addr, pc.size-1, 0), ir_cst(op0.cst(), pc.size-1, 0), addr ));
    
    return;
}

inline void x86_js_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, sf, op0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);

    /* Condition SF = 1 */ 
    block->add_instr(bblkid, ir_jcc(sf, ir_cst(op0.cst(), pc.size-1, 0), ir_cst(instr->size+addr, pc.size-1, 0), addr ));
    
    return;
}


inline void x86_lahf_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, sf, zf, af, pf, cf, ax;
    
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    sf = (mode == CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    zf = (mode == CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    af = (mode == CPUMode::X86)? ir_var(X86_AF, 31, 0) : ir_var(X64_AF, 63, 0);
    pf = (mode == CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0) : ir_var(X64_RAX, 63, 0);
    
    /* AH <- EFLAGS(SF:ZF:0:AF:0:PF:1:CF) */ 
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 15, 15), x86_arg_extract(sf, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 14, 14), x86_arg_extract(zf, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 13, 13), ir_cst(0, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 12, 12), x86_arg_extract(af, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 11, 11), ir_cst(0, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 10, 10), x86_arg_extract(pf, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 9, 9), ir_cst(1, 0, 0), addr ));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(ax, 8, 8), x86_arg_extract(cf, 0, 0), addr ));
    
    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_lea_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, tmp0, op0, op1;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count);
    
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    
    /* Check operand sizes */
    if( op0.size > op1.size ){
        /* Zero extend */
        tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
        block->add_instr(bblkid, ir_mov(tmp0, ir_cst(0, op0.size-1, 0), addr ));
        block->add_instr(bblkid, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
        block->add_instr(bblkid, ir_mov(op0, tmp0, addr ));
    }else{
        /* Truncate of needed */
        block->add_instr(bblkid, ir_mov(op0, x86_arg_extract(op1, op0.size-1, 0), addr ));
    }
    
    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_lodsb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, al, si, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    al = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 7, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    block->add_instr(bblkid, ir_ldm(al, si, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, 31, 0), ir_cst(inc, 31, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_lodsd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, eax, si, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 31, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    block->add_instr(bblkid, ir_ldm(eax, si, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_lodsq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, rax, si, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = ir_var(X64_DF, 63, 0);
    rax = ir_var(X64_RAX, 63, 0);
    si = ir_var(X64_RSI, 63, 0);
    pc = ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    block->add_instr(bblkid, ir_ldm(rax, si, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_lodsw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, ax, si, df;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 0): ir_var(X64_RAX, 15, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    block->add_instr(bblkid, ir_ldm(ax, si, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_mov_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    
    /*  Do the mov */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(op0, op1, addr));
    }else{
        block->add_instr(bblkid, ir_mov(op0, op1, addr));
    }
    
    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_movsb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, di, si, df, tmp0;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);

    /*  Load byte */
    tmp0 = ir_tmp(tmp_var_count++, 7, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_stm(di, tmp0, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment if DF = 0 */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement if DF = 1*/
    block->add_instr(dec, ir_sub(si, si, ir_cst(1, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_movsd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, di, si, df, tmp0;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);

    /*  Load dword */
    tmp0 = ir_tmp(tmp_var_count++, 31, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_stm(di, tmp0, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment if DF = 0 */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement if DF = 1*/
    block->add_instr(dec, ir_sub(si, si, ir_cst(4, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_movsq_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, di, si, df, tmp0;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);

    /*  Load qword */
    tmp0 = ir_tmp(tmp_var_count++, 63, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_stm(di, tmp0, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment if DF = 0 */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement if DF = 1*/
    block->add_instr(dec, ir_sub(si, si, ir_cst(8, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(8, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_movsw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, di, si, df, tmp0;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    si = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);

    /*  Load word */
    tmp0 = ir_tmp(tmp_var_count++, 15, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, si, addr));
    block->add_instr(bblkid, ir_stm(di, tmp0, addr));
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment if DF = 0 */ 
    block->add_instr(inc, ir_add(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(inc, ir_add(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement if DF = 1*/
    block->add_instr(dec, ir_sub(si, si, ir_cst(2, si.size-1, 0), addr));
    block->add_instr(dec, ir_sub(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_movsx_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp0;
    IRBasicBlockId pos, neg, end;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    /*  Test MSB */
    pos = block->new_bblock();
    neg = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(op1, op1.size-1, op1.size-1), ir_cst(neg, 31, 0), ir_cst(pos, 31, 0), addr));
    /* Positive (0 extend) */
    block->add_instr(pos, ir_mov(tmp0, ir_cst(0, tmp0.size-1, 0), addr));
    block->add_instr(pos, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    block->add_instr(pos, ir_mov(op0, tmp0, addr));
    block->add_instr(pos, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Negative (1 extend) */
    block->add_instr(neg, ir_mov(tmp0, ir_cst((ucst_t)0xffffffffffffffff<<op1.size, tmp0.size-1, 0), addr));
    block->add_instr(neg, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    block->add_instr(neg, ir_mov(op0, tmp0, addr));
    block->add_instr(neg, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_movsxd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp0;
    IRBasicBlockId pos, neg, end;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    /* If already same size, just mov */
    if( op0.size == op1.size ){
        block->add_instr(bblkid, ir_mov(op0, op1, addr));
        return;
    }
    /*  Else extend : Test MSB */
    pos = block->new_bblock();
    neg = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(op1, op1.size-1, op1.size-1), ir_cst(neg, 31, 0), ir_cst(pos, 31, 0), addr));
    /* Positive (0 extend) */
    block->add_instr(pos, ir_mov(tmp0, ir_cst(0, tmp0.size-1, 0), addr));
    block->add_instr(pos, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    block->add_instr(pos, ir_mov(op0, tmp0, addr));
    block->add_instr(pos, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Negative (1 extend) */
    block->add_instr(neg, ir_mov(tmp0, ir_cst((ucst_t)0xffffffffffffffff<<op1.size, tmp0.size-1, 0), addr));
    block->add_instr(neg, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    block->add_instr(neg, ir_mov(op0, tmp0, addr));
    block->add_instr(neg, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_movzx_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp0;
    
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);

    /* Positive (0 extend) */
    block->add_instr(bblkid, ir_mov(tmp0, ir_cst(0, tmp0.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(tmp0, op1.size-1, 0), op1, addr));
    block->add_instr(bblkid, ir_mov(op0, tmp0, addr));
    
    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_mul_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, lower, higher, tmp0, tmp1, ax, tmp2, tmp3, tmp4, cf, of;
    
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0): ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0): ir_var(X64_OF, 63, 0);
    
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, op0.size-1, 0): ir_var(X64_RAX, op0.size-1, 0);
    if( op0.size == 8 ){
        lower = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 15, 0);
        higher = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 8): ir_var(X64_RAX, 15, 8);
    }else{
        lower = (mode == CPUMode::X86)? ir_var(X86_EAX, op0.size-1, 0): ir_var(X64_RAX, op0.size-1, 0);
        higher = (mode == CPUMode::X86)? ir_var(X86_EDX, op0.size-1, 0): ir_var(X64_RDX, op0.size-1, 0);
    }
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp2 = ir_tmp(tmp_var_count++, 0, 0);
    tmp3 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Do the multiplication */
    block->add_instr(bblkid, ir_mul(tmp0, ax, op0, addr));
    block->add_instr(bblkid, ir_mulh(tmp1, ax, op0, addr));
    block->add_instr(bblkid, ir_mov(lower, tmp0, addr));
    block->add_instr(bblkid, ir_mov(higher, tmp1, addr));
    
    /* Set OF and CF to 1 if high order bits are not zero, else clear */
    block->add_instr(bblkid, ir_bisz(cf, tmp1, ir_cst(0, cf.size-1, 0), addr));
    block->add_instr(bblkid, ir_bisz(of, tmp1, ir_cst(0, of.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_neg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, cf, tmp0;
    
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0): ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    
    /* CF = (op0 != 0) */
    block->add_instr(bblkid, ir_bisz(cf, op0, ir_cst(0, cf.size-1, 0), addr));
    /* Do the neg */
    block->add_instr(bblkid, ir_neg(tmp0, op0, addr));
    
    /* Set flags according to the result (same that for a sub from 0) */
    x86_set_sf(mode, tmp0, addr, block, bblkid);
    x86_set_zf(mode, tmp0, addr, block, bblkid);
    x86_set_pf(mode, tmp0, addr, block, bblkid, tmp_var_count);
    x86_sub_set_af(mode, ir_cst(0, op0.size-1, 0), op0, tmp0, addr, block, bblkid, tmp_var_count);
    x86_sub_set_of(mode, ir_cst(0, op0.size-1, 0), op0, tmp0, addr, block, bblkid, tmp_var_count);
    
    /* Assign result */
    block->add_instr(bblkid, ir_mov(op0, tmp0, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_nop_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc;
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_not_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);

    /* Do the not */
    block->add_instr(bblkid, ir_not(op0, op0, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_or_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the or */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_or(res, op0, op1, addr));
    
    /* Update flags: SF, ZF, PF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    /* OF and CF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.high, cf.low), addr));
    
    /* Finally assign the result to the destination */ 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, res, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_pop_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, sp, pc, tmp0;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0); 
    
    /* Get the value on the stack */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, sp, addr));
    
    /* Increment stack pointer */
    block->add_instr(bblkid, ir_add(sp, sp, ir_cst(instr->detail->x86.operands[0].size, sp.size-1, 0), addr));
    
    /* Assign the value that was on the stack (AFTER incrementing ESP) */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(op0, tmp0, addr));
    }else{
        block->add_instr(bblkid, ir_mov(op0, tmp0, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_popad_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand esp, pc, edi, esi, ebp, ebx, edx, ecx, eax;
    
    /* Get operands */
    esp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0);
    edi = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0); 
    esi = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0); 
    ebp = (mode == CPUMode::X86)? ir_var(X86_EBP, 31, 0): ir_var(X64_RBP, 63, 0); 
    ebx = (mode == CPUMode::X86)? ir_var(X86_EBX, 31, 0): ir_var(X64_RBX, 63, 0); 
    edx = (mode == CPUMode::X86)? ir_var(X86_EDX, 31, 0): ir_var(X64_RDX, 63, 0); 
    ecx = (mode == CPUMode::X86)? ir_var(X86_ECX, 31, 0): ir_var(X64_RCX, 63, 0); 
    eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 63, 0);  
    
    /* Get the registers on the stack:
        EDI ← Pop();
        ESI ← Pop();
        EBP ← Pop();
        Increment ESP by 4; (* Skip next 4 bytes of stack *)
        EBX ← Pop();
        EDX ← Pop();
        ECX ← Pop();
        EAX ← Pop(); */
    
    block->add_instr(bblkid, ir_ldm(edi, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(esi, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(ebp, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/4, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(ebx, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(edx, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(ecx, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    block->add_instr(bblkid, ir_ldm(eax, esp, addr));
    block->add_instr(bblkid, ir_add(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_push_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, sp, pc;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0); 
    
    /* Decrement stack pointer */
    block->add_instr(bblkid, ir_sub(sp, sp, ir_cst(instr->detail->x86.operands[0].size, sp.size-1, 0), addr));
    
    /* Get the value on the stack */
    block->add_instr(bblkid, ir_stm(sp, op0, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_pushad_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand esp, pc, edi, esi, ebp, ebx, edx, ecx, eax, tmp0;
    
    /* Get operands */
    esp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0);
    edi = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0); 
    esi = (mode == CPUMode::X86)? ir_var(X86_ESI, 31, 0): ir_var(X64_RSI, 63, 0); 
    ebp = (mode == CPUMode::X86)? ir_var(X86_EBP, 31, 0): ir_var(X64_RBP, 63, 0); 
    ebx = (mode == CPUMode::X86)? ir_var(X86_EBX, 31, 0): ir_var(X64_RBX, 63, 0); 
    edx = (mode == CPUMode::X86)? ir_var(X86_EDX, 31, 0): ir_var(X64_RDX, 63, 0); 
    ecx = (mode == CPUMode::X86)? ir_var(X86_ECX, 31, 0): ir_var(X64_RCX, 63, 0); 
    eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 63, 0);  
    tmp0 = ir_tmp(tmp_var_count++, esp.size-1, 0);
    
    /* Get the registers on the stack:
        Temp ← (ESP);
        Push(EAX);
        Push(ECX);
        Push(EDX);
        Push(EBX);
        Push(Temp);
        Push(EBP);
        Push(ESI);
        Push(EDI); */
    
    block->add_instr(bblkid, ir_mov(tmp0, esp, addr));
    
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, eax, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, ecx, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, edx, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, ebx, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, tmp0, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, ebp, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, esi, addr));
    
    block->add_instr(bblkid, ir_sub(esp, esp, ir_cst(esp.size/8, esp.size-1, 0), addr));
    block->add_instr(bblkid, ir_stm(esp, edi, addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_rcl_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp_op0, tmp_oppo, of;
    IRBasicBlockId set_of, cont;
    unsigned int mask = (mode == CPUMode::X86)? 0b11111 : 0b111111;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op1.size-1, 0), addr)); // 5 bits for X86, 6 bits for X64
    
    /* Set rotations */
    tmp4 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp4, ir_cst(op0.size+1, tmp0.size-1, 0), tmp0, addr));
    
    /* Create a fake register CF.op0 to do the rotation */
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1+1, 0);
    tmp_op0 = ir_tmp(tmp_var_count++, tmp0.size-1+1, 0); // Ajust left shift to size N+1
    tmp_oppo = ir_tmp(tmp_var_count++, tmp4.size-1+1, 0); // Adjust right shift to size N+1
    block->add_instr(bblkid, ir_concat(tmp1, x86_arg_extract(cf, 0, 0), op0, addr));
    block->add_instr(bblkid, ir_mov(tmp_op0, ir_cst(0, tmp_op0.size-1, 0), addr)); 
    block->add_instr(bblkid, ir_mov(x86_arg_extract(tmp_op0, tmp0.size-1, 0), tmp0, addr)); // tmp_op0 = left shift
    block->add_instr(bblkid, ir_mov(tmp_oppo, ir_cst((ucst_t)1<<(tmp_oppo.size-1), tmp_oppo.size-1, 0), addr)); // 1 as MSB because negative right shift
    block->add_instr(bblkid, ir_mov(x86_arg_extract(tmp_oppo, tmp4.size-1, 0), tmp4, addr)); // tmp_oppo = right shift
    
    /* Rotate it (combine 2 shifts) */
    tmp2 = ir_tmp(tmp_var_count++, tmp1.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, tmp1.size-1, 0);
    block->add_instr(bblkid, ir_shl(tmp2, tmp1, tmp_op0, addr));
    block->add_instr(bblkid, ir_shr(tmp3, tmp1, tmp_oppo, addr));
    block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr)); // res on N+1 bits in tmp3
    
    /* Assign results to operand and CF */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, x86_arg_extract(tmp3, op0.size-1, 0), addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, x86_arg_extract(tmp3, op0.size-1, 0), addr));
    }
    block->add_instr(bblkid, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp3, tmp3.size-1, tmp3.size-1), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* Affect OF flag iff masked count == 1 (cf.res in tmp3)*/
    set_of = block->new_bblock();
    cont = block->new_bblock();
    tmp5 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(bblkid, ir_xor(tmp5, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(bblkid, ir_bcc(tmp5, ir_cst(cont, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(tmp3, tmp3.size-2, tmp3.size-2), x86_arg_extract(cf, 0, 0), addr)); // tmp3.size-2 because tmp3 has size N+1 (CF.DEST)
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(cont, 31, 0), ir_none(), addr));
    
    bblkid = cont;
    return;
}

inline void x86_rcr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp_op0, tmp_oppo, of;
    IRBasicBlockId set_of, cont;
    unsigned int mask = (mode == CPUMode::X86)? 0b11111 : 0b111111;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op1.size-1, 0), addr)); // 5 bits for X86, 6 bits for X64
    
    /* Affect OF flag iff masked count == 1 */
    set_of = block->new_bblock();
    cont = block->new_bblock();
    tmp5 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(bblkid, ir_xor(tmp5, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(bblkid, ir_bcc(tmp5, ir_cst(cont, 31, 0), ir_cst(set_of, 31, 0), addr));
    
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(op0, op0.size-1, op0.size-1), x86_arg_extract(cf, 0, 0), addr));
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0), ir_cst(cont, 31, 0), ir_none(), addr));
    
    bblkid = cont;
    /* Set rotations */
    tmp4 = ir_tmp(tmp_var_count++, op1.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp4, ir_cst(op0.size+1, tmp0.size-1, 0), tmp0, addr)); // Equivalent left shift of the rotate (+1 because CF included) 
    
    /* Create a fake register CF.op0 to do the rotation */
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1+1, 0);
    tmp_op0 = ir_tmp(tmp_var_count++, tmp0.size-1+1, 0); // Ajust right shift to size N+1
    tmp_oppo = ir_tmp(tmp_var_count++, tmp4.size-1+1, 0); // Adjust left shift to size N+1
    block->add_instr(bblkid, ir_concat(tmp1, x86_arg_extract(cf, 0, 0), op0, addr));
    block->add_instr(bblkid, ir_mov(tmp_op0, ir_cst((ucst_t)1<<(tmp_op0.size-1), tmp_op0.size-1, 0), addr)); // 1 as MSB because negative right shift 
    block->add_instr(bblkid, ir_mov(x86_arg_extract(tmp_op0, tmp0.size-1, 0), tmp0, addr)); // tmp_op0 = right shift
    block->add_instr(bblkid, ir_mov(tmp_oppo, ir_cst(0, tmp_oppo.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(tmp_oppo, tmp4.size-1, 0), tmp4, addr)); // tmp_oppo = left shift
    
    /* Rotate it (2 shifts) */
    tmp2 = ir_tmp(tmp_var_count++, tmp1.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, tmp1.size-1, 0);
    block->add_instr(bblkid, ir_shr(tmp2, tmp1, tmp_op0, addr));
    block->add_instr(bblkid, ir_shl(tmp3, tmp1, tmp_oppo, addr));
    block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr)); // res on N+1 bits in tmp3
    
    /* Assign results to operand and CF */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, x86_arg_extract(tmp3, op0.size-1, 0), addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, x86_arg_extract(tmp3, op0.size-1, 0), addr));
    }
    block->add_instr(bblkid, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp3, tmp3.size-1, tmp3.size-1), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_ret_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, sp, pc, tmp0;
    
    /* Get operands */
    sp = (mode == CPUMode::X86)? ir_var(X86_ESP, 31, 0): ir_var(X64_RSP, 63, 0); 
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0): ir_var(X64_RIP, 63, 0);
    
    /* Pop program counter */
    tmp0 = ir_tmp(tmp_var_count++, pc.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, sp, addr));
    block->add_instr(bblkid, ir_add(sp, sp, ir_cst(pc.size/8, sp.size-1, 0), addr));
    
    /* If source operand adjust sp */
    if( instr->detail->x86.op_count != 0 ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
        block->add_instr(bblkid, ir_add(sp, sp, op0, addr));
    }
    
    block->add_instr(bblkid, ir_jcc(ir_cst(1, pc.size-1, 0), tmp0, ir_none(), addr));
    
    return;
}

inline void x86_rol_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp_op0, tmp_oppo, of;
    IRBasicBlockId set_of, cont, set_cf, end;
    unsigned int mask = (mode == CPUMode::X86)? 0b11111 : 0b111111;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op0.size-1, 0), addr)); // 5 bits for X86, 6 bits for X64
    
    
    /* Set rotations */
    tmp4 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp4, ir_cst(op0.size, tmp0.size-1, 0), tmp0, addr));
    
    /* Rotate it (2 shifts) */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_shl(tmp2, op0, tmp0, addr));
    block->add_instr(bblkid, ir_shr(tmp3, op0, tmp4, addr));
    block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr)); // res in tmp3
    
    /* Assign result to operand */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp3, addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp3, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    set_cf = block->new_bblock();
    cont = block->new_bblock();
    set_of = block->new_bblock();
    end = block->new_bblock();
    
    /* Affect CF flag iff masked count != 0 */
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(set_cf, 31, 0), ir_cst(end, 31, 0), addr));
    block->add_instr(set_cf, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp3, 0, 0), addr));
    block->add_instr(set_cf, ir_bcc(ir_cst(1, 31, 0), ir_cst(cont, 31, 0), ir_none(), addr));
    
    /* Affect OF flag iff masked count == 1 (res in tmp3) */
    tmp5 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(cont, ir_xor(tmp5, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(cont, ir_bcc(tmp5, ir_cst(end, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(tmp3, tmp3.size-1, tmp3.size-1), x86_arg_extract(cf, 0, 0), addr)); 
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_ror_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp_op0, tmp_oppo, of;
    IRBasicBlockId set_of, cont, set_cf, end;
    unsigned int mask = (mode == CPUMode::X86)? 0b11111 : 0b111111;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, x86_arg_extract(op1, op0.size-1, 0), ir_cst(mask, op1.size-1, 0), addr)); // 5 bits for X86, 6 bits for X64
    block->add_instr(bblkid, ir_mov(tmp1, tmp0, addr));
    
    /* Set rotations */
    tmp4 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp4, ir_cst(op0.size, tmp0.size-1, 0), tmp0, addr));
    
    /* Rotate it (2 shifts) */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_shr(tmp2, op0, tmp0, addr));
    block->add_instr(bblkid, ir_shl(tmp3, op0, tmp4, addr));
    block->add_instr(bblkid, ir_or(tmp3, tmp3, tmp2, addr)); // res in tmp3
    
    /* Assign result to operand */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp3, addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp3, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    set_cf = block->new_bblock();
    cont = block->new_bblock();
    set_of = block->new_bblock();
    end = block->new_bblock();
    
    /* Affect CF flag iff masked count != 0 */
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(set_cf, 31, 0), ir_cst(end, 31, 0), addr));
    block->add_instr(set_cf, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp3, tmp3.size-1, tmp3.size-1), addr));
    block->add_instr(set_cf, ir_bcc(ir_cst(1, 31, 0), ir_cst(cont, 31, 0), ir_none(), addr));
    
    /* Affect OF flag iff masked count == 1 (res in tmp3) */
    tmp5 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(cont, ir_xor(tmp5, tmp1, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(cont, ir_bcc(tmp5, ir_cst(end, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(tmp3, tmp3.size-2, tmp3.size-2), x86_arg_extract(cf, 0, 0), addr)); 
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}


inline void x86_sal_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp_op0, tmp_oppo, of;
    IRBasicBlockId set_of, cont;
    unsigned int mask = (mode == CPUMode::X86)? 0b11111 : 0b111111;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op1.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, op1, ir_cst(mask, op1.size-1, 0), addr)); // 5 bits for X86, 6 bits for X64
    
    /* Affect CF (last bit shifted out) */
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp4 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp1, ir_cst(op0.size, tmp0.size-1, 0), tmp0, addr)); // Num of the last bit that'll be shifted out
    //block->add_instr(bblkid, ir_neg(tmp1, tmp1, addr)); // Shift right to get the bit
    block->add_instr(bblkid, ir_shr(tmp4, op0, tmp1, addr));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp4, 0, 0), addr));
    
    /* Do the shift */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_shl(tmp2, op0, tmp0, addr));
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp2, addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp2, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* Affect OF flag iff masked count == 1 */
    set_of = block->new_bblock();
    cont = block->new_bblock();
    tmp3 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(bblkid, ir_xor(tmp3, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(bblkid, ir_bcc(tmp3, ir_cst(cont, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_xor(x86_arg_extract(of, 0, 0), x86_arg_extract(tmp2, tmp2.size-1, tmp2.size-1), x86_arg_extract(cf, 0, 0), addr));
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(cont, 31, 0), ir_none(), addr));
    
    bblkid = cont;
    return;
}

inline void x86_sar_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp_op0, tmp_oppo, of;
    IRBasicBlockId set_of, cont, pos, neg;
    unsigned int mask = (mode == CPUMode::X86)? 0b11111 : 0b111111;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op1.size-1, 0);
    tmp3 = ir_tmp(tmp_var_count++, tmp0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, op1, ir_cst(mask, op1.size-1, 0), addr)); // 5 bits for X86, 6 bits for X64
    block->add_instr(bblkid, ir_mov(tmp3, tmp0, addr)); // save in tmp3
    
    /* Affect CF (last bit shifted out) */
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp4 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp1, tmp0, ir_cst(1, tmp0.size-1, 0), addr)); // Num of the last bit that'll be shifted out
    //block->add_instr(bblkid, ir_neg(tmp1, tmp1, addr)); // Shift right to get the bit
    block->add_instr(bblkid, ir_shr(tmp4, op0, tmp1, addr));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp4, 0, 0), addr));
    
    /* Get mask for sign propagation when shifting */
    tmp5 = ir_tmp(tmp_var_count++, op1.size-1, 0);
    tmp6 = ir_tmp(tmp_var_count++, op1.size-1, 0);
    pos = block->new_bblock();
    neg = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(x86_arg_extract(op0, op0.size-1, op0.size-1), ir_cst(neg, 31, 0), ir_cst(pos, 31, 0), addr));
    bblkid = block->new_bblock();
    block->add_instr(pos, ir_mov(tmp5, ir_cst(0, tmp5.size-1, 0), addr));
    block->add_instr(pos, ir_bcc(ir_cst(1, 31, 0), ir_cst(bblkid, 31, 0), ir_none(), addr));
    block->add_instr(neg, ir_mov(tmp5, ir_cst(-1, tmp5.size-1, 0), addr));
    block->add_instr(neg, ir_sub(tmp6, ir_cst(op0.size, tmp0.size-1, 0), tmp0, addr));
    block->add_instr(neg, ir_shl(tmp5, tmp5, tmp6, addr));
    block->add_instr(neg, ir_bcc(ir_cst(1, 31, 0), ir_cst(bblkid, 31, 0), ir_none(), addr));
    
    /* Do the shift */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_shr(tmp2, op0, tmp0, addr));
    block->add_instr(bblkid, ir_or(tmp2, tmp2, tmp5, addr));
    
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp2, addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp2, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /* Affect OF flag iff masked count == 1 */
    set_of = block->new_bblock();
    cont = block->new_bblock();
    block->add_instr(bblkid, ir_xor(tmp3, tmp3, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(bblkid, ir_bcc(tmp3, ir_cst(cont, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_mov(of, ir_cst(0, of.size-1, 0), addr));
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0) , ir_cst(cont, 31, 0), ir_none(), addr));
    
    bblkid = cont;
    return;
}

inline void x86_scasb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, al, di, df, tmp0, tmp1;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    al = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 7, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    tmp0 = ir_tmp(tmp_var_count++, al.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, al.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, di, addr));
    block->add_instr(bblkid, ir_sub(tmp1, al, tmp0, addr));
    
    /* Set flags */
    x86_set_pf( mode, tmp1, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp1, addr, block, bblkid );
    x86_set_sf( mode, tmp1, addr, block, bblkid );
    x86_sub_set_of( mode, al, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, al, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, al, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_scasd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, eax, di, df, tmp0, tmp1;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 31, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    tmp0 = ir_tmp(tmp_var_count++, eax.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, eax.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, di, addr));
    block->add_instr(bblkid, ir_sub(tmp1, eax, tmp0, addr));
    
    /* Set flags */
    x86_set_pf( mode, tmp1, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp1, addr, block, bblkid );
    x86_set_sf( mode, tmp1, addr, block, bblkid );
    x86_sub_set_of( mode, eax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, eax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, eax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_scasw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, ax, di, df, tmp0, tmp1;
    IRBasicBlockId inc, dec, end, prefix_start;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 0): ir_var(X64_RAX, 15, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    prefix_start = _x86_init_prefix(mode, instr, addr, block, bblkid);
    
    /*  Load byte */
    tmp0 = ir_tmp(tmp_var_count++, ax.size-1, 0);
    tmp1 = ir_tmp(tmp_var_count++, ax.size-1, 0);
    block->add_instr(bblkid, ir_ldm(tmp0, di, addr));
    block->add_instr(bblkid, ir_sub(tmp1, ax, tmp0, addr));
    
    /* Set flags */
    x86_set_pf( mode, tmp1, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp1, addr, block, bblkid );
    x86_set_sf( mode, tmp1, addr, block, bblkid );
    x86_sub_set_of( mode, ax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, ax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, ax, tmp0, tmp1, addr, block, bblkid, tmp_var_count );
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Add prefix if any */
    _x86_end_prefix(mode, instr, addr, block, prefix_start, end, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(end, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    bblkid = end;
    return;
}

inline void x86_seta_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, zf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 0 and ZF = 0 
    block->add_instr(bblkid, ir_not(tmp0, cf, addr));
    block->add_instr(bblkid, ir_not(tmp1, zf, addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setae_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 0 
    block->add_instr(bblkid, ir_bcc(cf, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 1
    block->add_instr(bblkid, ir_bcc(cf, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setbe_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand cf, zf, pc, tmp0, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    cf = (mode==CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, cf.size-1, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if CF = 1 or ZF = 1 
    block->add_instr(bblkid, ir_or(tmp0, cf, zf, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_sete_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand zf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 1
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, zf, of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 0 and  SF=OF 
    block->add_instr(bblkid, ir_xor(tmp0, x86_arg_extract(sf, 0, 0), x86_arg_extract(of, 0, 0), addr));
    block->add_instr(bblkid, ir_not(tmp0, tmp0, addr));
    block->add_instr(bblkid, ir_not(tmp1, x86_arg_extract(zf, 0, 0), addr));
    block->add_instr(bblkid, ir_and(tmp1, tmp1, tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp1, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setge_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF=OF 
    block->add_instr(bblkid, ir_xor(tmp0, x86_arg_extract(sf, 0, 0), x86_arg_extract(of, 0, 0), addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setl_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF != OF 
    block->add_instr(bblkid, ir_xor(tmp0, x86_arg_extract(sf, 0, 0), x86_arg_extract(of, 0, 0), addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setle_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, zf, of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    tmp0 = ir_tmp(tmp_var_count++, 0, 0);
    tmp1 = ir_tmp(tmp_var_count++, 0, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 1 or  SF != OF 
    block->add_instr(bblkid, ir_xor(tmp0, x86_arg_extract(sf, 0, 0), x86_arg_extract(of, 0, 0), addr));
    block->add_instr(bblkid, ir_or(tmp0, x86_arg_extract(zf, 0, 0), tmp0, addr));
    block->add_instr(bblkid, ir_bcc(tmp0, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setne_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand zf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    zf = (mode==CPUMode::X86)? ir_var(X86_ZF, 31, 0) : ir_var(X64_ZF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if ZF = 0
    block->add_instr(bblkid, ir_bcc(zf, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setno_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 0
    block->add_instr(bblkid, ir_bcc(of, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setnp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    pf = (mode==CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if PF = 0
    block->add_instr(bblkid, ir_bcc(pf, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setns_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF = 0
    block->add_instr(bblkid, ir_bcc(sf, ir_cst(dont_set,31, 0), ir_cst(set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_seto_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand of, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    of = (mode==CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if OF = 1
    block->add_instr(bblkid, ir_bcc(of, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_setp_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    pf = (mode==CPUMode::X86)? ir_var(X86_PF, 31, 0) : ir_var(X64_PF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if PF = 1
    block->add_instr(bblkid, ir_bcc(pf, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_sets_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand sf, pc, tmp0, tmp1, op0;
    IRBasicBlockId  set = block->new_bblock(),
                    dont_set = block->new_bblock(),
                    end = block->new_bblock();
    sf = (mode==CPUMode::X86)? ir_var(X86_SF, 31, 0) : ir_var(X64_SF, 63, 0);
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    // test if SF = 1
    block->add_instr(bblkid, ir_bcc(sf, ir_cst(set,31, 0), ir_cst(dont_set, 31, 0), addr));
    // do set
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(set, ir_stm(op0, ir_cst(1, op0.size-1, 0), addr));
    }else{
        block->add_instr(set, ir_mov(op0, ir_cst(1, op0.size-1, 0), addr));
    }
    block->add_instr(set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    // dont set - put zero 
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(dont_set, ir_stm(op0, ir_cst(0, op0.size-1, 0), addr));
    }else{
        block->add_instr(dont_set, ir_mov(op0, ir_cst(0, op0.size-1, 0), addr));
    }
    block->add_instr(dont_set, ir_bcc(ir_cst(1, 31, 0) , ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_shr_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp0, cf, tmp1, tmp2, tmp3, tmp4, tmp_op0, tmp_oppo, of;
    IRBasicBlockId set_of, cont;
    unsigned int mask = (mode == CPUMode::X86)? 0b11111 : 0b111111;
    
    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    
    /* Mask the number of rotations */
    tmp0 = ir_tmp(tmp_var_count++, op1.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp0, op1, ir_cst(mask, op1.size-1, 0), addr)); // 5 bits for X86, 6 bits for X64
    
    /* Affect CF (last bit shifted out) */
    tmp1 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    tmp4 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp1, tmp0, ir_cst(1, tmp0.size-1, 0), addr)); // Num of the last bit that'll be shifted out
    //block->add_instr(bblkid, ir_neg(tmp1, tmp1, addr)); // Shift right to get the bit
    block->add_instr(bblkid, ir_shr(tmp4, op0, tmp1, addr));
    block->add_instr(bblkid, ir_mov(x86_arg_extract(cf, 0, 0), x86_arg_extract(tmp4, 0, 0), addr));
    
    /* Affect OF flag iff masked count == 1 (before shifting) */
    set_of = block->new_bblock();
    cont = block->new_bblock();
    tmp3 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_xor(tmp3, tmp0, ir_cst(1, tmp0.size-1, 0), addr));
    block->add_instr(bblkid, ir_bcc(tmp3, ir_cst(cont, 31, 0), ir_cst(set_of, 31, 0), addr));
    block->add_instr(set_of, ir_mov(x86_arg_extract(of,0,0), x86_arg_extract(op0, op0.size-1, op0.size-1), addr));
    block->add_instr(set_of, ir_bcc(ir_cst(1, 31, 0), ir_cst(cont, 31, 0), ir_none(), addr));
    
    bblkid = cont;
    /* Do the shift */
    tmp2 = ir_tmp(tmp_var_count++, op0.size-1, 0);
    //block->add_instr(bblkid, ir_neg(tmp0, tmp0, addr)); // Transform into right shift
    block->add_instr(bblkid, ir_shr(tmp2, op0, tmp0, addr));
    
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp2, addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp2, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_stc_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, cf;
    
    /* Get operand */
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    
    /* Set flag */
    block->add_instr(bblkid, ir_mov(cf, ir_cst(1, cf.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_std_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, df;
    
    /* Get operand */
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    
    /* Set flag */
    block->add_instr(bblkid, ir_mov(df, ir_cst(1, df.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_sti_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, iflag;
    
    /* Get operand */
    iflag = (mode == CPUMode::X86)? ir_var(X86_IF, 31, 0) : ir_var(X64_IF, 63, 0);
    
    /* Set flag */
    block->add_instr(bblkid, ir_mov(iflag, ir_cst(1, iflag.size-1, 0), addr));
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_stosb_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, al, di, df;
    IRBasicBlockId inc, dec, end;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    al = (mode == CPUMode::X86)? ir_var(X86_EAX, 7, 0): ir_var(X64_RAX, 7, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /*  Store byte */
    block->add_instr(bblkid, ir_stm(di, al, addr));
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(1, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));

    bblkid = end;
    return;
}

inline void x86_stosd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, eax, di, df;
    IRBasicBlockId inc, dec, end;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    eax = (mode == CPUMode::X86)? ir_var(X86_EAX, 31, 0): ir_var(X64_RAX, 31, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /*  Store byte */
    block->add_instr(bblkid, ir_stm(di, eax, addr));
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(4, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));

    bblkid = end;
    return;
}

inline void x86_stosw_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, ax, di, df;
    IRBasicBlockId inc, dec, end;
    
    df = (mode == CPUMode::X86)? ir_var(X86_DF, 31, 0) : ir_var(X64_DF, 63, 0);
    ax = (mode == CPUMode::X86)? ir_var(X86_EAX, 15, 0): ir_var(X64_RAX, 15, 0);
    di = (mode == CPUMode::X86)? ir_var(X86_EDI, 31, 0): ir_var(X64_RDI, 63, 0);
    pc = (mode == CPUMode::X86)? ir_var(X86_EIP, 31, 0) : ir_var(X64_RIP, 63, 0);

    // Update PC
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    /*  Store byte */
    block->add_instr(bblkid, ir_stm(di, ax, addr));
    
    /* Adjust DI */
    inc = block->new_bblock();
    dec = block->new_bblock();
    end = block->new_bblock();
    block->add_instr(bblkid, ir_bcc(df, ir_cst(dec, df.size-1, 0), ir_cst(inc, df.size-1, 0), addr));
    /* Increment */ 
    block->add_instr(inc, ir_add(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(inc, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    /* Or decrement */
    block->add_instr(dec, ir_sub(di, di, ir_cst(2, di.size-1, 0), addr));
    block->add_instr(dec, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), addr));
    
    bblkid = end;
    return;
}

inline void x86_sub_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp, dest;
    
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    // tmp <- op0 - op1
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_sub(tmp, op0, op1, addr));
    
    // Update flags
    x86_set_pf( mode, tmp, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp, addr, block, bblkid );
    x86_set_sf( mode, tmp, addr, block, bblkid );
    x86_sub_set_of( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    x86_sub_set_cf( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    x86_sub_set_af( mode, op0, op1, tmp, addr, block, bblkid, tmp_var_count );
    
    /* Set dest operand */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, tmp, addr));
    }else{
        block->add_instr(bblkid, ir_mov(dest, tmp, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
   
    return;
}

inline void x86_sysenter_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, type, next_pc;
    
    /* Get operands */
    pc = x86_get_pc(mode);
    next_pc = ir_tmp(tmp_var_count++, pc.size-1, 0); 
    block->add_instr(bblkid, ir_add(next_pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    type = ir_cst(SYSCALL_X86_SYSENTER, 31, 0);
    
    /* Create interrupt */
    block->add_instr(bblkid, ir_syscall(type, next_pc, addr));
    return;
}

inline void x86_test_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand pc, op0, op1, tmp, cf, of;

    /* Get operands */
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0): ir_var(X64_CF, 63, 0);
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0): ir_var(X64_OF, 63, 0);

    // tmp <- op0 & op1
    tmp = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_and(tmp, op0, op1, addr));

    // Update flags (except AF that is undefined)
    x86_set_pf( mode, tmp, addr, block, bblkid, tmp_var_count );
    x86_set_zf( mode, tmp, addr, block, bblkid );
    x86_set_sf( mode, tmp, addr, block, bblkid );
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.size-1, 0), addr));
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.size-1, 0), addr));

    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));

    return;
}

inline void x86_xadd_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, pc, tmp;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);

    /* Do the add */
    res = ir_tmp(tmp_var_count++, op0.size-1, 0);
    block->add_instr(bblkid, ir_add(res, op0, op1, addr));
    
    /* Update flags */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_add_set_cf(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_af(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_add_set_of(mode, op0, op1, res, addr, block, bblkid, tmp_var_count);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    
    /* Exchange operands */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        tmp = ir_tmp(tmp_var_count++, dest.size-1, 0);
        block->add_instr(bblkid, ir_mov(tmp, dest, addr)); // In case dest is op1
        block->add_instr(bblkid, ir_mov(op1, op0, addr));
        block->add_instr(bblkid, ir_stm(tmp, res, addr));
    }else{
        block->add_instr(bblkid, ir_mov(op1, op0, addr));
        block->add_instr(bblkid, ir_mov(dest, res, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_xchg_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, pc, tmp, tmp2;
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    
    tmp2 = ir_tmp(tmp_var_count++, op1.size-1, 0);
    block->add_instr(bblkid, ir_mov(tmp2, op1, addr));
    
    /* Exchange operands */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        tmp = ir_tmp(tmp_var_count++, dest.size-1, 0);
        block->add_instr(bblkid, ir_mov(tmp, dest, addr)); // In case dest is op1
        block->add_instr(bblkid, ir_mov(op1, op0, addr));
        block->add_instr(bblkid, ir_stm(tmp, tmp2, addr));
    }else{
        block->add_instr(bblkid, ir_mov(op1, op0, addr));
        block->add_instr(bblkid, ir_mov(dest, tmp2, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

inline void x86_xor_d(CPUMode mode, cs_insn* instr, addr_t addr, IRBlock* block, IRBasicBlockId& bblkid , int& tmp_var_count){
    IROperand op0, op1, dest, res, of, cf, pc;
    of = (mode == CPUMode::X86)? ir_var(X86_OF, 31, 0) : ir_var(X64_OF, 63, 0);
    cf = (mode == CPUMode::X86)? ir_var(X86_CF, 31, 0) : ir_var(X64_CF, 63, 0);
    /* Get operands */
    dest = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count);
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        op0 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[0]), block, bblkid, tmp_var_count, true);
    }else{
        op0 = dest;
    }
    op1 = x86_arg_translate(mode, addr, &(instr->detail->x86.operands[1]), block, bblkid, tmp_var_count, true);
    /* Do the xor */
    res = ir_tmp(tmp_var_count++, (instr->detail->x86.operands[0].size*8)-1, 0);
    block->add_instr(bblkid, ir_xor(res, op0, op1, addr));
    
    /* Update flags: SF, ZF, PF */
    x86_set_zf(mode, res, addr, block, bblkid);
    x86_set_sf(mode, res, addr, block, bblkid);
    x86_set_pf(mode, res, addr, block, bblkid, tmp_var_count);
    /* OF and CF cleared */
    block->add_instr(bblkid, ir_mov(of, ir_cst(0, of.high, of.low), addr));
    block->add_instr(bblkid, ir_mov(cf, ir_cst(0, cf.high, cf.low), addr));
    
    /* Finally assign the result to the destination */ 
    /* If the add is written in memory */
    if( instr->detail->x86.operands[0].type == X86_OP_MEM ){
        block->add_instr(bblkid, ir_stm(dest, res, addr));
    /* Else direct register assign */
    }else{
        block->add_instr(bblkid, ir_mov(dest, res, addr));
    }
    
    // Update PC
    pc = x86_get_pc(mode);
    block->add_instr(bblkid, ir_add(pc, pc, ir_cst(instr->size, pc.size-1, 0), addr));
    
    return;
}

/* ==================================== */
/* Disassembly wapper 
 * 
 * If sym is not null, then is_symbolic and is_tainted should not be null.
 * If they are not null, then the disassembler should check for symbolic/tainted 
 * code and update the booleans accordingly. Disassembly ends immediately if 
 * symbolic code is detected.
 * */
IRBlock* DisassemblerX86::disasm_block(addr_t addr, code_t code, size_t code_size, SymbolicEngine* sym, bool* is_symbolic, bool* is_tainted){
    // Create new ir block
    stringstream ss; ss << "at_" << std::hex << addr;
    IRBlock * block = new IRBlock(ss.str(), addr);
    IRBasicBlockId bblkid = block->new_bblock();
    int tmp_var_count = 0;
    addr_t curr_addr = addr;
    bool stop = false;
    while( (!stop) && cs_disasm_iter(_handle, (const uint8_t**)&code, &code_size, &addr, _insn) ){
        // std::cout << "DEBUG, disassembling " << _insn->mnemonic << " " << _insn->op_str << std::endl;
        // If sym not null, check for symbolic or tainted code
        if( sym != nullptr ){
            sym->mem->check_status(curr_addr, curr_addr+_insn->size, *(sym->vars), *is_symbolic, *is_tainted); 
            if( *is_symbolic ){
                delete block;
                return nullptr; 
            }
        }
        
        // Add instruction to IRBlock
        switch(_insn->id){
            case X86_INS_AAA:       x86_aaa_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_AAD:       x86_aad_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_AAM:       x86_aam_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_AAS:       x86_aas_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ADC:       x86_adc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ADCX:      x86_adcx_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ADD:       x86_add_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_AND:       x86_and_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ANDN:      x86_andn_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BLSI:      x86_blsi_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BLSMSK:    x86_blsmsk_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BLSR:      x86_blsr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BSF:       x86_bsf_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BSR:       x86_bsr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BSWAP:     x86_bswap_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BT:        x86_bt_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BTC:       x86_btc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BTR:       x86_btr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BTS:       x86_bts_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_BZHI:      x86_bzhi_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CALL:      x86_call_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CBW:       x86_cbw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CDQ:       x86_cdq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CDQE:      x86_cdqe_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CLC:       x86_clc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CLD:       x86_cld_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CLI:       x86_cli_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMC:       x86_cmc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVA:     x86_cmova_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVAE:    x86_cmovae_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVB:     x86_cmovb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVBE:    x86_cmovbe_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVE:     x86_cmove_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVG:     x86_cmovg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVGE:    x86_cmovge_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVL:     x86_cmovl_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVLE:    x86_cmovle_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVNE:    x86_cmovne_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVNO:    x86_cmovno_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVNP:    x86_cmovnp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVNS:    x86_cmovns_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVO:     x86_cmovo_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVP:     x86_cmovp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMOVS:     x86_cmovs_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMP:       x86_cmp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPSB:     x86_cmpsb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPSD:     x86_cmpsd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPSQ:     x86_cmpsq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPSW:     x86_cmpsw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CMPXCHG:   x86_cmpxchg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CPUID:     x86_cpuid_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CWD:       x86_cwd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_CWDE:      x86_cwde_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_DEC:       x86_dec_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_DIV:       x86_div_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_IDIV:      x86_idiv_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_IMUL:      x86_imul_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_INC:       x86_inc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_INT:       x86_int_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_INT3:      x86_int3_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JA:        x86_ja_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JAE:       x86_jae_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JB:        x86_jb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JBE:       x86_jbe_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JCXZ:      x86_jcxz_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JE:        x86_je_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JECXZ:     x86_jecxz_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JG:        x86_jg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JGE:       x86_jge_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JL:        x86_jl_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JLE:       x86_jle_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JMP:       x86_jmp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JNE:       x86_jne_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JNO:       x86_jno_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JNP:       x86_jnp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JNS:       x86_jns_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JO:        x86_jo_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JP:        x86_jp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JRCXZ:     x86_jrcxz_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_JS:        x86_js_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LAHF:      x86_lahf_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LEA:       x86_lea_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LEAVE:     x86_leave_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LODSB:     x86_lodsb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LODSD:     x86_lodsd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LODSQ:     x86_lodsq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_LODSW:     x86_lodsw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOV:       x86_mov_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSB:     x86_movsb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSD:     x86_movsd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSQ:     x86_movsq_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSW:     x86_movsw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSX:     x86_movsx_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVSXD:    x86_movsxd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MOVZX:     x86_movzx_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_MUL:       x86_mul_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_NEG:       x86_neg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_NOP:       x86_nop_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_NOT:       x86_not_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_OR:        x86_or_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_POP:       x86_pop_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_POPAL:     x86_popad_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_PUSH:      x86_push_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_PUSHAL:    x86_pushad_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_RCL:       x86_rcl_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_RCR:       x86_rcr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_RET:       x86_ret_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ROL:       x86_rol_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_ROR:       x86_ror_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SAL:       x86_sal_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SAR:       x86_sar_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SCASB:     x86_scasb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SCASD:     x86_scasd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SCASW:     x86_scasw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETA:      x86_seta_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETAE:     x86_setae_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETB:      x86_setb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETBE:     x86_setbe_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETE:      x86_sete_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETG:      x86_setg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETGE:     x86_setge_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETL:      x86_setl_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETLE:     x86_setle_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETNE:     x86_setne_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETNO:     x86_setno_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETNP:     x86_setnp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETNS:     x86_setns_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETO:      x86_seto_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETP:      x86_setp_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SETS:      x86_sets_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SHL:       x86_sal_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break; // Same as SAL
            case X86_INS_SHR:       x86_shr_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STC:       x86_stc_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STD:       x86_std_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STI:       x86_sti_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STOSB:     x86_stosb_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STOSD:     x86_stosd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_STOSW:     x86_stosw_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SUB:       x86_sub_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_SYSENTER:  x86_sysenter_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_TEST:      x86_test_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_XADD:      x86_xadd_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_XCHG:      x86_xchg_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            case X86_INS_XOR:       x86_xor_d(_mode, _insn, curr_addr, block, bblkid, tmp_var_count); break;
            default: throw unsupported_instruction_exception(ExceptionFormatter() << 
                "DisassemblerX86:disasm_block(): unsupported instruction " << _insn->mnemonic << " at addr 0x" << std::hex << addr -_insn->size
                >> ExceptionFormatter::to_str );
        }
        
        // Stop if last operation is a branch operation 
        for( int i = 0; i < _insn->detail->groups_count; i++){
            if(     _insn->detail->groups[i] == X86_GRP_JUMP ||
                    _insn->detail->groups[i] == X86_GRP_CALL ||
                    _insn->detail->groups[i] == X86_GRP_RET ||
                    _insn->detail->groups[i] == X86_GRP_INT ||
                    _insn->detail->groups[i] == X86_GRP_IRET /*||
                    _insn->detail->groups[i] == X86_GRP_PRIVILEGE ||
                    _insn->detail->groups[i] == X86_GRP_BRANCH_RELATIVE */
            ){
                stop = true;
            }
        }
        curr_addr = addr;
    }
    /* Set some infos about the block */
    block->end_addr = addr;
    block->raw_size = block->start_addr - addr;
    /* Compute branching info if possible */
    if( block->get_bblock(block->nb_bblocks()-1).back().op == IROperation::JCC ){
        if( block->get_bblock(block->nb_bblocks()-1).back().src2.is_none() ){
            if( !block->get_bblock(block->nb_bblocks()-1).back().src1.is_cst() ){
                block->branch_type = BranchType::UNDEFINED;
            }else{
                block->branch_type = BranchType::BRANCH;
                block->branch_target[1] = cst_sign_trunc((_mode==CPUMode::X86)?32:64, 
                                            block->get_bblock(block->nb_bblocks()-1).back().src1.cst());
            }
        }else{
            if( !block->get_bblock(block->nb_bblocks()-1).back().src1.is_cst() ||
                !block->get_bblock(block->nb_bblocks()-1).back().src2.is_cst() ){
                block->branch_type = BranchType::MULTIUNDEFINED;
            }else{
                block->branch_type = BranchType::MULTIBRANCH;
                block->branch_target[0] = cst_sign_trunc((_mode==CPUMode::X86)?32:64, 
                                            block->get_bblock(block->nb_bblocks()-1).back().src2.cst());
                block->branch_target[1] = cst_sign_trunc((_mode==CPUMode::X86)?32:64, 
                                            block->get_bblock(block->nb_bblocks()-1).back().src1.cst());
            }
        }
    }else{
        block->branch_type = BranchType::NONE;
    }
    /* Save number of tmp variables */
    block->_nb_tmp_vars = tmp_var_count;
    return block;
}

/* ===================================
    Supported X86 - X64 instructions : 

    AAA                 ASCII Adjust After Addition
    AAD                 ASCII Adjust AX Before Division
    AAM                 ASCII Adjust AX After Multiply
    AAS                 ASCII Adjust AL After Subtraction
    ADC                 Add with Carry
    ADCX                Unsigned Integer Addition of Two Operands with Carry Flag
    ADD                 Add
    AND                 Logical AND
    ANDN                Logical AND NOT
    BLSI                Extract Lowest Set Isolated Bit
    BLSMSK              Get Mask Up to Lowest Set Bit
    BLSR                Reset Lowest Set Bit
    BSF                 Bit Scan Forward
    BSR                 Bit Scan Reverse
    BSWAP               Byte Swap
    BT                  Bit Test
    BTC                 Bit Test and Complement
    BTR                 Bit Test and Reset
    BTS                 Bit Test and Set
    BZHI                Zero High Bits Starting with Specified Bit Position
    CALL                Call Procedure
    CBW                 Convert Byte to Word (AL -> AX)
    CDQ                 Convert Doubleword to Quadword (EAX -> EDX:EAX)
    CDQE                Convert Doubleword to Quadword (EAX -> RAX)
    CLC                 Clear Carry Flag
    CLD                 Clear Direction Flag
    CLI                 Clear Interrupt Flag
    CMC                 Complement Carry Flag
    CMOVA               Conditionnal Mov if above
    CMOVAE              Conditionnal Mov if above or equal
    CMOVB               Conditionnal Mov if below
    CMOVBE              Conditionnal Mov if below or equal
    CMOVE               Conditionnal Mov if equal
    CMOVG               Conditionnal Mov if greater
    CMOVGE              Conditionnal Mov if greater or equal
    CMOVL               Conditionnal Mov if less
    CMOVLE              Conditionnal Mov if less or equal
    CMOVNE              Conditionnal Mov if not equal
    CMOVNO              Conditionnal Mov if not overflow
    CMOVNP              Conditionnal Mov if not parity
    CMOVNS              Conditionnal Mov if not sign 
    CMOVO               Conditionnal Mov if overflow
    CMOVP               Conditionnal Mov if parity
    CMOVS               Conditionnal Mov if sign
    CMP                 Compare Two Operands
    CMPSB               Compare Byte String Operands
    CMPSD               Compare Double Word String Operands
    CMPSQ               Compare Quad Word String Operands
    CMPSW               Compare Word String Operands
    CMPXCHG             Compare and Exchange
    CPUID               CPU Identification
    CWD                 Convert Word to Doubleword (AX -> DX:AX)
    CWDE                Convert Word to Doubleword (AX -> EAX)
    DEC                 Decrement by 1
    DIV                 Unsigned Divide
    IDIV                Signed Divide
    IMUL                Signed Multiply
    INC                 Increment by 1
    INT n               Call to Interrupt Procedure
    INT3                Call to Interrupt Procedure
    JA                  Conditionnal Jmp if above
    JAE                 Conditionnal Jmp if above or equal
    JB                  Conditionnal Jmp if below
    JBE                 Conditionnal Jmp if below or equal
    JCXZ                Conditionnal Jmp if CX == 0
    JECXZ               Conditionnal Jmp if ECX == 0
    JE                  Conditionnal Jmp if equal
    JG                  Conditionnal Jmp if greater
    JGE                 Conditionnal Jmp if greater or equal
    JL                  Conditionnal Jmp if less
    JLE                 Conditionnal Jmp if less or equal
    JMP                 Jump
    JNE                 Conditionnal Jmp if not equal
    JNO                 Conditionnal Jmp if not overflow
    JNP                 Conditionnal Jmp if not parity
    JNS                 Conditionnal Jmp if not sign
    JO                  Conditionnal Jmp if overflow
    JP                  Conditionnal Jmp if parity
    JRCXZ               Conditionnal Jmp if RCX == 0
    JS                  Conditionnal Jmp if sign
    LAHF                Load flags in AH
    LEA                 Load Effective Address
    LEAVE               High Level Procedure Exit
    LODSB               Load String
    LODSD               Load String
    LODSQ               Load String
    LODSW               Load String
    MOV                 Move
    MOVSB               Move Data from String to String
    MOVSD               Move Data from String to String
    MOVSQ               Move Data from String to String  
    MOVSW               Move Data from String to String 
    MOVSX               Move with sign extend
    MOVSXD              Move with sign extend
    MOVZX               Move with Zero-Extend 
    MUL                 Unsigned Multiply
    NEG                 Two's Complement Negation
    NOP                 No Operation
    NOT                 One's Complement Negation
    OR                  Logical Inclusive OR
    POP                 Pop a Value from the Stack
    POPAD               Pop All General-Purpose Registers
    PUSH                Push Word, Doubleword or Quadword Onto the Stack     
    PUSHAD              Push All General-Purpose Registers
    RCL                 Rotate left with CF
    RCR                 Rotate right with CF
    REP                 Repeat String Operation Prefix
    REPE                Repeat String Operation Prefix
    REPNE               Repeat String Operation Prefix
    REPNZ               Repeat String Operation Prefix
    REPZ                Repeat String Operation Prefix
    RET                 Return from Procedure
    ROL                 Rotate left
    ROR                 Rotate right
    SAL                 Shift Arithmetic Left
    SAR                 Shift Arithmetc Right
    SCASB               Scan String
    SCASD               Scan String
    SCASW               Scan String
    SETA                Conditionnal Set byte if above
    SETAE               Conditionnal Set byte if above or equal
    SETE                Conditionnal Set byte if equal
    SETG                Conditionnal Set byte if greater
    SETGE               Conditionnal Set byte if greater or equal
    SETL                Conditionnal Set byte if less
    SETLE               Conditionnal Set byte if less or equal
    SETNE               Conditionnal Set byte if not equal
    SETNO               Conditionnal Set byte if not overflow
    SETNP               Conditionnal Set byte if not parity
    SETNS               Conditionnal Set byte if not sign
    SETO                Conditionnal Set byte if overflow
    SETP                Conditionnal Set byte if parity
    SETS                Conditionnal Set byte if sign
    SHL                 Shift Logical Left 
    SHR                 Shift Logical Right
    STC                 Set Carry Flag
    STD                 Set Direction Flag
    STI                 Set Interrupt Flag
    STOSB               Store Byte String Operand
    STOSD               Store Double Word String Operand
    STOSW               Store Word String Operand
    SUB                 Subtract
    SYSENTER            Fast System Call
    TEST                Logical Compare
    XADD                Exchange and Add
    XCHG                Exchange Register/Memory with Register
    XOR                 Logical Exclusive OR
*/


/* ========================================= 
    Yet unsupported X86 - X64 instructions : 
    
    
    ADOX                Unsigned Integer Addition of Two Operands with Overflow Flag
    BEXTR               Bit Field Extract
    BNDCL               Check Lower Bound
    BNDCN               Check Upper Bound
    BNDCU               Check Upper Bound
    BOUND               Check Array Index Against Bounds
    CQO                 Convert Word to Doubleword/Convert Doubleword to Quadword
    CRC32               Accumulate CRC32 Value
    DAA                 Decimal Adjust AL after Addition
    DAS                 Decimal Adjust AL after Subtraction
    LOOP                Loop According to ECX Counter
    LOOPcc                Loop According to ECX Counter
    MULX                Unsigned Multiply Without Affecting Flags
    PAND                Logical AND
    PANDN                Logical AND NOT
    PAUSE                Spin Loop Hint
    POPA                Pop All General-Purpose Registers
    POPCNT                Return the Count of Number of Bits Set to 1
    POPF                Pop Stack into EFLAGS Register
    POPFD                Pop Stack into EFLAGS Register
    POPFQ                Pop Stack into EFLAGS Register
    PUSHA                Push All General-Purpose Registers
    PUSHF                Push EFLAGS Register onto the Stack
    PUSHFD                Push EFLAGS Register onto the Stack
    PUSHFQ                Push EFLAGS Register onto the Stack
    PXOR                Logical Exclusive OR
    RDFSBASE                Read FS/GS Segment Base
    RDGSBASE                Read FS/GS Segment Base
    RDMSR                Read from Model Specific Register
    RDPID                Read Processor ID
    RDPKRU                Read Protection Key Rights for User Pages
    RDPMC                Read Performance-Monitoring Counters
    RDRAND                Read Random Number
    RDSEED                Read Random SEED
    RDTSC                Read Time-Stamp Counter
    RDTSCP                Read Time-Stamp Counter and Processor ID
    RORX                Rotate Right Logical Without Affecting Flags
    SAHF                Store AH into Flags
    SARX                Shift Without Affecting Flags
    SBB                Integer Subtraction with Borrow
    SHLX                Shift Without Affecting Flags
    SHRD                Double Precision Shift Right
    SHRX                Shift Without Affecting Flags
    STAC                Set AC Flag in EFLAGS Register
    STOSQ                Store String
    STR                Store Task Register
    SYSCALL                Fast System Call
    SYSEXIT                Fast Return from Fast System Call
    SYSRET                Return From Fast System Call
    TPAUSE                Timed PAUSE
    TZCNT                Count the Number of Trailing Zero Bits
    UD                Undefined Instruction
    UMONITOR                User Level Set Up Monitor Address
    UMWAIT                User Level Monitor Wait
    VERR                Verify a Segment for Reading or Writing
    VERW                Verify a Segment for Reading or Writing
    WAIT                Wait

*/


/* Out-of-scope at the moment:
 
    ADDPD               Add Packed Double-Precision Floating-Point Values
    ADDPS               Add Packed Single-Precision Floating-Point Values
    ADDSD               Add Scalar Double-Precision Floating-Point Values
    ADDSS               Add Scalar Single-Precision Floating-Point Values
    ADDSUBPD            Packed Double-FP Add/Subtract
    ADDSUBPS            Packed Single-FP Add/Subtract
    AESDEC              Perform One Round of an AES Decryption Flow
    AESDECLAST          Perform Last Round of an AES Decryption Flow
    AESENC              Perform One Round of an AES Encryption Flow
    AESENCLAST          Perform Last Round of an AES Encryption Flow
    AESIMC              Perform the AES InvMixColumn Transformation
    AESKEYGENASSIST     AES Round Key Generation Assist
    ANDNPD              Bitwise Logical AND NOT of Packed Double Precision Floating-Point Values
    ANDNPS              Bitwise Logical AND NOT of Packed Single Precision Floating-Point Values
    ANDPD               Bitwise Logical AND of Packed Double Precision Floating-Point Values
    ANDPS               Bitwise Logical AND of Packed Single Precision Floating-Point Values
    ARPL                Adjust RPL Field of Segment Selector
    BLENDPD             Blend Packed Double Precision Floating-Point Values
    BLENDPS             Blend Packed Single Precision Floating-Point Values
    BLENDVPD            Variable Blend Packed Double Precision Floating-Point Values
    BLENDVPS            Variable Blend Packed Single Precision Floating-Point Values
    BNDLDX              Load Extended Bounds Using Address Translation
    BNDMK               Make Bounds
    BNDMOV              Move Bounds
    BNDSTX              Store Extended Bounds Using Address Translation
    CLAC                Clear AC Flag in EFLAGS Register
    CLDEMOTE            Cache Line Demote
    CLFLUSH             Flush Cache Line
    CLFLUSHOPT          Flush Cache Line Optimized
    CLTS                Clear Task-Switched Flag in CR0
    CLWB                Cache Line Write Back
    CMPPD               Compare Packed Double-Precision Floating-Point Values
    CMPPS               Compare Packed Single-Precision Floating-Point Values
    CMPSD (1)           Compare Scalar Double-Precision Floating-Point Value
    CMPSS               Compare Scalar Single-Precision Floating-Point Value
    CMPXCHG             Compare and Exchange
    CMPXCHG16B          Compare and Exchange Bytes
    CMPXCHG8B           Compare and Exchange Bytes
    COMISD              Compare Scalar Ordered Double-Precision Floating-Point Values and Set EFLAGS
    COMISS              Compare Scalar Ordered Single-Precision Floating-Point Values and Set EFLAGS
    CVTDQ2PD            Convert Packed Doubleword Integers to Packed Double-Precision Floating-Point Values
    CVTDQ2PS            Convert Packed Doubleword Integers to Packed Single-Precision Floating-Point Values
    CVTPD2DQ            Convert Packed Double-Precision Floating-Point Values to Packed Doubleword Integers
    CVTPD2PI            Convert Packed Double-Precision FP Values to Packed Dword Integers
    CVTPD2PS            Convert Packed Double-Precision Floating-Point Values to Packed Single-Precision Floating-Point Values
    CVTPI2PD            Convert Packed Dword Integers to Packed Double-Precision FP Values
    CVTPI2PS            Convert Packed Dword Integers to Packed Single-Precision FP Values
    CVTPS2DQ            Convert Packed Single-Precision Floating-Point Values to Packed Signed Doubleword Integer Values
    CVTPS2PD            Convert Packed Single-Precision Floating-Point Values to Packed Double-Precision Floating-Point Values
    CVTPS2PI            Convert Packed Single-Precision FP Values to Packed Dword Integers
    CVTSD2SI            Convert Scalar Double-Precision Floating-Point Value to Doubleword Integer
    CVTSD2SS            Convert Scalar Double-Precision Floating-Point Value to Scalar Single-Precision Floating-Point Value
    CVTSI2SD            Convert Doubleword Integer to Scalar Double-Precision Floating-Point Value
    CVTSI2SS            Convert Doubleword Integer to Scalar Single-Precision Floating-Point Value
    CVTSS2SD            Convert Scalar Single-Precision Floating-Point Value to Scalar Double-Precision Floating-Point Value
    CVTSS2SI            Convert Scalar Single-Precision Floating-Point Value to Doubleword Integer
    CVTTPD2DQ           Convert with Truncation Packed Double-Precision Floating-Point Values to Packed Doubleword Integers
    CVTTPD2PI           Convert with Truncation Packed Double-Precision FP Values to Packed Dword Integers
    CVTTPS2DQ           Convert with Truncation Packed Single-Precision Floating-Point Values to Packed Signed Doubleword Integer Values
    CVTTPS2PI           Convert with Truncation Packed Single-Precision FP Values to Packed Dword Integers
    CVTTSD2SI           Convert with Truncation Scalar Double-Precision Floating-Point Value to Signed Integer
    CVTTSS2SI           Convert with Truncation Scalar Single-Precision Floating-Point Value to Integer
    DIVPD               Divide Packed Double-Precision Floating-Point Values
    DIVPS               Divide Packed Single-Precision Floating-Point Values
    DIVSD               Divide Scalar Double-Precision Floating-Point Value
    DIVSS               Divide Scalar Single-Precision Floating-Point Values
    DPPD                Dot Product of Packed Double Precision Floating-Point Values
    DPPS                Dot Product of Packed Single Precision Floating-Point Values
    EMMS                Empty MMX Technology State
    ENTER               Make Stack Frame for Procedure Parameters
    EXTRACTPS           Extract Packed Floating-Point Values
    F2XM1               Compute 2x–1
    FABS                Absolute Value
    FADD                Add
    FADDP               Add
    FBLD                Load Binary Coded Decimal
    FBSTP               Store BCD Integer and Pop
    FCHS                Change Sign
    FCLEX               Clear Exceptions
    FCMOVcc             Floating-Point Conditional Move
    FCOM                Compare Floating Point Values
    FCOMI               Compare Floating Point Values and Set EFLAGS
    FCOMIP              Compare Floating Point Values and Set EFLAGS
    FCOMP               Compare Floating Point Values
    FCOMPP              Compare Floating Point Values
    FCOS                Cosine
    FDECSTP             Decrement Stack-Top Pointer
    FDIV                Divide
    FDIVP               Divide
    FDIVR               Reverse Divide
    FDIVRP              Reverse Divide
    FFREE               Free Floating-Point Register
    FIADD               Add
    FICOM               Compare Integer
    FICOMP              Compare Integer
    FIDIV               Divide
    FIDIVR              Reverse Divide
    FILD                Load Integer
    FIMUL               Multiply
    FINCSTP             Increment Stack-Top Pointer
    FINIT               Initialize Floating-Point Unit
    FIST                Store Integer
    FISTP               Store Integer
    FISTTP              Store Integer with Truncation
    FISUB               Subtract
    FISUBR              Reverse Subtract
    FLD                 Load Floating Point Value
    FLD1                Load Constant
    FLDCW               Load x87 FPU Control Word
    FLDENV              Load x87 FPU Environment
    FLDL2E              Load Constant
    FLDL2T              Load Constant
    FLDLG2              Load Constant
    FLDLN2              Load Constant
    FLDPI               Load Constant
    FLDZ                Load Constant
    FMUL                Multiply
    FMULP               Multiply
    FNCLEX              Clear Exceptions
    FNINIT              Initialize Floating-Point Unit
    FNOP                No Operation
    FNSAVE              Store x87 FPU State
    FNSTCW              Store x87 FPU Control Word
    FNSTENV             Store x87 FPU Environment
    FNSTSW              Store x87 FPU Status Word
    FPATAN              Partial Arctangent
    FPREM               Partial Remainder
    FPREM1              Partial Remainder
    FPTAN               Partial Tangent
    FRNDINT             Round to Integer
    FRSTOR              Restore x87 FPU State
    FSAVE               Store x87 FPU State
    FSCALE              Scale
    FSIN                Sine
    FSINCOS             Sine and Cosine
    FSQRT               Square Root
    FST                 Store Floating Point Value
    FSTCW               Store x87 FPU Control Word
    FSTENV                Store x87 FPU Environment
    FSTP                Store Floating Point Value
    FSTSW                Store x87 FPU Status Word
    FSUB                Subtract
    FSUBP                Subtract
    FSUBR                Reverse Subtract
    FSUBRP                Reverse Subtract
    FTST                TEST
    FUCOM                Unordered Compare Floating Point Values
    FUCOMI                Compare Floating Point Values and Set EFLAGS
    FUCOMIP                Compare Floating Point Values and Set EFLAGS
    FUCOMP                Unordered Compare Floating Point Values
    FUCOMPP                Unordered Compare Floating Point Values
    FWAIT                Wait
    FXAM                Examine Floating-Point
    FXCH                Exchange Register Contents
    FXRSTOR                Restore x87 FPU, MMX, XMM, and MXCSR State
    FXSAVE                Save x87 FPU, MMX Technology, and SSE State
    FXTRACT                Extract Exponent and Significand
    FYL2X                Compute y ∗ log2x
    FYL2XP1                Compute y ∗ log2(x +1)
    GF2P8AFFINEINVQB                Galois Field Affine Transformation Inverse
    GF2P8AFFINEQB                Galois Field Affine Transformation
    GF2P8MULB                Galois Field Multiply Bytes
    HADDPD                Packed Double-FP Horizontal Add
    HADDPS                Packed Single-FP Horizontal Add
    HLT                Halt
    HSUBPD                Packed Double-FP Horizontal Subtract
    HSUBPS                Packed Single-FP Horizontal Subtract
    IN                Input from Port
    INS                Input from Port to String
    INSB                Input from Port to String
    INSD                Input from Port to String
    INSERTPS                Insert Scalar Single-Precision Floating-Point Value
    INSW                Input from Port to String
    INT1                Call to Interrupt Procedure
    INTO                Call to Interrupt Procedure
    INVD                Invalidate Internal Caches
    INVLPG                Invalidate TLB Entries
    INVPCID                Invalidate Process-Context Identifier
    IRET                Interrupt Return
    IRETD                Interrupt Return

    KADDB                ADD Two Masks
    KADDD                ADD Two Masks
    KADDQ                ADD Two Masks
    KADDW                ADD Two Masks
    KANDB                Bitwise Logical AND Masks
    KANDD                Bitwise Logical AND Masks
    KANDNB                Bitwise Logical AND NOT Masks
    KANDND                Bitwise Logical AND NOT Masks
    KANDNQ                Bitwise Logical AND NOT Masks
    KANDNW                Bitwise Logical AND NOT Masks
    KANDQ                Bitwise Logical AND Masks
    KANDW                Bitwise Logical AND Masks
    KMOVB                Move from and to Mask Registers
    KMOVD                Move from and to Mask Registers
    KMOVQ                Move from and to Mask Registers
    KMOVW                Move from and to Mask Registers
    KNOTB                NOT Mask Register
    KNOTD                NOT Mask Register
    KNOTQ                NOT Mask Register
    KNOTW                NOT Mask Register
    KORB                Bitwise Logical OR Masks
    KORD                Bitwise Logical OR Masks
    KORQ                Bitwise Logical OR Masks
    KORTESTB                OR Masks And Set Flags
    KORTESTD                OR Masks And Set Flags
    KORTESTQ                OR Masks And Set Flags
    KORTESTW                OR Masks And Set Flags
    KORW                Bitwise Logical OR Masks
    KSHIFTLB                Shift Left Mask Registers
    KSHIFTLD                Shift Left Mask Registers
    KSHIFTLQ                Shift Left Mask Registers
    KSHIFTLW                Shift Left Mask Registers
    KSHIFTRB                Shift Right Mask Registers
    KSHIFTRD                Shift Right Mask Registers
    KSHIFTRQ                Shift Right Mask Registers
    KSHIFTRW                Shift Right Mask Registers
    KTESTB                Packed Bit Test Masks and Set Flags
    KTESTD                Packed Bit Test Masks and Set Flags
    KTESTQ                Packed Bit Test Masks and Set Flags
    KTESTW                Packed Bit Test Masks and Set Flags
    KUNPCKBW                Unpack for Mask Registers
    KUNPCKDQ                Unpack for Mask Registers
    KUNPCKWD                Unpack for Mask Registers
    KXNORB                Bitwise Logical XNOR Masks
    KXNORD                Bitwise Logical XNOR Masks
    KXNORQ                Bitwise Logical XNOR Masks
    KXNORW                Bitwise Logical XNOR Masks
    KXORB                Bitwise Logical XOR Masks
    KXORD                Bitwise Logical XOR Masks
    KXORQ                Bitwise Logical XOR Masks
    KXORW                Bitwise Logical XOR Masks
    LAHF                Load Status Flags into AH Register
    LAR                Load Access Rights Byte
    LDDQU                Load Unaligned Integer 128 Bits
    LDMXCSR                Load MXCSR Register
    LDS                Load Far Pointer
    LES                Load Far Pointer
    LFENCE                Load Fence
    LFS                Load Far Pointer
    LGDT                Load Global/Interrupt Descriptor Table Register
    LGS                Load Far Pointer
    LIDT                Load Global/Interrupt Descriptor Table Register
    LLDT                Load Local Descriptor Table Register
    LMSW                Load Machine Status Word
    LOCK                Assert LOCK# Signal Prefix
    LSL                Load Segment Limit
    LSS                Load Far Pointer
    LTR                Load Task Register
    LZCNT                Count the Number of Leading Zero Bits
    MASKMOVDQU                Store Selected Bytes of Double Quadword
    MASKMOVQ                Store Selected Bytes of Quadword
    MAXPD                Maximum of Packed Double-Precision Floating-Point Values
    MAXPS                Maximum of Packed Single-Precision Floating-Point Values
    MAXSD                Return Maximum Scalar Double-Precision Floating-Point Value
    MAXSS                Return Maximum Scalar Single-Precision Floating-Point Value
    MFENCE                Memory Fence
    MINPD                Minimum of Packed Double-Precision Floating-Point Values
    MINPS                Minimum of Packed Single-Precision Floating-Point Values
    MINSD                Return Minimum Scalar Double-Precision Floating-Point Value
    MINSS                Return Minimum Scalar Single-Precision Floating-Point Value
    MONITOR                Set Up Monitor Address
    MOV (1)                Move to/from Control Registers
    MOV (2)                Move to/from Debug Registers
    MOVAPD                Move Aligned Packed Double-Precision Floating-Point Values
    MOVAPS                Move Aligned Packed Single-Precision Floating-Point Values
    MOVBE                Move Data After Swapping Bytes
    MOVD                Move Doubleword/Move Quadword
    MOVDDUP                Replicate Double FP Values
    MOVDIR64B                Move 64 Bytes as Direct Store
    MOVDIRI                Move Doubleword as Direct Store
    MOVDQ2Q                Move Quadword from XMM to MMX Technology Register
    MOVDQA                Move Aligned Packed Integer Values
    MOVDQU                Move Unaligned Packed Integer Values
    MOVHLPS                Move Packed Single-Precision Floating-Point Values High to Low
    MOVHPD                Move High Packed Double-Precision Floating-Point Value
    MOVHPS                Move High Packed Single-Precision Floating-Point Values
    MOVLHPS                Move Packed Single-Precision Floating-Point Values Low to High
    MOVLPD                Move Low Packed Double-Precision Floating-Point Value
    MOVLPS                Move Low Packed Single-Precision Floating-Point Values
    MOVMSKPD                Extract Packed Double-Precision Floating-Point Sign Mask
    MOVMSKPS                Extract Packed Single-Precision Floating-Point Sign Mask
    MOVNTDQ                Store Packed Integers Using Non-Temporal Hint
    MOVNTDQA                Load Double Quadword Non-Temporal Aligned Hint
    MOVNTI                Store Doubleword Using Non-Temporal Hint
    MOVNTPD                Store Packed Double-Precision Floating-Point Values Using Non-Temporal Hint
    MOVNTPS                Store Packed Single-Precision Floating-Point Values Using Non-Temporal Hint
    MOVNTQ                Store of Quadword Using Non-Temporal Hint
    MOVQ                Move Doubleword/Move Quadword
    MOVQ (1)                Move Quadword
    MOVQ2DQ                Move Quadword from MMX Technology to XMM Register
    MOVS                Move Data from String to String
    MOVSD (1)                Move or Merge Scalar Double-Precision Floating-Point Value
    MOVSHDUP                Replicate Single FP Values
    MOVSLDUP                Replicate Single FP Values
    MOVSS                Move or Merge Scalar Single-Precision Floating-Point Value
    MOVUPD                Move Unaligned Packed Double-Precision Floating-Point Values
    MOVUPS                Move Unaligned Packed Single-Precision Floating-Point Values
    MPSADBW                Compute Multiple Packed Sums of Absolute Difference
    MULPD                Multiply Packed Double-Precision Floating-Point Values
    MULPS                Multiply Packed Single-Precision Floating-Point Values
    MULSD                Multiply Scalar Double-Precision Floating-Point Value
    MULSS                Multiply Scalar Single-Precision Floating-Point Values
    
    MWAIT                Monitor Wait
    ORPD                Bitwise Logical OR of Packed Double Precision Floating-Point Values
    ORPS                Bitwise Logical OR of Packed Single Precision Floating-Point Values
    OUT                Output to Port
    OUTS                Output String to Port
    OUTSB                Output String to Port
    OUTSD                Output String to Port
    OUTSW                Output String to Port
    PABSB                Packed Absolute Value
    PABSD                Packed Absolute Value
    PABSQ                Packed Absolute Value
    PABSW                Packed Absolute Value
    PACKSSDW                Pack with Signed Saturation
    PACKSSWB                Pack with Signed Saturation
    PACKUSDW                Pack with Unsigned Saturation
    PACKUSWB                Pack with Unsigned Saturation
    PADDB                Add Packed Integers
    PADDD                Add Packed Integers
    PADDQ                Add Packed Integers
    PADDSB                Add Packed Signed Integers with Signed Saturation
    PADDSW                Add Packed Signed Integers with Signed Saturation
    PADDUSB                Add Packed Unsigned Integers with Unsigned Saturation
    PADDUSW                Add Packed Unsigned Integers with Unsigned Saturation
    PADDW                Add Packed Integers
    PALIGNR                Packed Align Right
    
    
    
    PAVGB                Average Packed Integers
    PAVGW                Average Packed Integers
    PBLENDVB                Variable Blend Packed Bytes
    PBLENDW                Blend Packed Words
    PCLMULQDQ                Carry-Less Multiplication Quadword
    PCMPEQB                Compare Packed Data for Equal
    PCMPEQD                Compare Packed Data for Equal
    PCMPEQQ                Compare Packed Qword Data for Equal
    PCMPEQW                Compare Packed Data for Equal
    PCMPESTRI                Packed Compare Explicit Length Strings, Return Index
    PCMPESTRM                Packed Compare Explicit Length Strings, Return Mask
    PCMPGTB                Compare Packed Signed Integers for Greater Than
    PCMPGTD                Compare Packed Signed Integers for Greater Than
    PCMPGTQ                Compare Packed Data for Greater Than
    PCMPGTW                Compare Packed Signed Integers for Greater Than
    PCMPISTRI                Packed Compare Implicit Length Strings, Return Index
    PCMPISTRM                Packed Compare Implicit Length Strings, Return Mask
    PDEP                Parallel Bits Deposit
    PEXT                Parallel Bits Extract
    PEXTRB                Extract Byte/Dword/Qword
    PEXTRD                Extract Byte/Dword/Qword
    PEXTRQ                Extract Byte/Dword/Qword
    PEXTRW                Extract Word
    PHADDD                Packed Horizontal Add
    PHADDSW                Packed Horizontal Add and Saturate
    PHADDW                Packed Horizontal Add
    PHMINPOSUW                Packed Horizontal Word Minimum
    PHSUBD                Packed Horizontal Subtract
    PHSUBSW                Packed Horizontal Subtract and Saturate
    PHSUBW                Packed Horizontal Subtract
    PINSRB                Insert Byte/Dword/Qword
    PINSRD                Insert Byte/Dword/Qword
    PINSRQ                Insert Byte/Dword/Qword
    PINSRW                Insert Word
    PMADDUBSW                Multiply and Add Packed Signed and Unsigned Bytes
    PMADDWD                Multiply and Add Packed Integers
    PMAXSB                Maximum of Packed Signed Integers
    PMAXSD                Maximum of Packed Signed Integers
    PMAXSQ                Maximum of Packed Signed Integers
    PMAXSW                Maximum of Packed Signed Integers
    PMAXUB                Maximum of Packed Unsigned Integers
    PMAXUD                Maximum of Packed Unsigned Integers
    PMAXUQ                Maximum of Packed Unsigned Integers
    PMAXUW                Maximum of Packed Unsigned Integers
    PMINSB                Minimum of Packed Signed Integers
    PMINSD                Minimum of Packed Signed Integers
    PMINSQ                Minimum of Packed Signed Integers
    PMINSW                Minimum of Packed Signed Integers
    PMINUB                Minimum of Packed Unsigned Integers
    PMINUD                Minimum of Packed Unsigned Integers
    PMINUQ                Minimum of Packed Unsigned Integers
    PMINUW                Minimum of Packed Unsigned Integers
    PMOVMSKB                Move Byte Mask
    PMOVSX                Packed Move with Sign Extend
    PMOVZX                Packed Move with Zero Extend
    PMULDQ                Multiply Packed Doubleword Integers
    PMULHRSW                Packed Multiply High with Round and Scale
    PMULHUW                Multiply Packed Unsigned Integers and Store High Result
    PMULHW                Multiply Packed Signed Integers and Store High Result
    PMULLD                Multiply Packed Integers and Store Low Result
    PMULLQ                Multiply Packed Integers and Store Low Result
    PMULLW                Multiply Packed Signed Integers and Store Low Result
    PMULUDQ                Multiply Packed Unsigned Doubleword Integers
    POR                Bitwise Logical OR
    PREFETCHW                Prefetch Data into Caches in Anticipation of a Write
    PREFETCHh                Prefetch Data Into Caches
    PSADBW                Compute Sum of Absolute Differences
    PSHUFB                Packed Shuffle Bytes
    PSHUFD                Shuffle Packed Doublewords
    PSHUFHW                Shuffle Packed High Words
    PSHUFLW                Shuffle Packed Low Words
    PSHUFW                Shuffle Packed Words
    PSIGNB                Packed SIGN
    PSIGND                Packed SIGN
    PSIGNW                Packed SIGN
    PSLLD                Shift Packed Data Left Logical
    PSLLDQ                Shift Double Quadword Left Logical
    PSLLQ                Shift Packed Data Left Logical
    PSLLW                Shift Packed Data Left Logical
    PSRAD                Shift Packed Data Right Arithmetic
    PSRAQ                Shift Packed Data Right Arithmetic
    PSRAW                Shift Packed Data Right Arithmetic
    PSRLD                Shift Packed Data Right Logical
    PSRLDQ                Shift Double Quadword Right Logical
    PSRLQ                Shift Packed Data Right Logical
    PSRLW                Shift Packed Data Right Logical
    PSUBB                Subtract Packed Integers
    PSUBD                Subtract Packed Integers
    PSUBQ                Subtract Packed Quadword Integers
    PSUBSB                Subtract Packed Signed Integers with Signed Saturation
    PSUBSW                Subtract Packed Signed Integers with Signed Saturation
    PSUBUSB                Subtract Packed Unsigned Integers with Unsigned Saturation
    PSUBUSW                Subtract Packed Unsigned Integers with Unsigned Saturation
    PSUBW                Subtract Packed Integers
    PTEST                Logical Compare
    PTWRITE                Write Data to a Processor Trace Packet
    PUNPCKHBW                Unpack High Data
    PUNPCKHDQ                Unpack High Data
    PUNPCKHQDQ                Unpack High Data
    PUNPCKHWD                Unpack High Data
    PUNPCKLBW                Unpack Low Data
    PUNPCKLDQ                Unpack Low Data
    PUNPCKLQDQ                Unpack Low Data
    PUNPCKLWD                Unpack Low Data
    
    RCPPS                Compute Reciprocals of Packed Single-Precision Floating-Point Values
    RCPSS                Compute Reciprocal of Scalar Single-Precision Floating-Point Values
    ROUNDPD                Round Packed Double Precision Floating-Point Values
    ROUNDPS                Round Packed Single Precision Floating-Point Values
    ROUNDSD                Round Scalar Double Precision Floating-Point Values
    ROUNDSS                Round Scalar Single Precision Floating-Point Values
    RSM                Resume from System Management Mode
    RSQRTPS                Compute Reciprocals of Square Roots of Packed Single-Precision Floating-Point Values
    RSQRTSS                Compute Reciprocal of Square Root of Scalar Single-Precision Floating-Point Value
    
    SFENCE                Store Fence
    SGDT                Store Global Descriptor Table Register
    SHA1MSG1                Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords
    SHA1MSG2                Perform a Final Calculation for the Next Four SHA1 Message Dwords
    SHA1NEXTE                Calculate SHA1 State Variable E after Four Rounds
    SHA1RNDS4                Perform Four Rounds of SHA1 Operation
    SHA256MSG1                Perform an Intermediate Calculation for the Next Four SHA256 Message Dwords
    SHA256MSG2                Perform a Final Calculation for the Next Four SHA256 Message Dwords
    SHA256RNDS2                Perform Two Rounds of SHA256 Operation
    SHLD                Double Precision Shift Left
    SHUFPD                Packed Interleave Shuffle of Pairs of Double-Precision Floating-Point Values
    SHUFPS                Packed Interleave Shuffle of Quadruplets of Single-Precision Floating-Point Values
    SIDT                Store Interrupt Descriptor Table Register
    SLDT                Store Local Descriptor Table Register
    SMSW                Store Machine Status Word
    SQRTPD                Square Root of Double-Precision Floating-Point Values
    SQRTPS                Square Root of Single-Precision Floating-Point Values
    SQRTSD                Compute Square Root of Scalar Double-Precision Floating-Point Value
    SQRTSS                Compute Square Root of Scalar Single-Precision Value
    STMXCSR                Store MXCSR Register State
    SUBPD                Subtract Packed Double-Precision Floating-Point Values
    SUBPS                Subtract Packed Single-Precision Floating-Point Values
    SUBSD                Subtract Scalar Double-Precision Floating-Point Value
    SUBSS                Subtract Scalar Single-Precision Floating-Point Value
    SWAPGS                Swap GS Base Register
    UCOMISD                Unordered Compare Scalar Double-Precision Floating-Point Values and Set EFLAGS
    UCOMISS                Unordered Compare Scalar Single-Precision Floating-Point Values and Set EFLAGS
    UNPCKHPD                Unpack and Interleave High Packed Double-Precision Floating-Point Values
    UNPCKHPS                Unpack and Interleave High Packed Single-Precision Floating-Point Values
    UNPCKLPD                Unpack and Interleave Low Packed Double-Precision Floating-Point Values
    UNPCKLPS                Unpack and Interleave Low Packed Single-Precision Floating-Point Values
    VALIGND                Align Doubleword/Quadword Vectors
    VALIGNQ                Align Doubleword/Quadword Vectors
    VBLENDMPD                Blend Float64/Float32 Vectors Using an OpMask Control
    VBLENDMPS                Blend Float64/Float32 Vectors Using an OpMask Control
    VBROADCAST                Load with Broadcast Floating-Point Data
    VCOMPRESSPD                Store Sparse Packed Double-Precision Floating-Point Values into Dense Memory
    VCOMPRESSPS                Store Sparse Packed Single-Precision Floating-Point Values into Dense Memory
    VCVTPD2QQ                Convert Packed Double-Precision Floating-Point Values to Packed Quadword Integers
    VCVTPD2UDQ                Convert Packed Double-Precision Floating-Point Values to Packed Unsigned Doubleword Integers
    VCVTPD2UQQ                Convert Packed Double-Precision Floating-Point Values to Packed Unsigned Quadword Integers
    VCVTPH2PS                Convert 16-bit FP values to Single-Precision FP values
    VCVTPS2PH                Convert Single-Precision FP value to 16-bit FP value
    VCVTPS2QQ                Convert Packed Single Precision Floating-Point Values to Packed Singed Quadword Integer Values
    VCVTPS2UDQ                Convert Packed Single-Precision Floating-Point Values to Packed Unsigned Doubleword Integer Values
    VCVTPS2UQQ                Convert Packed Single Precision Floating-Point Values to Packed Unsigned Quadword Integer Values
    VCVTQQ2PD                Convert Packed Quadword Integers to Packed Double-Precision Floating-Point Values
    VCVTQQ2PS                Convert Packed Quadword Integers to Packed Single-Precision Floating-Point Values
    VCVTSD2USI                Convert Scalar Double-Precision Floating-Point Value to Unsigned Doubleword Integer
    VCVTSS2USI                Convert Scalar Single-Precision Floating-Point Value to Unsigned Doubleword Integer
    VCVTTPD2QQ                Convert with Truncation Packed Double-Precision Floating-Point Values to Packed Quadword Integers
    VCVTTPD2UDQ                Convert with Truncation Packed Double-Precision Floating-Point Values to Packed Unsigned Doubleword Integers
    VCVTTPD2UQQ                Convert with Truncation Packed Double-Precision Floating-Point Values to Packed Unsigned Quadword Integers
    VCVTTPS2QQ                Convert with Truncation Packed Single Precision Floating-Point Values to Packed Singed Quadword Integer Values
    VCVTTPS2UDQ                Convert with Truncation Packed Single-Precision Floating-Point Values to Packed Unsigned Doubleword Integer Values
    VCVTTPS2UQQ                Convert with Truncation Packed Single Precision Floating-Point Values to Packed Unsigned Quadword Integer Values
    VCVTTSD2USI                Convert with Truncation Scalar Double-Precision Floating-Point Value to Unsigned Integer
    VCVTTSS2USI                Convert with Truncation Scalar Single-Precision Floating-Point Value to Unsigned Integer
    VCVTUDQ2PD                Convert Packed Unsigned Doubleword Integers to Packed Double-Precision Floating-Point Values
    VCVTUDQ2PS                Convert Packed Unsigned Doubleword Integers to Packed Single-Precision Floating-Point Values
    VCVTUQQ2PD                Convert Packed Unsigned Quadword Integers to Packed Double-Precision Floating-Point Values
    VCVTUQQ2PS                Convert Packed Unsigned Quadword Integers to Packed Single-Precision Floating-Point Values
    VCVTUSI2SD                Convert Unsigned Integer to Scalar Double-Precision Floating-Point Value
    VCVTUSI2SS                Convert Unsigned Integer to Scalar Single-Precision Floating-Point Value
    VDBPSADBW                Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes
    
    VEXPANDPD                Load Sparse Packed Double-Precision Floating-Point Values from Dense Memory
    VEXPANDPS                Load Sparse Packed Single-Precision Floating-Point Values from Dense Memory
    VEXTRACTF128                Extra ct Packed Floating-Point Values
    VEXTRACTF32x4                Extra ct Packed Floating-Point Values
    VEXTRACTF32x8                Extra ct Packed Floating-Point Values
    VEXTRACTF64x2                Extra ct Packed Floating-Point Values
    VEXTRACTF64x4                Extra ct Packed Floating-Point Values
    VEXTRACTI128                Extract packed Integer Values
    VEXTRACTI32x4                Extract packed Integer Values
    VEXTRACTI32x8                Extract packed Integer Values
    VEXTRACTI64x2                Extract packed Integer Values
    VEXTRACTI64x4                Extract packed Integer Values
    VFIXUPIMMPD                Fix Up Special Packed Float64 Values
    VFIXUPIMMPS                Fix Up Special Packed Float32 Values
    VFIXUPIMMSD                Fix Up Special Scalar Float64 Value
    VFIXUPIMMSS                Fix Up Special Scalar Float32 Value
    VFMADD132PD                Fused Multiply-Add of Packed Double- Precision Floating-Point Values
    VFMADD132PS                Fused Multiply-Add of Packed Single- Precision Floating-Point Values
    VFMADD132SD                Fused Multiply-Add of Scalar Double- Precision Floating-Point Values
    VFMADD132SS                Fused Multiply-Add of Scalar Single-Precision Floating-Point Values
    VFMADD213PD                Fused Multiply-Add of Packed Double- Precision Floating-Point Values
    VFMADD213PS                Fused Multiply-Add of Packed Single- Precision Floating-Point Values
    VFMADD213SD                Fused Multiply-Add of Scalar Double- Precision Floating-Point Values
    VFMADD213SS                Fused Multiply-Add of Scalar Single-Precision Floating-Point Values
    VFMADD231PD                Fused Multiply-Add of Packed Double- Precision Floating-Point Values
    VFMADD231PS                Fused Multiply-Add of Packed Single- Precision Floating-Point Values
    VFMADD231SD                Fused Multiply-Add of Scalar Double- Precision Floating-Point Values
    VFMADD231SS                Fused Multiply-Add of Scalar Single-Precision Floating-Point Values
    VFMADDSUB132PD                Fused Multiply-Alternating Add/Subtract of Packed Double-Precision Floating-Point Values
    VFMADDSUB132PS                Fused Multiply-Alternating Add/Subtract of Packed Single-Precision Floating-Point Values
    VFMADDSUB213PD                Fused Multiply-Alternating Add/Subtract of Packed Double-Precision Floating-Point Values
    VFMADDSUB213PS                Fused Multiply-Alternating Add/Subtract of Packed Single-Precision Floating-Point Values
    VFMADDSUB231PD                Fused Multiply-Alternating Add/Subtract of Packed Double-Precision Floating-Point Values
    VFMADDSUB231PS                Fused Multiply-Alternating Add/Subtract of Packed Single-Precision Floating-Point Values
    VFMSUB132PD                Fused Multiply-Subtract of Packed Double- Precision Floating-Point Values
    VFMSUB132PS                Fused Multiply-Subtract of Packed Single- Precision Floating-Point Values
    VFMSUB132SD                Fused Multiply-Subtract of Scalar Double- Precision Floating-Point Values
    VFMSUB132SS                Fused Multiply-Subtract of Scalar Single- Precision Floating-Point Values
    VFMSUB213PD                Fused Multiply-Subtract of Packed Double- Precision Floating-Point Values
    VFMSUB213PS                Fused Multiply-Subtract of Packed Single- Precision Floating-Point Values
    VFMSUB213SD                Fused Multiply-Subtract of Scalar Double- Precision Floating-Point Values
    VFMSUB213SS                Fused Multiply-Subtract of Scalar Single- Precision Floating-Point Values
    VFMSUB231PD                Fused Multiply-Subtract of Packed Double- Precision Floating-Point Values
    VFMSUB231PS                Fused Multiply-Subtract of Packed Single- Precision Floating-Point Values
    VFMSUB231SD                Fused Multiply-Subtract of Scalar Double- Precision Floating-Point Values
    VFMSUB231SS                Fused Multiply-Subtract of Scalar Single- Precision Floating-Point Values
    VFMSUBADD132PD                Fused Multiply-Alternating Subtract/Add of Packed Double-Precision Floating-Point Values
    VFMSUBADD132PS                Fused Multiply-Alternating Subtract/Add of Packed Single-Precision Floating-Point Values
    VFMSUBADD213PD                Fused Multiply-Alternating Subtract/Add of Packed Double-Precision Floating-Point Values
    VFMSUBADD213PS                Fused Multiply-Alternating Subtract/Add of Packed Single-Precision Floating-Point Values
    VFMSUBADD231PD                Fused Multiply-Alternating Subtract/Add of Packed Double-Precision Floating-Point Values
    VFMSUBADD231PS                Fused Multiply-Alternating Subtract/Add of Packed Single-Precision Floating-Point Values
    VFNMADD132PD                Fused Negative Multiply-Add of Packed Double-Precision Floating-Point Values
    VFNMADD132PS                Fused Negative Multiply-Add of Packed Single-Precision Floating-Point Values
    VFNMADD132SD                Fused Negative Multiply-Add of Scalar Double-Precision Floating-Point Values
    VFNMADD132SS                Fused Negative Multiply-Add of Scalar Single-Precision Floating-Point Values
    VFNMADD213PD                Fused Negative Multiply-Add of Packed Double-Precision Floating-Point Values
    VFNMADD213PS                Fused Negative Multiply-Add of Packed Single-Precision Floating-Point Values
    VFNMADD213SD                Fused Negative Multiply-Add of Scalar Double-Precision Floating-Point Values
    VFNMADD213SS                Fused Negative Multiply-Add of Scalar Single-Precision Floating-Point Values
    VFNMADD231PD                Fused Negative Multiply-Add of Packed Double-Precision Floating-Point Values
    VFNMADD231PS                Fused Negative Multiply-Add of Packed Single-Precision Floating-Point Values
    VFNMADD231SD                Fused Negative Multiply-Add of Scalar Double-Precision Floating-Point Values
    VFNMADD231SS                Fused Negative Multiply-Add of Scalar Single-Precision Floating-Point Values
    VFNMSUB132PD                Fused Negative Multiply-Subtract of Packed Double-Precision Floating-Point Values
    VFNMSUB132PS                Fused Negative Multiply-Subtract of Packed Single-Precision Floating-Point Values
    VFNMSUB132SD                Fused Negative Multiply-Subtract of Scalar Double-Precision Floating-Point Values
    VFNMSUB132SS                Fused Negative Multiply-Subtract of Scalar Single-Precision Floating-Point Values
    VFNMSUB213PD                Fused Negative Multiply-Subtract of Packed Double-Precision Floating-Point Values
    VFNMSUB213PS                Fused Negative Multiply-Subtract of Packed Single-Precision Floating-Point Values
    VFNMSUB213SD                Fused Negative Multiply-Subtract of Scalar Double-Precision Floating-Point Values
    VFNMSUB213SS                Fused Negative Multiply-Subtract of Scalar Single-Precision Floating-Point Values
    VFNMSUB231PD                Fused Negative Multiply-Subtract of Packed Double-Precision Floating-Point Values
    VFNMSUB231PS                Fused Negative Multiply-Subtract of Packed Single-Precision Floating-Point Values
    VFNMSUB231SD                Fused Negative Multiply-Subtract of Scalar Double-Precision Floating-Point Values
    VFNMSUB231SS                Fused Negative Multiply-Subtract of Scalar Single-Precision Floating-Point Values
    VFPCLASSPD                Tests Types Of a Packed Float64 Values
    VFPCLASSPS                Tests Types Of a Packed Float32 Values
    VFPCLASSSD                Tests Types Of a Scalar Float64 Values
    VFPCLASSSS                Tests Types Of a Scalar Float32 Values
    VGATHERDPD                Gather Packed DP FP Values Using Signed Dword/Qword Indices
    VGATHERDPD (1)                Gather Packed Single, Packed Double with Signed Dword
    VGATHERDPS                Gather Packed SP FP values Using Signed Dword/Qword Indices
    VGATHERDPS (1)                Gather Packed Single, Packed Double with Signed Dword
    VGATHERQPD                Gather Packed DP FP Values Using Signed Dword/Qword Indices
    VGATHERQPD (1)                Gather Packed Single, Packed Double with Signed Qword Indices
    VGATHERQPS                Gather Packed SP FP values Using Signed Dword/Qword Indices
    VGATHERQPS (1)                Gather Packed Single, Packed Double with Signed Qword Indices
    VGETEXPPD                Convert Exponents of Packed DP FP Values to DP FP Values
    VGETEXPPS                Convert Exponents of Packed SP FP Values to SP FP Values
    VGETEXPSD                Convert Exponents of Scalar DP FP Values to DP FP Value
    VGETEXPSS                Convert Exponents of Scalar SP FP Values to SP FP Value
    VGETMANTPD                Extract Float64 Vector of Normalized Mantissas from Float64 Vector
    VGETMANTPS                Extract Float32 Vector of Normalized Mantissas from Float32 Vector
    VGETMANTSD                Extract Float64 of Normalized Mantissas from Float64 Scalar
    VGETMANTSS                Extract Float32 Vector of Normalized Mantissa from Float32 Vector
    VINSERTF128                Insert Packed Floating-Point Values
    VINSERTF32x4                Insert Packed Floating-Point Values
    VINSERTF32x8                Insert Packed Floating-Point Values
    VINSERTF64x2                Insert Packed Floating-Point Values
    VINSERTF64x4                Insert Packed Floating-Point Values
    VINSERTI128                Insert Packed Integer Values
    VINSERTI32x4                Insert Packed Integer Values
    VINSERTI32x8                Insert Packed Integer Values
    VINSERTI64x2                Insert Packed Integer Values
    VINSERTI64x4                Insert Packed Integer Values
    VMASKMOV                Conditional SIMD Packed Loads and Stores
    VMOVDQA32                Move Aligned Packed Integer Values
    VMOVDQA64                Move Aligned Packed Integer Values
    VMOVDQU16                Move Unaligned Packed Integer Values
    VMOVDQU32                Move Unaligned Packed Integer Values
    VMOVDQU64                Move Unaligned Packed Integer Values
    VMOVDQU8                Move Unaligned Packed Integer Values
    VPBLENDD                Blend Packed Dwords
    VPBLENDMB                Blend Byte/Word Vectors Using an Opmask Control
    VPBLENDMD                Blend Int32/Int64 Vectors Using an OpMask Control
    VPBLENDMQ                Blend Int32/Int64 Vectors Using an OpMask Control
    VPBLENDMW                Blend Byte/Word Vectors Using an Opmask Control
    VPBROADCAST                Load Integer and Broadcast
    VPBROADCASTB                Load with Broadcast Integer Data from General Purpose Register
    VPBROADCASTD                Load with Broadcast Integer Data from General Purpose Register
    VPBROADCASTM                Broadcast Mask to Vector Register
    VPBROADCASTQ                Load with Broadcast Integer Data from General Purpose Register
    VPBROADCASTW                Load with Broadcast Integer Data from General Purpose Register
    VPCMPB                Compare Packed Byte Values Into Mask
    VPCMPD                Compare Packed Integer Values into Mask
    VPCMPQ                Compare Packed Integer Values into Mask
    VPCMPUB                Compare Packed Byte Values Into Mask
    VPCMPUD                Compare Packed Integer Values into Mask
    VPCMPUQ                Compare Packed Integer Values into Mask
    VPCMPUW                Compare Packed Word Values Into Mask
    VPCMPW                Compare Packed Word Values Into Mask
    VPCOMPRESSD                Store Sparse Packed Doubleword Integer Values into Dense Memory/Register
    VPCOMPRESSQ                Store Sparse Packed Quadword Integer Values into Dense Memory/Register
    VPCONFLICTD                Detect Conflicts Within a Vector of Packed Dword/Qword Values into Dense Memory/ Register
    VPCONFLICTQ                Detect Conflicts Within a Vector of Packed Dword/Qword Values into Dense Memory/ Register
    VPERM2F128                Permute Floating-Point Values
    VPERM2I128                Permute Integer Values
    VPERMB                Permute Packed Bytes Elements
    VPERMD                Permute Packed Doublewords/Words Elements
    VPERMI2B                Full Permute of Bytes from Two Tables Overwriting the Index
    VPERMI2D                Full Permute From Two Tables Overwriting the Index
    VPERMI2PD                Full Permute From Two Tables Overwriting the Index
    VPERMI2PS                Full Permute From Two Tables Overwriting the Index
    VPERMI2Q                Full Permute From Two Tables Overwriting the Index
    VPERMI2W                Full Permute From Two Tables Overwriting the Index
    VPERMILPD                Permute In-Lane of Pairs of Double-Precision Floating-Point Values
    VPERMILPS                Permute In-Lane of Quadruples of Single-Precision Floating-Point Values
    VPERMPD                Permute Double-Precision Floating-Point Elements
    VPERMPS                Permute Single-Precision Floating-Point Elements
    VPERMQ                Qwords Element Permutation
    VPERMT2B                Full Permute of Bytes from Two Tables Overwriting a Table
    VPERMT2D                Full Permute from Two Tables Overwriting one Table
    VPERMT2PD                Full Permute from Two Tables Overwriting one Table
    VPERMT2PS                Full Permute from Two Tables Overwriting one Table
    VPERMT2Q                Full Permute from Two Tables Overwriting one Table
    VPERMT2W                Full Permute from Two Tables Overwriting one Table
    VPERMW                Permute Packed Doublewords/Words Elements
    VPEXPANDD                Load Sparse Packed Doubleword Integer Values from Dense Memory / Register
    VPEXPANDQ                Load Sparse Packed Quadword Integer Values from Dense Memory / Register
    VPGATHERDD                Gather Packed Dword Values Using Signed Dword/Qword Indices
    VPGATHERDD (1)                Gather Packed Dword, Packed Qword with Signed Dword Indices
    VPGATHERDQ                Gather Packed Dword, Packed Qword with Signed Dword Indices
    VPGATHERDQ (1)                Gather Packed Qword Values Using Signed Dword/Qword Indices
    VPGATHERQD                Gather Packed Dword Values Using Signed Dword/Qword Indices
    VPGATHERQD (1)                Gather Packed Dword, Packed Qword with Signed Qword Indices
    VPGATHERQQ                Gather Packed Qword Values Using Signed Dword/Qword Indices
    VPGATHERQQ (1)                Gather Packed Dword, Packed Qword with Signed Qword Indices
    VPLZCNTD                Count the Number of Leading Zero Bits for Packed Dword, Packed Qword Values
    VPLZCNTQ                Count the Number of Leading Zero Bits for Packed Dword, Packed Qword Values
    VPMADD52HUQ                Packed Multiply of Unsigned 52-bit Unsigned Integers and Add High 52-bit Products to 64-bit Accumulators
    VPMADD52LUQ                Packed Multiply of Unsigned 52-bit Integers and Add the Low 52-bit Products to Qword Accumulators
    VPMASKMOV                Conditional SIMD Integer Packed Loads and Stores
    VPMOVB2M                Convert a Vector Register to a Mask
    VPMOVD2M                Convert a Vector Register to a Mask
    VPMOVDB                Down Convert DWord to Byte
    VPMOVDW                Down Convert DWord to Word
    VPMOVM2B                Convert a Mask Register to a Vector Register
    VPMOVM2D                Convert a Mask Register to a Vector Register
    VPMOVM2Q                Convert a Mask Register to a Vector Register
    VPMOVM2W                Convert a Mask Register to a Vector Register
    VPMOVQ2M                Convert a Vector Register to a Mask
    VPMOVQB                Down Convert QWord to Byte
    VPMOVQD                Down Convert QWord to DWord
    VPMOVQW                Down Convert QWord to Word
    VPMOVSDB                Down Convert DWord to Byte
    VPMOVSDW                Down Convert DWord to Word
    VPMOVSQB                Down Convert QWord to Byte
    VPMOVSQD                Down Convert QWord to DWord
    VPMOVSQW                Down Convert QWord to Word
    VPMOVSWB                Down Convert Word to Byte
    VPMOVUSDB                Down Convert DWord to Byte
    VPMOVUSDW                Down Convert DWord to Word
    VPMOVUSQB                Down Convert QWord to Byte
    VPMOVUSQD                Down Convert QWord to DWord
    VPMOVUSQW                Down Convert QWord to Word
    VPMOVUSWB                Down Convert Word to Byte
    VPMOVW2M                Convert a Vector Register to a Mask
    VPMOVWB                Down Convert Word to Byte
    VPMULTISHIFTQB                Select Packed Unaligned Bytes from Quadword Sources
    VPROLD                Bit Rotate Left
    VPROLQ                Bit Rotate Left
    VPROLVD                Bit Rotate Left
    VPROLVQ                Bit Rotate Left
    VPRORD                Bit Rotate Right
    VPRORQ                Bit Rotate Right
    VPRORVD                Bit Rotate Right
    VPRORVQ                Bit Rotate Right
    VPSCATTERDD                Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword Indices
    VPSCATTERDQ                Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword Indices
    VPSCATTERQD                Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword Indices
    VPSCATTERQQ                Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword Indices
    VPSLLVD                Variable Bit Shift Left Logical
    VPSLLVQ                Variable Bit Shift Left Logical
    VPSLLVW                Variable Bit Shift Left Logical
    VPSRAVD                Variable Bit Shift Right Arithmetic
    VPSRAVQ                Variable Bit Shift Right Arithmetic
    VPSRAVW                Variable Bit Shift Right Arithmetic
    VPSRLVD                Variable Bit Shift Right Logical
    VPSRLVQ                Variable Bit Shift Right Logical
    VPSRLVW                Variable Bit Shift Right Logical
    VPTERNLOGD                Bitwise Ternary Logic
    VPTERNLOGQ                Bitwise Ternary Logic
    VPTESTMB                Logical AND and Set Mask
    VPTESTMD                Logical AND and Set Mask
    VPTESTMQ                Logical AND and Set Mask
    VPTESTMW                Logical AND and Set Mask
    VPTESTNMB                Logical NAND and Set
    VPTESTNMD                Logical NAND and Set
    VPTESTNMQ                Logical NAND and Set
    VPTESTNMW                Logical NAND and Set
    VRANGEPD                Range Restriction Calculation For Packed Pairs of Float64 Values
    VRANGEPS                Range Restriction Calculation For Packed Pairs of Float32 Values
    VRANGESD                Range Restriction Calculation From a pair of Scalar Float64 Values
    VRANGESS                Range Restriction Calculation From a Pair of Scalar Float32 Values
    VRCP14PD                Compute Approximate Reciprocals of Packed Float64 Values
    VRCP14PS                Compute Approximate Reciprocals of Packed Float32 Values
    VRCP14SD                Compute Approximate Reciprocal of Scalar Float64 Value
    VRCP14SS                Compute Approximate Reciprocal of Scalar Float32 Value
    VREDUCEPD                Perform Reduction Transformation on Packed Float64 Values
    VREDUCEPS                Perform Reduction Transformation on Packed Float32 Values
    VREDUCESD                Perform a Reduction Transformation on a Scalar Float64 Value
    VREDUCESS                Perform a Reduction Transformation on a Scalar Float32 Value
    VRNDSCALEPD                Round Packed Float64 Values To Include A Given Number Of Fraction Bits
    VRNDSCALEPS                Round Packed Float32 Values To Include A Given Number Of Fraction Bits
    VRNDSCALESD                Round Scalar Float64 Value To Include A Given Number Of Fraction Bits
    VRNDSCALESS                Round Scalar Float32 Value To Include A Given Number Of Fraction Bits
    VRSQRT14PD                Compute Approximate Reciprocals of Square Roots of Packed Float64 Values
    VRSQRT14PS                Compute Approximate Reciprocals of Square Roots of Packed Float32 Values
    VRSQRT14SD                Compute Approximate Reciprocal of Square Root of Scalar Float64 Value
    VRSQRT14SS                Compute Approximate Reciprocal of Square Root of Scalar Float32 Value
    VSCALEFPD                Scale Packed Float64 Values With Float64 Values
    VSCALEFPS                Scale Packed Float32 Values With Float32 Values
    VSCALEFSD                Scale Scalar Float64 Values With Float64 Values
    VSCALEFSS                Scale Scalar Float32 Value With Float32 Value
    VSCATTERDPD                Scatter Packed Single, Packed Double with Signed Dword and Qword Indices
    VSCATTERDPS                Scatter Packed Single, Packed Double with Signed Dword and Qword Indices
    VSCATTERQPD                Scatter Packed Single, Packed Double with Signed Dword and Qword Indices
    VSCATTERQPS                Scatter Packed Single, Packed Double with Signed Dword and Qword Indices
    VSHUFF32x4                Shuffle Packed Values at 128-bit Granularity
    VSHUFF64x2                Shuffle Packed Values at 128-bit Granularity
    VSHUFI32x4                Shuffle Packed Values at 128-bit Granularity
    VSHUFI64x2                Shuffle Packed Values at 128-bit Granularity
    VTESTPD                Packed Bit Test
    VTESTPS                Packed Bit Test
    VZEROALL                Zero All YMM Registers
    VZEROUPPER                Zero Upper Bits of YMM Registers
    WBINVD                Write Back and Invalidate Cache
    WRFSBASE                Write FS/GS Segment Base
    WRGSBASE                Write FS/GS Segment Base
    WRMSR                Write to Model Specific Register
    WRPKRU                Write Data to User Page Key Register
    XABORT                Transactional Abort
    XACQUIRE                Hardware Lock Elision Prefix Hints
    XBEGIN                Transactional Begin
    XEND                Transactional End
    XGETBV                Get Value of Extended Control Register
    XLAT                Table Look-up Translation
    XLATB                Table Look-up Translation
    XORPD                Bitwise Logical XOR of Packed Double Precision Floating-Point Values
    XORPS                Bitwise Logical XOR of Packed Single Precision Floating-Point Values
    XRELEASE                Hardware Lock Elision Prefix Hints
    XRSTOR                Restore Processor Extended States
    XRSTORS                Restore Processor Extended States Supervisor
    XSAVE                Save Processor Extended States
    XSAVEC                Save Processor Extended States with Compaction
    XSAVEOPT                Save Processor Extended States Optimized
    XSAVES                Save Processor Extended States Supervisor
    XSETBV                Set Extended Control Register
    XTEST                Test If In Transactional Execution



*/
