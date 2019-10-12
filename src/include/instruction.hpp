#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include <vector>

/* Type aliasing */
typedef unsigned int IRVar;

#include "expression.hpp"
#include "memory.hpp"

/* IR Operations 
 ===============
Maat IR supports basic arithmetic and logical operations, 
store/load operations, and register 'mov'  
It also has two branchment instructions:
 - BCC : conditionnal jump to an IRBasicBlock
 - JCC : conditionnal jump to an IRBlock
And two special instructions: INT and SYSCALL
  - they are handled not directly but the symbolic engine
    but by the EnvManager */

enum class IROperation{
    /* Arithmetic and logical operations */
    ADD,
    SUB,
    MUL,
    MULH,
    SMULL,
    SMULH,
    DIV,
    SDIV,
    NEG,
    AND,
    OR,
    XOR,
    NOT,
    SHL,
    SHR,
    MOD,
    SMOD,
    /* Memory read and write */
    LDM,
    STM,
    /* Set register with a value */
    MOV,
    /* Conditionnal jumps */
    BCC, // Internal, to same IRBlock. Used for conditionnal instructions
    JCC, // External, to other IRBlock Used for branch instructions 
    /* Boolean flag set if zero */
    BISZ,
    /* Concatenate two variables */
    CONCAT,
    /* System calls and interrupt */
    INT,
    SYSCALL
};
bool iroperation_is_assignment(IROperation& op);
bool iroperation_is_memory(IROperation& op);
ostream& operator<<(ostream& os, IROperation& op);

/* Values for syscalls */
#define SYSCALL_X86_INT80 1
#define SYSCALL_X86_SYSENTER 2 


/* IR Operations 
 ===============
Maat IR operands can be of 3 main types.
    - CST: a constant operand 
    - VAR: a operand representing a register of the disassembled arch
    - TMP: temporary registers used to model complex operations, they don't 
           correspond to actual processor registers
    - NONE: represents the fact that there is no argument used */ 
enum class IROperandType{
    CST,
    VAR,
    TMP,
    NONE
};

class IROperand{
    cst_t _val;
public:
    IROperandType type;
    exprsize_t high, low, size;
    
    IROperand();
    IROperand(IROperandType t, cst_t val, exprsize_t high, exprsize_t low);
    
    bool is_cst();
    bool is_var();
    bool is_tmp();
    bool is_none();
    
    cst_t cst();
    IRVar var();
    IRVar tmp();
};

ostream& operator<<(ostream& os, IROperand& op);
/* Helpers to create operands */
IROperand ir_cst(cst_t val, exprsize_t high, exprsize_t low);
IROperand ir_var(cst_t num, exprsize_t high, exprsize_t low);
IROperand ir_tmp(cst_t num, exprsize_t high, exprsize_t low);
IROperand ir_none();

/* IR Instructions
   ===============
Maat IR Instructions are composed of an IROperation, and 3
IROperands: one destination, and two (optional) sources  */

class IRInstruction{
public:
    addr_t addr;
    IROperation op;
    IROperand dst;
    IROperand src1;
    IROperand src2;
    
    IRInstruction(IROperation op, IROperand dst, IROperand src1, addr_t addr = 0);
    IRInstruction(IROperation op, IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
    bool reads_var(IRVar var);
    bool writes_var(IRVar var);
    bool uses_var(IRVar var);
    bool reads_tmp(IRVar tmp);
    bool writes_tmp(IRVar tmp);
    vector<IROperand> used_vars_read();
    vector<IROperand> used_vars_write();
    vector<IROperand> used_tmps_read();
    vector<IROperand> used_tmps_write();
};

ostream& operator<<(ostream& os, IRInstruction& ins);
/* Helpers to create instructions */
IRInstruction ir_add(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_sub(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_mul(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_mulh(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_smull(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_smulh(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_div(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_sdiv(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_and(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_or(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_xor(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_shl(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_shr(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_mod(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_smod(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_neg(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_not(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_ldm(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_stm(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_mov(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_bcc(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_jcc(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_bisz(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_concat(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_int(IROperand num, IROperand ret, addr_t addr = 0);
IRInstruction ir_syscall(IROperand type, IROperand ret, addr_t addr = 0);

/* IRContext 
   =========
Holds current expressions for every register */

class IRContext{
friend class BreakpointManager;
    Expr* _var;
    int _nb_var; 
    VarContext* _varctx;
public:
    IRContext(VarContext* varctx = nullptr);
    IRContext(IRVar nb_var, VarContext* varctx = nullptr);
    ~IRContext();
    int nb_vars();
    /* Get and set IR variables */
    void set(IRVar num, Expr e);
    Expr get(IRVar num);
    cst_t concretize(IRVar num, VarContext* varctx= nullptr);
    cst_t as_signed(IRVar num, VarContext* varctx= nullptr);
    cst_t as_unsigned(IRVar num, VarContext* varctx= nullptr);
    /* Make registers symbolic / tainted / etc */
    string make_symbolic(IRVar num, string name); // Make purely symbolic (replace the expression)
    void make_tainted(IRVar num); // Make the expression tainted :)
    string make_var(IRVar num, string name); // Represent the register by a simple var (but keep its concrete value)
    /* Copy */
    void copy_from(IRContext& other);
    IRContext * copy();
};

ostream& operator<<(ostream& os, IRContext& ctx);
#endif 

