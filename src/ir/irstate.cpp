#include "irstate.hpp"

IRState::IRState(){
    reset();
}
void IRState::reset(){
    is_set = false;
    tmp_vars.clear();  
    instr_addr = 0;
    block_addr = 0;
    bblkid = 0xffffffff;
    ir_instr_num = 0xffffffff;
};
void IRState::copy_from(IRState& other){
    is_set = other.is_set;
    tmp_vars = other.tmp_vars;
    instr_addr = other.instr_addr;
    block_addr = other.block_addr;
    ir_instr_num = other.ir_instr_num;
    bblkid = other.bblkid;
};

