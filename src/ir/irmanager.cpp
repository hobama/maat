#include "irmanager.hpp"
#include <algorithm>
#include <iostream>

/* ======================================== */
IRManager::IRManager(): _irblocks(irblock_map_t()){};

addr_t IRManager::add(IRBlock* irblock){
    _irblocks[irblock->start_addr] = irblock;
    return irblock->start_addr;
}

IRBlock* IRManager::starts_at_addr(addr_t addr){
    irblock_map_t::iterator it;
    vector<IRBlock*> res;
    if( (it = _irblocks.find(addr)) != _irblocks.end() ){
        return it->second;
    }else{
        return nullptr;
    }
}

vector<IRBlock*> IRManager::contains_addr(addr_t addr){
    irblock_map_t::iterator it;
    vector<IRBlock*> res;
    // Search inside blocks and get first block that ends after 'addr'
    it = std::lower_bound(_irblocks.begin(), _irblocks.end(), addr,
         [](std::pair<addr_t, IRBlock*> block, addr_t addr) -> bool {
             return block.second->end_addr <= addr;  
             });
    // Then check all blocks to see if they contain 'addr' until the start is after 'addr'
    for( ; it != _irblocks.end() && it->second->start_addr <= addr ; it++ ){
        if( it->second->end_addr > addr )
            res.push_back(it->second);
    }
    return res;
}

/* This function redoes what contains_addr() does but I prefer not calling contains_addr()
 * add copy vectors etc, for performance reasons */
vector<InstructionLocation> IRManager::contains_instr(addr_t addr){
    irblock_map_t::iterator it;
    vector<InstructionLocation> res;
    IRBasicBlockId bblkid;
    unsigned int ir_instr_count;
    IRBlock* block;
    bool found_instr;
    vector<IRInstruction>::iterator instr;
    // Search inside blocks and get first block that ends after 'addr'
    it = std::lower_bound(_irblocks.begin(), _irblocks.end(), addr,
         [](std::pair<addr_t, IRBlock*> block, addr_t addr) -> bool {
             return block.second->end_addr < addr;  
             });
    // Then check all blocks to see if they contain 'addr' until the start is after 'addr'
    for( ; it != _irblocks.end() && it->second->start_addr <= addr ; it++ ){
        if( it->second->end_addr >= addr ){
            block = it->second;
            /* Check if the block contains the exact instruction at 'addr' */
            found_instr = false;
            for( bblkid = 0; bblkid < block->nb_bblocks(); bblkid++){
                ir_instr_count = 0;
                for( instr = block->get_bblock(bblkid).begin(); instr != block->get_bblock(bblkid).end(); instr++){
                    if( instr->addr == addr ){
                        res.push_back(InstructionLocation(block, bblkid, ir_instr_count));
                        found_instr = true;
                        break;
                    }
                    ir_instr_count++;
                }
                if( found_instr )
                    break;
            }
        }
    }
    return res;
}

void IRManager::remove(addr_t addr){
    irblock_map_t::iterator it;
    it = _irblocks.find(addr);
    if( it != _irblocks.end()){
        delete it->second;
        _irblocks.erase(addr);
    }
}

IRManager::~IRManager(){
    irblock_map_t::iterator it;
    for( it = _irblocks.begin(); it != _irblocks.end(); it++){
        delete it->second;
    }
}
/* ======================================== */
