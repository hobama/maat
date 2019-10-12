#ifndef IR_MANAGER_H
#define IR_MANAGER_H

#include <map>
#include "memory.hpp"
#include "block.hpp"

/* Type aliasing */
typedef std::map<addr_t, IRBlock*> irblock_map_t;

/* InstructionLocation
   =================== */
   
struct InstructionLocation{
    IRBlock* block; /* The ir block where the instruction is */
    IRBasicBlockId bblkid; /* The basic block where the instruction is */
    unsigned int instr_count; /* The instruction starts at this IRInstruction in the ir basic block */ 
    InstructionLocation(IRBlock* b, IRBasicBlockId bbid, unsigned int c ): block(b), bblkid(bbid), instr_count(c){}
};

/* IRManager
   =========
A simple class that maps addresses to IRBlocks. */ 

class IRManager{
    irblock_map_t _irblocks;
public:
    IRManager();
    ~IRManager();
    addr_t add(IRBlock* irblock);
    IRBlock* starts_at_addr(addr_t);
    vector<IRBlock*> contains_addr(addr_t);
    vector<InstructionLocation> contains_instr(addr_t);
    void remove(addr_t);
};

#endif 
