#ifndef IRSTATE_H
#define IRSTATE_H

#include <vector>
#include "typedefs.hpp"

using std::vector;

class IRState{
public:
    bool is_set;
    addr_t instr_addr;
    addr_t block_addr;
    IRBasicBlockId bblkid;
    int ir_instr_num;
    vector<Expr> tmp_vars;
    
    IRState();
    void reset();
    void copy_from(IRState& other);
};

#endif
