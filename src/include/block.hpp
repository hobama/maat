#ifndef IRBLOCK_H
#define IRBLOCK_H

#include <vector>
#include <string>
#include "instruction.hpp"
#include "typedefs.hpp"

using std::vector;
using std::string;

/* Type aliasing */
typedef vector<IRInstruction> IRBasicBlock;


/* BranchType: describes the type of branchment that is found at the 
 * end of an IR Basic Block */
enum class BranchType{
    NONE,           // Non branching instruction at the end
    UNDEFINED,      // Single branch but can't resolve target address
    BRANCH,         // Single branch
    MULTIBRANCH,    // Two branches
    MULTIUNDEFINED  // Two branches but can't resolve one or both target addresses
};


/* IRBlock
   =======
   An IRBlock represents a basic block in assembly. By basic block we mean
   a sequence of contiguous instructions that are executed sequentially (so
   no branchement instruction in the middle of a basic block, only at the
   end).

    An IRBlock is **uniquely** identifier by its start address ! There is a 'name'
    field but it's just here for convenience.

    An IRBlock is made of several IRBasicBlocks (which are just lists of
    IRInstructions). It also holds several "meta" informations like the number
    of tmp ir vars it holds, it's size in IR, in raw assembly, the branchment
    type it finishes with, etc.
*/
class IRBlock{
friend class DisassemblerX86;
    vector<IRBasicBlock> _bblocks;
public:
    int _nb_tmp_vars;
    addr_t start_addr, end_addr;
    const string name;
    unsigned int ir_size;
    unsigned int raw_size;
    BranchType branch_type;
    addr_t branch_target[2]; // [0]: target when condition expression is 0
                             // [1]: target when condition expression is != 0
    IRBlock(string name, addr_t start=0, addr_t end=0);
    void add_instr(IRBasicBlockId bblock, IRInstruction instr);
    IRBasicBlockId new_bblock();
    IRBasicBlock& get_bblock(IRBasicBlockId id);
    int nb_bblocks();
    vector<IRBasicBlock>& bblocks();
    /* Optimisations */
    void remove_unused_vars(int nb_vars);
    void remove_unused_vars(int nb_vars, vector<IRVar> ignore);
};

ostream& operator<<(ostream& os, IRBlock& blk);


#endif 
