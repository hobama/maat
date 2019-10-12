#include "block.hpp"
#include <cassert>
#include <cstring>
#include <algorithm>
#include <iostream>

using std::max;
using std::min;

IRBlock::IRBlock(string n, addr_t start, addr_t end): name(n), ir_size(0), 
            raw_size(0), start_addr(start), end_addr(end), branch_type(BranchType::NONE), _nb_tmp_vars(0){
    branch_target[0] = 0;
    branch_target[1] = 0;
}

void IRBlock::add_instr(IRBasicBlockId bblock, IRInstruction instr){
    assert(_bblocks.size() > bblock && "Adding instruction to basic block that doesn't exist" );
    _bblocks[bblock].push_back(instr);
    ir_size++;
}

IRBasicBlockId IRBlock::new_bblock(){
    _bblocks.push_back(IRBasicBlock());
    return (IRBasicBlockId)(_bblocks.size()-1);
}

IRBasicBlock& IRBlock::get_bblock(IRBasicBlockId id){
    return _bblocks[id];
}

int IRBlock::nb_bblocks(){
    return _bblocks.size();
}

vector<IRBasicBlock>& IRBlock::bblocks(){
    return _bblocks;
};

struct Bounds{
    int high;
    int low;
    Bounds(){
        high = 0;
        low = 0xffffff;
    }
    Bounds(int h, int l){
        high = h;
        low = l;
    };
    void update(int h, int l){
        high = max(h, high);
        low = min(l, low);
    };
    void update_min(int h, int l){
        high = min(h, high);
        low = max(l, low);
    };
    bool contains(int h, int l){
        return  high >= h && low <= l;
    };
};


/* Removing dead variables in IRBlocks
 * 
 * The algortihms is as follows:
 *    - First eliminate dead variables in each IRBasicBlock. That's easy, 
 *      simply iterate it from end to beginning and record when variables/
 *      tmps are read and set. If a variable is set and then set a second time
 *      without being read we can remove the first one. Of course we also check
 *      the high/low bits of sets because if we so set var1[31:0] and then set
 *      var1[10:0] we can not remove the first set.
 * 
 *    - Then we eliminate dead variables in the whole block. To do this, for each
 *      basic block, we get all possible paths (stop on loop to itself). If a variable
 *      is set in the basic block, not read, then set in every possible path taken 
 *      after the basic block, we can remove the set.
 * 
 * */
void IRBlock::remove_unused_vars(int nb_vars){
    remove_unused_vars(nb_vars, vector<IRVar>());
} 

void IRBlock::remove_unused_vars(int nb_vars, vector<IRVar> ignore){
    uint8_t READ=0, SET=1, UNKNOWN=2;
    uint8_t** var_use_tables = new uint8_t*[_bblocks.size()]{nullptr};
    uint8_t** tmp_use_tables = new uint8_t*[_bblocks.size()]{nullptr};
    Bounds** var_bounds_tables = new Bounds*[_bblocks.size()];
    Bounds ** tmp_bounds_tables = new Bounds*[_bblocks.size()];
    IRBasicBlock::reverse_iterator it;
    vector<IRBasicBlock>::iterator bbit;
    vector<IRBasicBlockId>::iterator bbid_it;
    IRBasicBlock::iterator bblk_it;
    vector<IROperand> vars, tmps;
    vector<IROperand>::iterator var_it;
    vector<IROperand>::iterator tmp_it;
    bool removed = false;
    IRBasicBlockId bblkid;
    unsigned int debug_remove_count = 0;
    
    /* =================== First step ===================
     * Eliminate dead IR code in each basic block 
     * ==================================================*/

    /* Remove unused variables inside each basic black first */
    for( bbit = _bblocks.begin(); bbit != _bblocks.end(); bbit++){
        bblkid = bbit - _bblocks.begin();
        /* Create use tables for this block */
        var_use_tables[bblkid] = new uint8_t[nb_vars];
        tmp_use_tables[bblkid] = new uint8_t[_nb_tmp_vars];
        var_bounds_tables[bblkid] = new Bounds[nb_vars];
        tmp_bounds_tables[bblkid] = new Bounds[_nb_tmp_vars];
        memset(var_use_tables[bblkid], UNKNOWN, nb_vars);
        memset(tmp_use_tables[bblkid], UNKNOWN, _nb_tmp_vars);
        for( it = bbit->rbegin(); it != bbit->rend(); it++){
            removed = false;
            /* Get written variables and tmps */
            vars = it->used_vars_write();
            /* Check if the instruction can be removed */
            for( var_it = vars.begin(); var_it != vars.end(); var_it++){
                if( std::find(ignore.begin(), ignore.end(), var_it->var()) == ignore.end() &&
                    var_use_tables[bblkid][var_it->var()] == SET && 
                    var_bounds_tables[bblkid][var_it->var()].contains(var_it->high, var_it->low)){
                    // Remove instruction
                    bbit->erase(it.base()-1);
                    removed = true;
                    debug_remove_count++;
                    break;
                }
                var_use_tables[bblkid][var_it->var()] = SET;
                var_bounds_tables[bblkid][var_it->var()].update(var_it->high, var_it->low);
            }
            if( !removed ){
                tmps = it->used_tmps_write();
                for( tmp_it = tmps.begin(); tmp_it != tmps.end(); tmp_it++){
                    if( tmp_use_tables[bblkid][tmp_it->tmp()] == SET &&
                        tmp_bounds_tables[bblkid][tmp_it->tmp()].contains(tmp_it->high, tmp_it->low)){
                        // Remove instruction
                        bbit->erase(it.base()-1);
                        removed = true;
                        debug_remove_count++;
                        break;
                    }
                    tmp_use_tables[bblkid][tmp_it->var()] = SET;
                    tmp_bounds_tables[bblkid][tmp_it->tmp()].update(tmp_it->high, tmp_it->low);
                }
            }
            if( removed )
                continue;
            
            /* Get read variables (AFTER written because if it is both read and write we want
               to keep the information that it's read) */
            vars = it->used_vars_read();
            tmps = it->used_tmps_read();
            for( var_it = vars.begin(); var_it != vars.end(); var_it++){
                var_use_tables[bblkid][var_it->var()] = READ;
                var_bounds_tables[bblkid][var_it->var()] = Bounds();
            }
            for( tmp_it = tmps.begin(); tmp_it != tmps.end(); tmp_it++){
                tmp_use_tables[bblkid][tmp_it->tmp()] = READ;
                tmp_bounds_tables[bblkid][tmp_it->tmp()] = Bounds();
            }
        }
    }
    
    /* =================== Second step ===================
     * Eliminate dead IR code by taking connected basic
     * blocks into account ! 
     * ==================================================*/
    
    vector<vector<IRBasicBlockId>> paths;
    vector<IRBasicBlockId> path1, path2;
    uint8_t* curr_var_use_table = new uint8_t[nb_vars];
    uint8_t* curr_tmp_use_table = new uint8_t[_nb_tmp_vars];
    Bounds* curr_var_bounds_table = new Bounds[nb_vars];
    Bounds* curr_tmp_bounds_table = new Bounds[_nb_tmp_vars];
    uint8_t* global_var_use_table = new uint8_t[nb_vars];
    uint8_t* global_tmp_use_table = new uint8_t[_nb_tmp_vars];
    Bounds* global_var_bounds_table = new Bounds[nb_vars];
    Bounds* global_tmp_bounds_table = new Bounds[_nb_tmp_vars];
    IRBasicBlockId tmp_bblkid;

    /* For each basic block check all possible paths */
    for( bblkid = 0; bblkid < _bblocks.size(); bblkid++){
        /* Init global tables */
        memset(global_var_use_table, UNKNOWN, nb_vars);
        memset(global_tmp_use_table, UNKNOWN, _nb_tmp_vars);
        for( int i = 0; i <  nb_vars; i++)
            global_var_bounds_table[i] = Bounds(0xffff, 0); // Invert bounds because we do update_min of globals ! 
        for( int i = 0; i <  _nb_tmp_vars; i++)
            global_tmp_bounds_table[i] = Bounds(0xffff, 0);
        /* Add initial path, only this bblkid */
        paths.push_back(vector<IRBasicBlockId>(1,bblkid));
        while( ! paths.empty() ){
            /* Get new path */
            path1 = paths.back();
            paths.pop_back();
            tmp_bblkid = path1.back();
            if( (std::count(path1.begin(), path1.end(), tmp_bblkid) > 1) || _bblocks[tmp_bblkid].back().op != IROperation::BCC ){
                /* Not BCC or initial bblkid => end of a path, do the analysis */
                //path1.push_back(tmp_bblkid);
                /* Init current-path tables */ 
                memset(curr_var_use_table, UNKNOWN, nb_vars);
                memset(curr_tmp_use_table, UNKNOWN, _nb_tmp_vars);
                for( int i = 0; i <  nb_vars; i++)
                    curr_var_bounds_table[i] = Bounds();
                for( int i = 0; i <  _nb_tmp_vars; i++)
                    curr_tmp_bounds_table[i] = Bounds();
                /* Go through all bblocks in order
                 *  and update the use info  (skip first since it's the one we analyse)*/ 
                for( bbid_it = path1.begin()+1; bbid_it != path1.end(); bbid_it++){
                    /* Get use info for vars */
                    for( int var = 0; var < nb_vars; var++){
                        // If first use of var is READ, then mark as read
                        if( var_use_tables[*bbid_it][var] == READ && curr_var_use_table[var] == UNKNOWN ){
                            curr_var_use_table[var] = READ;
                        // If we SET it without having read it before update set info
                        }else if(var_use_tables[*bbid_it][var] == SET && curr_var_use_table[var] != READ ){
                            /* Update current with max but global with min */
                            curr_var_use_table[var] = SET;
                            curr_var_bounds_table[var].update(var_bounds_tables[*bbid_it][var].high, var_bounds_tables[*bbid_it][var].low);
                        }
                    }
                    /* Get use info for tmps */
                    for( int tmp = 0; tmp < _nb_tmp_vars; tmp++){
                        // If first use of tmp is READ, then mark as READ in global (we cannot remove it )
                        if( tmp_use_tables[*bbid_it][tmp] == READ && curr_tmp_use_table[tmp] == UNKNOWN ){
                            curr_tmp_use_table[tmp] = READ;
                        // If we SET it without having read it before update set info
                        }else if(tmp_use_tables[*bbid_it][tmp] == SET && curr_tmp_use_table[tmp] != READ  ){
                            /* Update current with max but global with min */
                            curr_tmp_use_table[tmp] = SET;
                            curr_tmp_bounds_table[tmp].update(tmp_bounds_tables[*bbid_it][tmp].high, tmp_bounds_tables[*bbid_it][tmp].low);
                        }
                    }
                }
                /* Update the global table with table for this path */
                for( int var = 0; var < nb_vars; var++ ){
                    /* If not set then consider that READ */
                    if( curr_var_use_table[var] != SET ){
                        global_var_use_table[var] = READ;
                        global_var_bounds_table[var] = Bounds();
                    /* If set and not yet READ in global (by another path), set as SET */
                    }else if( curr_var_use_table[var] == SET &&
                              global_var_use_table[var] != READ ){
                        global_var_use_table[var] = SET;
                        /* Update global bounds with min ! */
                        global_var_bounds_table[var].update_min(curr_var_bounds_table[var].high, curr_var_bounds_table[var].low);
                    }
                }
                for( int tmp = 0; tmp < _nb_tmp_vars; tmp++){
                    /* Consider READ only if READ (if UNKNOWN then we discard it because tmp) */
                    if( curr_tmp_use_table[tmp] == READ ){
                        global_tmp_use_table[tmp] = READ;
                        global_tmp_bounds_table[tmp] = Bounds();
                    /* If set and not yet READ in global (by another path), set as SET */
                    }else if( curr_tmp_use_table[tmp] == SET && global_tmp_use_table[tmp] != READ ){
                        global_tmp_use_table[tmp] = SET;
                        /* Update global bounds with min ! */
                        global_tmp_bounds_table[tmp].update_min(curr_tmp_bounds_table[tmp].high, curr_tmp_bounds_table[tmp].low);
                    }
                }
                    
            }else{
                /* BCC, add the "src2" branch if any and take the "left" branch */
                if( _bblocks[tmp_bblkid].back().src2.is_cst()){
                    path2 = path1;
                    path2.push_back(_bblocks[tmp_bblkid].back().src2.cst());
                    paths.push_back(path2);
                }
                path1.push_back(_bblocks[tmp_bblkid].back().src1.cst());
                paths.push_back(path1);
            }
        }
        
        /* Remove unused variables in current basic block according to the
         * global use tables */
        /* Iterate each instruction of the block in reverse */
        for( it = _bblocks[bblkid].rbegin(); it != _bblocks[bblkid].rend(); it++){
            removed = false;
            /* Get written variables and tmps */
            vars = it->used_vars_write();
            /* Check if the instruction can be removed */
            for( var_it = vars.begin(); var_it != vars.end(); var_it++){
                if( std::find(ignore.begin(), ignore.end(), var_it->var()) == ignore.end() &&
                    global_var_use_table[var_it->var()] == SET && 
                    global_var_bounds_table[var_it->var()].contains(var_it->high, var_it->low)){
                    // Remove instruction
                    _bblocks[bblkid].erase(it.base()-1);
                    removed = true;
                    debug_remove_count++;
                    break;
                }else if( global_var_use_table[var_it->var()] == UNKNOWN){
                    global_var_use_table[var_it->var()] = SET;
                    global_var_bounds_table[var_it->var()] = Bounds(var_it->high, var_it->low);
                    
                }else{
                    global_var_use_table[var_it->var()] = SET;
                    global_var_bounds_table[var_it->var()].update(var_it->high, var_it->low);
                }
            }
            if( !removed ){
                tmps = it->used_tmps_write();
                for( tmp_it = tmps.begin(); tmp_it != tmps.end(); tmp_it++){
                    /* Remove tmp if they are SET or UNKNOWN, because unless registers
                     * tmp variables have no scope outsite of the block */
                    if( global_tmp_use_table[tmp_it->tmp()] != READ &&
                        global_tmp_bounds_table[tmp_it->tmp()].contains(tmp_it->high, tmp_it->low)){
                        // Remove instruction
                        _bblocks[bblkid].erase(it.base()-1);
                        removed = true;
                        debug_remove_count++;
                        break;
                    }else if( global_tmp_use_table[tmp_it->tmp()] == UNKNOWN){
                        global_tmp_use_table[tmp_it->tmp()] = SET;
                        global_tmp_bounds_table[tmp_it->tmp()] = Bounds(tmp_it->high, tmp_it->low);
                    }else{
                        global_tmp_use_table[tmp_it->tmp()] = SET;
                        global_tmp_bounds_table[tmp_it->tmp()].update(tmp_it->high, tmp_it->low);
                    }
                }
            }
            if( removed )
                continue;
            
            /* Get read variables (AFTER written because if it is both read and write we want
               to keep the information that it's read) */
            vars = it->used_vars_read();
            tmps = it->used_tmps_read();
            for( var_it = vars.begin(); var_it != vars.end(); var_it++){
                global_var_use_table[var_it->var()] = READ;
                global_var_bounds_table[var_it->var()] = Bounds();
            }
            for( tmp_it = tmps.begin(); tmp_it != tmps.end(); tmp_it++){
                global_tmp_use_table[tmp_it->tmp()] = READ;
                global_tmp_bounds_table[tmp_it->tmp()] = Bounds();
            }
        }
        
        
        
    }
    
    
    /* ===============  Free all use tables ============== */
    for( bblkid = 0; bblkid < _bblocks.size(); bblkid++){
        delete [] var_use_tables[bblkid];
        delete [] tmp_use_tables[bblkid];
        delete [] var_bounds_tables[bblkid];
        delete [] tmp_bounds_tables[bblkid];
    }
    delete [] var_use_tables;
    delete [] tmp_use_tables;
    delete [] var_bounds_tables;
    delete [] tmp_bounds_tables;
    
    delete [] curr_var_use_table;
    delete [] curr_tmp_use_table;
    delete [] curr_var_bounds_table;
    delete [] curr_tmp_bounds_table;
    delete [] global_var_use_table;
    delete [] global_tmp_use_table;
    delete [] global_var_bounds_table;
    delete [] global_tmp_bounds_table;
}

ostream& operator<<(ostream& os, IRBlock& blk){
    IRBasicBlock::iterator it;
    os << std::endl << blk.name;
    for( int i = 0; i < blk.bblocks().size(); i++){
        os << "\n\tbblk_" << i << ":" << std::endl;
        for( it = blk.bblocks()[i].begin(); it != blk.bblocks()[i].end(); it++){
            os << "\t" << *it;
        }
    }
    return os;
}
