#include "irmanager.hpp"
#include "instruction.hpp"
#include "block.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "disassembler.hpp"

using std::cout;
using std::endl; 
using std::string;

namespace test{
    namespace ir{
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int ir_context(){
            IRContext ctx = IRContext(4);
            Expr    e1 = exprcst(32, 56),
                    e2 = exprvar(64, "var1"),
                    e3 = exprvar(16, "var2");
            unsigned int nb = 0;
            ctx.set(0, e1);
            ctx.set(1, e1);
            ctx.set(2, e2);
            ctx.set(3, e3);
            nb += _assert(ctx.get(0)->eq(e1), "IRContext failed to update then get variable");
            nb += _assert(ctx.get(1)->eq(e1), "IRContext failed to update then get variable");
            nb += _assert(ctx.get(2)->eq(e2), "IRContext failed to update then get variable");
            nb += _assert(ctx.get(3)->eq(e3), "IRContext failed to update then get variable");
            return nb; 
        }
    
        unsigned int ir_addresses(){
            unsigned int nb = 0;
            IRManager irm = IRManager();
            IRBlock *b1 = new IRBlock("test", 0x0, 0x20 ),
                    *b2 = new IRBlock("test", 0x30, 0x3f ),
                    *b3 = new IRBlock("test", 0x40, 0x6789 );
            irm.add(b1);
            irm.add(b2);
            irm.add(b3);
            
            nb += _assert(!irm.contains_addr(0x0).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x0)[0] == b1, "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(!irm.contains_addr(0x1).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x1)[0] == b1, "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(!irm.contains_addr(0x18).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x18)[0] == b1, "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(!irm.contains_addr(0x19).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x19)[0] == b1, "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(!irm.contains_addr(0x30).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x30)[0] == b2, "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(!irm.contains_addr(0x3e).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x3e)[0] == b2, "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(!irm.contains_addr(0x40).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x40)[0] == b3, "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(!irm.contains_addr(0x6788).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x6788)[0] == b3, "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x6799).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x21).empty(), "IRManager::get() didn't return the right IRBlock ");
            nb += _assert(irm.contains_addr(0x29).empty(), "IRManager::get() didn't return the right IRBlock ");
            return nb;
        }
        
        unsigned int optimize_ir(){
            unsigned int nb = 0;
            
            /* Simple test inside a single basic block */
            IRBlock *block = new IRBlock("test", 0x0, 0x1000);
            IRBasicBlockId bb1, bb2, bb3, end;
            block->_nb_tmp_vars = 4;
            
            // -------
            bb1 = block->new_bblock();
            block->add_instr(bb1, ir_add(ir_var(2, 0, 0), ir_var(1, 0, 0), ir_var(0, 0, 0), 0x0));
            block->add_instr(bb1, ir_sub(ir_tmp(3, 0, 0), ir_var(1, 0, 0), ir_var(0, 0, 0), 0x1));
            block->add_instr(bb1, ir_mov(ir_var(2, 0, 0), ir_tmp(3, 0, 0), 0x2));
            block->remove_unused_vars(4);

            nb += _assert(block->get_bblock(bb1)[0].addr == 0x1, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[1].addr == 0x2, "IRBlock::remove_unused_vars() failed");
            
            // -------
            bb1 = block->new_bblock();
            block->add_instr(bb1, ir_add(ir_var(2, 0, 0), ir_var(1, 0, 0), ir_var(0, 0, 0), 0x0)); 
            block->add_instr(bb1, ir_sub(ir_tmp(3, 0, 0), ir_var(1, 0, 0), ir_var(2, 0, 0), 0x1));
            block->add_instr(bb1, ir_mov(ir_tmp(3, 0, 0), ir_cst(0, 0, 0), 0x2));
            block->add_instr(bb1, ir_mov(ir_var(2, 0, 0), ir_cst(1, 0, 0), 0x3)); 
            block->remove_unused_vars(4);
            nb += _assert(block->get_bblock(bb1)[0].addr == 0x3, "IRBlock::remove_unused_vars() failed");
            
            // -------
            bb1 = block->new_bblock();
            block->add_instr(bb1, ir_add(ir_tmp(3, 0, 0), ir_var(1, 0, 0), ir_var(0, 0, 0), 0x0)); 
            block->add_instr(bb1, ir_add(ir_tmp(3, 0, 0), ir_tmp(3, 0, 0), ir_var(0, 0, 0), 0x1));
            block->add_instr(bb1, ir_stm(ir_tmp(3, 0, 0), ir_var(1, 0, 0), 0x2)); 
            block->remove_unused_vars(4);
            
            nb += _assert(block->get_bblock(bb1)[0].addr == 0x0, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[1].addr == 0x1, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[2].addr == 0x2, "IRBlock::remove_unused_vars() failed");
            
            // -------
            bb1 = block->new_bblock();
            block->add_instr(bb1, ir_add(ir_var(2, 0, 0), ir_var(1, 0, 0), ir_var(0, 0, 0), 0x0)); 
            block->add_instr(bb1, ir_add(ir_var(2, 0, 0), ir_var(1, 0, 0), ir_cst(0, 0, 0), 0x1));
            block->add_instr(bb1, ir_stm(ir_var(1, 0, 0), ir_var(2, 0, 0), 0x2));
            block->add_instr(bb1, ir_add(ir_var(2, 0, 0), ir_var(1, 0, 0), ir_cst(1, 0, 0), 0x3)); 
            block->add_instr(bb1, ir_mulh(ir_var(2, 0, 0), ir_var(1, 0, 0), ir_cst(0, 0, 0), 0x4));
            block->add_instr(bb1, ir_mov(ir_tmp(2, 0, 0), ir_var(2, 0, 0), 0x5)); 
            block->remove_unused_vars(4);
            
            nb += _assert(block->get_bblock(bb1)[0].addr == 0x1, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[1].addr == 0x2, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[2].addr == 0x4, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[3].addr == 0x5, "IRBlock::remove_unused_vars() failed");
            
            // -------
            bb1 = block->new_bblock();
            block->add_instr(bb1, ir_add(ir_var(2, 31, 0), ir_var(1, 31, 0), ir_var(0, 31, 0), 0x0)); 
            block->add_instr(bb1, ir_add(ir_var(2, 17, 2), ir_var(1, 16, 1), ir_cst(0, 15, 0), 0x1));
            block->remove_unused_vars(4);
            
            nb += _assert(block->get_bblock(bb1)[0].addr == 0x0, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[1].addr == 0x1, "IRBlock::remove_unused_vars() failed");
            
            // -------
            bb1 = block->new_bblock();
            block->add_instr(bb1, ir_add(ir_var(2, 31, 0), ir_var(1, 31, 0), ir_var(0, 31, 0), 0x0)); 
            block->add_instr(bb1, ir_add(ir_var(2, 63, 0), ir_var(1, 63, 0), ir_cst(0, 63, 0), 0x1));
            block->add_instr(bb1, ir_stm(ir_var(2, 63, 0), ir_cst(1, 0, 0), 0x2));
            block->add_instr(bb1, ir_mov(ir_var(2, 0, 0), ir_cst(0, 0, 0), 0x3));
            
            block->remove_unused_vars(4);
            
            nb += _assert(block->get_bblock(bb1)[0].addr == 0x1, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[1].addr == 0x2, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[2].addr == 0x3, "IRBlock::remove_unused_vars() failed");            

            delete block;
            
            /* Interblock optimisations */
            block = new IRBlock("test", 0, 0x1000);
            bb1 = block->new_bblock();
            bb2 = block->new_bblock();
            bb3 = block->new_bblock();
            end = block->new_bblock();
            
            // paths bb1 -> bb2 -> end
            //       bb1 -> bb3 -> end
            
            // Var 2 set in bb1, reset in bb2 but read in bb3 -> should not be removed
            // Var 4 set in bb1, reset in bb2, but not modified in bb3 -> should not be removed
            // Var 5 set in bb1, reset in bb2, reset in end --> should be removed
            block->add_instr(bb1, ir_add(ir_var(2, 31, 0), ir_var(1, 31, 0), ir_var(0, 31, 0), 0x0));
            block->add_instr(bb1, ir_add(ir_var(4, 31, 0), ir_var(1, 31, 0), ir_var(0, 31, 0), 0x1));
            block->add_instr(bb1, ir_add(ir_var(5, 31, 0), ir_var(1, 31, 0), ir_var(0, 31, 0), 0x2)); 
            block->add_instr(bb1, ir_bcc(ir_var(0, 63, 0), ir_cst(bb2, 63, 0), ir_cst(bb3, 63, 0), 0x3));
            
            block->add_instr(bb2, ir_add(ir_var(2, 31, 0), ir_var(3, 31, 0), ir_var(3, 31, 0), 0x4)); 
            block->add_instr(bb2, ir_mul(ir_var(4, 31, 0), ir_var(3, 31, 0), ir_var(3, 31, 0), 0x5)); 
            block->add_instr(bb2, ir_xor(ir_var(5, 31, 0), ir_var(3, 31, 0), ir_var(3, 31, 0), 0x6));
            block->add_instr(bb2, ir_bcc(ir_var(1, 63, 0), ir_cst(end, 63, 0), ir_none(), 0x6));
            
            block->add_instr(bb3, ir_add(ir_var(3, 31, 0), ir_var(2, 31, 0), ir_var(2, 31, 0), 0x7)); 
            block->add_instr(bb3, ir_bcc(ir_var(1, 63, 0), ir_cst(end, 63, 0), ir_none(), 0x7));
            
            block->add_instr(end, ir_or(ir_var(5, 31, 0), ir_var(1, 31, 0), ir_var(1, 31, 0), 0x7));
            
            block->_nb_tmp_vars = 0;
            block->remove_unused_vars(6);
            
            nb += _assert(block->get_bblock(bb1)[0].addr == 0x0, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[1].addr == 0x1, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[2].addr == 0x3, "IRBlock::remove_unused_vars() failed");   
            
            delete block;
            
            /* Interblock optimisations with loop */
            block = new IRBlock("test", 0, 0x1000);
            bb1 = block->new_bblock();
            bb2 = block->new_bblock();
            end = block->new_bblock();
            
            // paths bb1 -> bb2 -> end
            //       bb1 -> bb2 -> bb1 -> end
            
            // Var 2 set in bb1, reset in end but read in beginning of bb1 -> should not be removed
            // Var 4 set then read then set in bb1,  then set in end -> should remove the second set in bb1
            block->add_instr(bb1, ir_add(ir_var(5, 31, 0), ir_var(2, 31, 0), ir_var(0, 31, 0), 0x0));
            block->add_instr(bb1, ir_add(ir_var(4, 31, 0), ir_var(1, 31, 0), ir_var(0, 31, 0), 0x1));
            block->add_instr(bb1, ir_add(ir_var(2, 31, 0), ir_var(1, 31, 0), ir_var(0, 31, 0), 0x2));
            block->add_instr(bb1, ir_mul(ir_var(1, 31, 0), ir_var(4, 31, 0), ir_var(0, 31, 0), 0x3));
            block->add_instr(bb1, ir_add(ir_var(4, 31, 0), ir_var(0, 31, 0), ir_var(0, 31, 0), 0x4));
            block->add_instr(bb1, ir_bcc(ir_cst(1, 63, 0), ir_cst(bb2, 63, 0), ir_none(), 0x5));
            
            block->add_instr(bb2, ir_bcc(ir_var(0, 63, 0), ir_cst(bb1, 63, 0), ir_cst(end, 63, 0), 0x6));
            
            block->add_instr(end, ir_or(ir_var(4, 31, 0), ir_var(0, 31, 0), ir_var(0, 31, 0), 0x7));
            
            block->_nb_tmp_vars = 0;
            block->remove_unused_vars(6);
            
            nb += _assert(block->get_bblock(bb1)[0].addr == 0x0, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[1].addr == 0x1, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[2].addr == 0x2, "IRBlock::remove_unused_vars() failed");
            nb += _assert(block->get_bblock(bb1)[3].addr == 0x3, "IRBlock::remove_unused_vars() failed");   
            nb += _assert(block->get_bblock(bb1)[4].addr == 0x5, "IRBlock::remove_unused_vars() failed");
            
            delete block;
            return nb;
        }

    }
    
    
}

using namespace test::ir; 
// All unit tests 
void test_ir(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing ir module... " << std::flush;  
    total += ir_context();
    total += ir_addresses();
    total += optimize_ir();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
