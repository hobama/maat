#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "exception.hpp"
#include "symbolic.hpp"
#include "environment.hpp"


using std::cout;
using std::endl; 
using std::string;


namespace test{
    namespace environment{
        
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }

        // Expects to args
        EnvCallbackReturn _dummy_callback_1(SymbolicEngine& sym, vector<Expr> args){
            return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, 0x12345678); 
        }
        
        // Expects (i16, i16, i32), stores arg[0] + arg[1] at arg[2]
        EnvCallbackReturn _dummy_callback_2(SymbolicEngine& sym, vector<Expr> args){
            sym.mem->write((uint32_t)(args[2]->concretize(sym.vars)), args[0] + args[1]);
            return EnvCallbackReturn(ENV_CALLBACK_SUCCESS); 
        }

        unsigned int dummy_1(){
            unsigned int nb = 0;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            EnvManager envm = EnvManager();
            envm.add_function(new EnvFunction(_dummy_callback_1, "dummy", ABI::X86_CDECL, vector<size_t>{}));
            
            sym.mem->new_segment(0, 200);
            
            envm.get_function("dummy").call(sym);
            
            nb += _assert((uint32_t)sym.regs->concretize(X86_EAX) == 0x12345678, "EnvManager: failed to call simple callback on X86");
            nb += _assert((uint32_t)sym.regs->concretize(X86_ESP) == 0x4, "EnvManager: failed to call simple callback on X86");

            return nb;
        }
        
        unsigned simple_callback(){
            unsigned int nb = 0;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.env->add_function(new EnvFunction(_dummy_callback_1, "dummy", ABI::X86_CDECL, vector<size_t>{}));
            sym.env->loaded_function("dummy", 0x600);
            
            /* Code is
                mov eax, 0;
                mov ebx, 1;
                mov ecx, 2;
                push ecx;
                push ebx;
                push eax;
                call 0x600;
                jmp 0x10 --> to stop disassembly :)
            */
            
            string code = string("\xb8\x00\x00\x00\x00\xbb\x01\x00\x00\x00\x51\x53\x50\xe8\xee\x05\x00\x00\xeb\x10", 20);
            sym.mem->new_segment(0, 0x2000);
            sym.mem->write(0, (uint8_t*)code.c_str(), code.size());
            sym.breakpoint.add(BreakpointType::ADDR, "after", 18);
            
            sym.regs->set(X86_ESP, exprcst(32,0x300));
            sym.execute_from(0);
            
            nb += _assert((uint32_t)sym.regs->concretize(X86_EAX) == 0x12345678, "EnvManager: failed to call simple callback on X86");
            nb += _assert((uint32_t)sym.regs->concretize(X86_ESP) == 0x2f4, "EnvManager: failed to call simple callback on X86");
            nb += _assert((uint32_t)sym.regs->concretize(X86_EIP) == 18, "EnvManager: failed to call simple callback on X86");
            
            return nb;
        }

        unsigned simple_callback_args(){
            unsigned int nb = 0;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.env->add_function(new EnvFunction(_dummy_callback_2, "dummy", ABI::X86_CDECL, vector<size_t>{2, 2, 4}));
            sym.env->loaded_function("dummy", 0x600);
            
            /* Code is
                mov eax, 0;
                mov ebx, 1;
                mov ecx, 0x700;
                push ecx;
                push bx;
                push ax;
                call 0x600;
                jmp 0x10 --> to stop disassembly :)
            */
            
            string code = string("\xb8\x00\x00\x00\x00\xbb\x01\x00\x00\x00\xb9\x00\x07\x00\x00\x51\x66\x53\x66\x50\xe8\xe7\x05\x00\x00\xeb\x10", 27);
            sym.mem->new_segment(0, 0x2000);
            sym.mem->write(0, (uint8_t*)code.c_str(), code.size());
            sym.breakpoint.add(BreakpointType::ADDR, "after", 25);
            
            sym.regs->set(X86_ESP, exprcst(32,0x300));
            sym.execute_from(0);
            
            nb += _assert((uint32_t)sym.mem->read(0x700, 2)->concretize(sym.vars) == 1, "EnvManager: failed to call simple callback on X86");
            nb += _assert((uint32_t)sym.regs->concretize(X86_ESP) == 0x2f8, "EnvManager: failed to call simple callback on X86");
            nb += _assert((uint32_t)sym.regs->concretize(X86_EIP) == 25, "EnvManager: failed to call simple callback on X86");
            
            return nb;
        }
        
    }
}

using namespace test::environment;
// All unit tests 
void test_env(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing environment simulation... " << std::flush;  
    total += dummy_1();
    total += simple_callback();
    total += simple_callback_args();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
