#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "loader.hpp"
#include "symbolic.hpp"
#include "exception.hpp"

using std::cout;
using std::endl; 
using std::string;


namespace test{
    namespace loader{
        
// Don't compile this if no Loader backend defined
#if defined(HAS_LOADER_BACKEND)
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }   
        
        unsigned int load_simple_algo_2(){
            unsigned int nb = 0;
            SymbolicEngine sym(ArchType::X86, SysType::LINUX);
            Loader* l = NewLoader(sym);
            addr_t tmp;
            l->load("tests/ressources/simple_algo_2/simple_algo_2", BinType::ELF32, 0x56555000, vector<CmdlineArg>{CmdlineArg("12345678")});
            
            nb += _assert(sym.regs->concretize(X86_EIP) == 0x56555430, "Loader: ELF X86: instruction pointer not set correctly");
            nb += _assert(sym.mem->read(0x565555dd, 4)->concretize() == 0x56555680, "Loader: ELF X86: relocation failed");
            nb += _assert(sym.mem->read(0x56556ecc, 4)->concretize() == 0x56555560, "Loader: ELF X86: relocation failed");
            nb += _assert(sym.mem->read(0x56556ed0, 4)->concretize() == 0x56555510, "Loader: ELF X86: relocation failed");
            nb += _assert(sym.mem->read(0x56556ff8, 4)->concretize() == 0x56555598, "Loader: ELF X86: relocation failed");
            nb += _assert(sym.mem->read(0x56557004, 4)->concretize() == 0x56557004, "Loader: ELF X86: relocation failed");
            
            nb += _assert(sym.mem->read((uint32_t)sym.regs->concretize(X86_ESP), 4)->concretize() == 2, "Loader: ELF X86: argc not set correctly");
            tmp = (uint32_t)sym.mem->read((uint32_t)(sym.regs->concretize(X86_ESP)) + 4 + 4, 4)->concretize();
            nb += _assert(sym.mem->read(tmp, 8)->concretize() == 0x3837363534333231, "Loader: ELF X86: failed to setup argument in stack");
            nb += _assert(sym.mem->read(tmp+8, 1)->concretize() == 0, "Loader: ELF X86: failed to setup argument in stack (missing termination '\0')");
            
            delete l;
            return nb;
        }

#endif
    }
}

using namespace test::loader;
// All unit tests 
void test_loader(){
// Do tests only if a loader backend has been defined
#if defined(HAS_LOADER_BACKEND)
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing loader interface... " << std::flush;  

    total += load_simple_algo_2();
    
    // Print res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
#endif
}
