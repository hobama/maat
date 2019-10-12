#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include "exception.hpp"
#include "expression.hpp"
#include "solver.hpp"
#include "symbolic.hpp"
#include <fstream>

using std::cout;
using std::endl; 
using std::string;

namespace test{
    namespace code_coverage{
#ifdef HAS_SOLVER_BACKEND        
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        bool do_code_coverage(SymbolicEngine& sym, addr_t start, addr_t end){
            Solver* sol = NewSolver();
            VarContext* model;
            /* Set breakpoints and handlers */
            sym.breakpoint.add(BreakpointType::ADDR, "end", end);
            sym.breakpoint.add(BreakpointType::PATH_CONSTRAINT, "path");
            
            /* Set EIP at starting point */
            sym.regs->set(X86_EIP, exprcst(32, 0x4ed));
            
            /* Execute code coverage !!! */
            bool success = false;
            bool cont = true;
            sym.enable(SymbolicEngineOption::RECORD_PATH_CONSTRAINTS);
            while( sym.execute() == StopInfo::BREAKPOINT ){
                if( sym.info.breakpoint == "end" ){
                    /* First try to find a model for EAX == 1 */
                    sol->reset();
                    sym.path->constraints_to_solver(sol);
                    sol->add(sym.regs->get(X86_EAX) != exprcst(32, 0));
                    if( sol->check() ){
                        success = true;
                        model = sol->get_model();
                        // Update context and continue from here with new values
                        sym.vars->update_from(*model);
                        delete model; model = nullptr;
                        break; // Success
                    }else{
                        // Else go back to previous snapshot and invert condition
                        cont = false;
                        while( sym.restore_snapshot(true) ){
                            sym.execute(1);
                            _assert(sym.info.breakpoint == "path", "find_input(): failed to re-break on conditionnal instruction");
                            sol->reset();
                            sym.path->constraints_to_solver(sol);
                            sol->add(sym.info.path_constraint->invert());
                            //_assert(sol->check(), "find_input(): couldn't find model to explore new branch");
                            if( sol->check() ){
                                // Get new input
                                model = sol->get_model();
                                // Update context and continue from here with new values
                                sym.vars->update_from(*model);
                                delete model; model = nullptr;
                                cont = true;
                                break;
                            }
                        }
                        // If all snapshots consumed, we tried all possible paths, stop execution !
                        if( !cont)
                            break;
                    }
                }else if( sym.info.breakpoint == "path" ){
                    sym.take_snapshot();
                }else{
                    cout << "\nFail: find_input(): got unknown breapoint " << std::endl;
                    throw test_exception();
                }
            }
            delete sol; sol = nullptr;
            return success;
        }
        
        unsigned int plaintext_pwd(){
            /* Function that checks a password 
             *     0x000004ed <+0>:	    push   ebp
                   0x000004ee <+1>:	    mov    ebp,esp
                   0x000004f0 <+3>:	    sub    esp,0x10
                   0x000004f3 <+6>:	    mov    BYTE PTR [ebp-0x9],0x74
                   0x000004f7 <+10>:	mov    BYTE PTR [ebp-0x8],0x72
                   0x000004fb <+14>:	mov    BYTE PTR [ebp-0x7],0x75
                   0x000004ff <+18>:	mov    BYTE PTR [ebp-0x6],0x63
                   0x00000503 <+22>:	mov    BYTE PTR [ebp-0x5],0x0
                   0x00000507 <+26>:	mov    DWORD PTR [ebp-0x4],0x0
                   0x0000050e <+33>:	jmp    0x52a <check+61>
                   0x00000510 <+35>:	mov    edx,DWORD PTR [ebp-0x4]
                   0x00000513 <+38>:	mov    eax,DWORD PTR [ebp+0x8]
                   0x00000516 <+41>:	add    eax,edx
                   0x00000518 <+43>:	movzx  eax,BYTE PTR [eax]
                   0x0000051b <+46>:	test   al,al
                   0x0000051d <+48>:	jne    0x526 <check+57>
                   0x0000051f <+50>:	mov    eax,0x0
                   0x00000524 <+55>:	jmp    0x568 <check+123>
                   0x00000526 <+57>:	add    DWORD PTR [ebp-0x4],0x1
                   0x0000052a <+61>:	cmp    DWORD PTR [ebp-0x4],0x3
                   0x0000052e <+65>:	jg     0x54a <check+93>
                   0x00000530 <+67>:	lea    edx,[ebp-0x9]
                   0x00000533 <+70>:	mov    eax,DWORD PTR [ebp-0x4]
                   0x00000536 <+73>:	add    eax,edx
                   0x00000538 <+75>:	movzx  edx,BYTE PTR [eax]
                   0x0000053b <+78>:	mov    ecx,DWORD PTR [ebp-0x4]
                   0x0000053e <+81>:	mov    eax,DWORD PTR [ebp+0x8]
                   0x00000541 <+84>:	add    eax,ecx
                   0x00000543 <+86>:	movzx  eax,BYTE PTR [eax]
                   0x00000546 <+89>:	cmp    dl,al
                   0x00000548 <+91>:	je     0x510 <check+35>
                   0x0000054a <+93>:	lea    edx,[ebp-0x9]
                   0x0000054d <+96>:	mov    eax,DWORD PTR [ebp-0x4]
                   0x00000550 <+99>:	add    eax,edx
                   0x00000552 <+101>:	movzx  edx,BYTE PTR [eax]
                   0x00000555 <+104>:	mov    ecx,DWORD PTR [ebp-0x4]
                   0x00000558 <+107>:	mov    eax,DWORD PTR [ebp+0x8]
                   0x0000055b <+110>:	add    eax,ecx
                   0x0000055d <+112>:	movzx  eax,BYTE PTR [eax]
                   0x00000560 <+115>:	cmp    dl,al
                   0x00000562 <+117>:	sete   al
                   0x00000565 <+120>:	movzx  eax,al
                   0x00000568 <+123>:	leave  
                   0x00000569 <+124>:	ret 
            */
            unsigned int nb = 0;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            bool success;
            sym.mem->new_segment(0x0, 0xfff, MEM_FLAG_RWX);
            sym.mem->new_segment(0x4000, 0x5fff, MEM_FLAG_RW); // stack
            sym.regs->set(X86_ESP, exprcst(32, 0x5000));
            sym.mem->write(0x5004, exprcst(32, 0x6000)); // argument of the function pushed on the stack
            sym.regs->set(X86_EAX, exprcst(32, 0x6000));
            sym.mem->new_segment(0x6000, 0x6100, MEM_FLAG_RW); // The input password
            
            /* Make user supplied password symbolic */
            sym.mem->write(0x6000, exprvar(8, "char0", Taint::TAINTED));
            sym.mem->write(0x6001, exprvar(8, "char1", Taint::TAINTED));
            sym.mem->write(0x6002, exprvar(8, "char2", Taint::TAINTED));
            sym.mem->write(0x6003, exprvar(8, "char3", Taint::TAINTED));
            sym.mem->write(0x6004, exprvar(8, "char4", Taint::TAINTED));
            /* First try to run on */
            string initial_try = "aaaaa";
            sym.vars->set("char0", initial_try[0]);
            sym.vars->set("char1", initial_try[1]);
            sym.vars->set("char2", initial_try[2]);
            sym.vars->set("char3", initial_try[3]);
            sym.vars->set("char4", initial_try[4]);
            
            /* Write the code of the function in memory */
            // map function at address 0x4ed
            std::ifstream file("tests/ressources/plaintext_pwd/check.bin", std::ios::binary | std::ios::ate);
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            std::vector<char> buffer(size);
            if( ! file.read(buffer.data(), size)){
                cout << "\nFailed to get ressource to launch tests !" << endl << std::flush; 
                throw test_exception();
            }
            sym.mem->write(0x4ed, (uint8_t*)string(buffer.begin(), buffer.end()).c_str(), size);
            
            /* Execute code coverage !!! */
            success = do_code_coverage(sym, 0x4ed, 0x568);
            
            nb += _assert(success, "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char0") == 't', "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char1") == 'r', "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char2") == 'u', "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char3") == 'c', "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char4") == 0, "find_input(): failed to find the correct input");
            
            return nb;
        }
        
        unsigned int xored_pwd(){
            /* Function that checks a xored password 
             *     0x000004ed <+0>:	    push   %ebp
                   0x000004ee <+1>:	    mov    %esp,%ebp
                   0x000004f0 <+3>:	    sub    $0x10,%esp
                   0x000004f3 <+6>:	    movb   $0xdf,-0x9(%ebp)
                   0x000004f7 <+10>:	movb   $0xd3,-0x8(%ebp)
                   0x000004fb <+14>:	movb   $0xd3,-0x7(%ebp)
                   0x000004ff <+18>:	movb   $0xc8,-0x6(%ebp)
                   0x00000503 <+22>:	movb   $0xb4,-0x5(%ebp)
                   0x00000507 <+26>:	movl   $0x0,-0x4(%ebp)
                   0x0000050e <+33>:	movl   $0x0,-0x4(%ebp)
                   0x00000515 <+40>:	jmp    0x548 <check+91>
                   0x00000517 <+42>:	mov    -0x4(%ebp),%edx
                   0x0000051a <+45>:	mov    0x8(%ebp),%eax
                   0x0000051d <+48>:	add    %edx,%eax
                   0x0000051f <+50>:	movzbl (%eax),%eax
                   0x00000522 <+53>:	xor    $0xffffffb3,%eax
                   0x00000525 <+56>:	movzbl %al,%eax
                   0x00000528 <+59>:	lea    0x1(%eax),%ecx
                   0x0000052b <+62>:	lea    -0x9(%ebp),%edx
                   0x0000052e <+65>:	mov    -0x4(%ebp),%eax
                   0x00000531 <+68>:	add    %edx,%eax
                   0x00000533 <+70>:	movzbl (%eax),%eax
                   0x00000536 <+73>:	movzbl %al,%eax
                   0x00000539 <+76>:	cmp    %eax,%ecx
                   0x0000053b <+78>:	je     0x544 <check+87>
                   0x0000053d <+80>:	mov    $0x0,%eax
                   0x00000542 <+85>:	jmp    0x553 <check+102>
                   0x00000544 <+87>:	addl   $0x1,-0x4(%ebp)
                   0x00000548 <+91>:	cmpl   $0x4,-0x4(%ebp)
                   0x0000054c <+95>:	jle    0x517 <check+42>
                   0x0000054e <+97>:	mov    $0x1,%eax
                   0x00000553 <+102>:	leave  
                   0x00000554 <+103>:	ret
            */
            unsigned int nb = 0;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            bool success;
            
            sym.mem->new_segment(0x0, 0xfff, MEM_FLAG_RWX);
            sym.mem->new_segment(0x4000, 0x5fff, MEM_FLAG_RW); // stack
            sym.regs->set(X86_ESP, exprcst(32, 0x5000));
            sym.mem->write(0x5004, exprcst(32, 0x6000)); // argument of the function pushed on the stack
            sym.regs->set(X86_EAX, exprcst(32, 0x6000));
            sym.mem->new_segment(0x6000, 0x6100, MEM_FLAG_RW); // The input password
            
            /* Make user supplied password symbolic */
            sym.mem->write(0x6000, exprvar(8, "char0", Taint::TAINTED));
            sym.mem->write(0x6001, exprvar(8, "char1", Taint::TAINTED));
            sym.mem->write(0x6002, exprvar(8, "char2", Taint::TAINTED));
            sym.mem->write(0x6003, exprvar(8, "char3", Taint::TAINTED));
            sym.mem->write(0x6004, exprvar(8, "char4", Taint::TAINTED));
            /* First try to run on */
            string initial_try = "aaaaa";
            sym.vars->set("char0", initial_try[0]);
            sym.vars->set("char1", initial_try[1]);
            sym.vars->set("char2", initial_try[2]);
            sym.vars->set("char3", initial_try[3]);
            sym.vars->set("char4", initial_try[4]);
            
            /* Write the code of the function in memory */
            // map function at address 0x4ed
            std::ifstream file("tests/ressources/xored_pwd/check.bin", std::ios::binary | std::ios::ate);
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            std::vector<char> buffer(size);
            if( ! file.read(buffer.data(), size)){
                cout << "\nFailed to get ressource to launch tests !" << endl << std::flush; 
                throw test_exception();
            }
            sym.mem->write(0x4ed, (uint8_t*)string(buffer.begin(), buffer.end()).c_str(), size);
            
            /* Execute code coverage !!! */
            success = do_code_coverage(sym, 0x4ed, 0x553);
            
            nb += _assert(success, "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char0") == 'm', "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char1") == 'a', "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char2") == 'a', "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char3") == 't', "find_input(): failed to find the correct input");
            nb += _assert((char)sym.vars->get("char4") == 0, "find_input(): failed to find the correct input");
            
            return nb;
        }
#endif
    }
}

using namespace test::code_coverage;
// All unit tests 
void test_code_coverage(){
#ifdef HAS_SOLVER_BACKEND
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing code coverage... " << std::flush;
    total += plaintext_pwd();
    total += xored_pwd();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
#endif
}
