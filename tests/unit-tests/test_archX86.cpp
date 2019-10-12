#include "arch.hpp"
#include "symbolic.hpp"
#include "exception.hpp"
#include "disassembler.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>

using std::cout;
using std::endl; 
using std::string;

namespace test{
    namespace archX86{
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int some_bench(){
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\x11\xD8", 2); // adc eax, ebx
            sym.mem->write(0x1150, (uint8_t*)code.c_str(), 2);
            code = string("\x66\x0F\x38\xF6\xC3", 5); // adcx eax, ebx
            sym.mem->write(0x1152, (uint8_t*)code.c_str(), 5);
            code = string("\x11\xD8", 2); // adc eax, ebx
            sym.mem->write(0x1157, (uint8_t*)code.c_str(), 2);
            code = string("\x37", 1); // aaa
            sym.mem->write(0x1159, (uint8_t*)code.c_str(), 1);
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_EAX, exprcst(32, 0x10));
            sym.regs->set(X86_EBX, exprcst(32, 0x20));
            
            for( int i = 0; i < 250000; i++){
                if( i % 10000 == 0 ){
                    sym.regs->set(X86_CF, exprcst(32, 1));
                    sym.regs->set(X86_EAX, exprcst(32, 0x10));
                    sym.regs->set(X86_EBX, exprcst(32, 0x20));
                }
                sym.execute_from(0x1150, 4);
            }
            return 0;
        }
        
        unsigned int reg_translation(){
            unsigned int nb = 0;
            reg_t reg;
            ArchX86 arch = ArchX86();
            for( reg = 0; reg < X86_NB_REGS; reg++ ){
                nb += _assert( arch.reg_num(arch.reg_name(reg)) == reg , "ArchX86: translation reg_num <-> reg_name failed");
            }
            nb += _assert(arch.sp() == X86_ESP, "ArchX86: translation reg_num <-> reg_name failed");
            nb += _assert(arch.pc() == X86_EIP, "ArchX86: translation reg_num <-> reg_name failed");
            return nb;
        }
        
        unsigned int disass_add(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.regs->make_symbolic(X86_EAX, "eax");
            sym.regs->make_symbolic(X86_EBX, "ebx");
            sym.regs->make_symbolic(X86_ECX, "ecx");
            sym.regs->make_symbolic(X86_EDX, "edx");
            
            sym.mem->new_segment(0x1000, 0x1fff);
            /* ADD REG,IMM */
            // add eax, 1
            code = "\x83\xC0\x01";
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), code.size());
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->eq(exprvar(32, "eax")+exprcst(32,1)), 
                            "ArchX86: failed to disassembly and/or execute ADD"); 
            // add bl, 0xff
            code = "\x80\xC3\xFF";
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), code.size());
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1010, 1);
            nb += _assert(  sym.regs->get(X86_EBX)->eq(concat(extract(exprvar(32, "ebx"), 31, 8),
                                                               extract(exprvar(32, "ebx"), 7, 0)+exprcst(8,0xff))), 
                            "ArchX86: failed to disassembly and/or execute ADD"); 
            // add ch, 0x10
            code = "\x80\xC5\x10";
            sym.mem->write(0x1020, (uint8_t*)code.c_str(), code.size());
            sym.mem->write(0x1020+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1020, 1);
            nb += _assert(  sym.regs->get(X86_ECX)->eq( 
                    concat( concat( extract(exprvar(32, "ecx"), 31, 16),
                                    extract(exprvar(32, "ecx"), 15, 8)+exprcst(8,0x10)),
                            extract(exprvar(32, "ecx"), 7, 0))),
                    "ArchX86: failed to disassembly and/or execute ADD"); 
            // add dx, 0xffff
            code = "\x66\x83\xC2\xFF";
            sym.mem->write(0x1030, (uint8_t*)code.c_str(), code.size());
            sym.mem->write(0x1030+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1030, 1);
            nb += _assert(  sym.regs->get(X86_EDX)->eq(concat(extract(exprvar(32, "edx"), 31, 16),
                                                               extract(exprvar(32, "edx"), 15, 0)+exprcst(16,0xffff))), 
                            "ArchX86: failed to disassembly and/or execute ADD"); 
            /* ADD REG, REG */
            sym.regs->set(X86_EAX, exprvar(32, "eax")); // reset 
            sym.regs->set(X86_EBX, exprvar(32, "ebx")); // reset 
            sym.regs->set(X86_ECX, exprvar(32, "ecx")); // reset 
            sym.regs->set(X86_EDX, exprvar(32, "edx")); // reset 
            // add al,bl
            code = string("\x00\xD8",2);
            sym.mem->write(0x1040, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1040+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1040, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->eq(concat(extract(exprvar(32, "eax"), 31, 8),
                                                    extract(exprvar(32, "eax"), 7, 0)+extract(exprvar(32,"ebx"), 7, 0))), 
                            "ArchX86: failed to disassembly and/or execute ADD"); 
            sym.regs->set(X86_EAX, exprvar(32, "eax")); // reset 
            // add ch,dh
            code = string("\x00\xF5", 2);
            sym.mem->write(0x1050, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1050+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1050, 1);
            nb += _assert(  sym.regs->get(X86_ECX)->eq(
                concat( concat( extract(exprvar(32, "ecx"), 31, 16),
                                extract(exprvar(32, "ecx"), 15, 8)+extract(exprvar(32,"edx"), 15, 8)),
                        extract(exprvar(32, "ecx"), 7, 0 ))),
                "ArchX86: failed to disassembly and/or execute ADD"); 
            sym.regs->set(X86_ECX, exprvar(32, "ecx")); // reset 
            // add ax,bx
            code = string("\x66\x01\xD8", 3);
            sym.mem->write(0x1060, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1060+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1060, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->eq(concat(extract(exprvar(32, "eax"), 31, 16),
                                                    extract(exprvar(32, "eax"), 15, 0)+extract(exprvar(32,"ebx"), 15, 0))), 
                            "ArchX86: failed to disassembly and/or execute ADD"); 
            sym.regs->set(X86_EAX, exprvar(32, "eax")); // reset 
            // add ecx, edx
            code = string("\x01\xD1",2);
            sym.mem->write(0x1070, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1070+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1070, 1);
            nb += _assert(  sym.regs->get(X86_ECX)->eq(exprvar(32, "ecx")+ exprvar(32,"edx")),
                "ArchX86: failed to disassembly and/or execute ADD"); 
            sym.regs->set(X86_ECX, exprvar(32, "ecx")); // reset
            
            /* ADD REG, MEM */
            sym.regs->set(X86_EAX, exprcst(32, 0x612)); 
            sym.regs->set(X86_EBX, exprcst(32, 0x612)); 
            sym.regs->set(X86_ECX, exprcst(32, 0x612));
            sym.regs->set(X86_EDX, exprcst(32, 0x612));
            sym.mem->new_segment(0x0, 0xfff); // New segment because r/w with 
                                              // regs initialized to 0 by default
            sym.mem->write(0x612, exprcst(32, 0x12345678), sym.vars);
            // add al, BYTE PTR [eax]
            code = string("\x02\x00",2);
            sym.mem->write(0x1080, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1080+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1080, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x68a, "ArchX86: failed to disassembly and/or execute ADD");
            // add bx, WORD PTR [ebx]
            code = string("\x66\x03\x1B", 3);
            sym.mem->write(0x1090, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1090+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1090, 1);
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0x5c8a, "ArchX86: failed to disassembly and/or execute ADD");
            // add ecx, DWORD PTR [ecx]
            code = string("\x03\x09", 2);
            sym.mem->write(0x1100, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1100+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1100, 1);
            nb += _assert(  sym.regs->concretize(X86_ECX) == 0x12345c8a, "ArchX86: failed to disassembly and/or execute ADD");
            /* ADD MEM, IMM */
            sym.mem->new_segment(0x2000,0x3000);
            sym.regs->set(X86_EAX, exprcst(32, 0x2000));
            sym.regs->set(X86_EBX, exprcst(32, 0x2010));
            sym.regs->set(X86_ECX, exprcst(32, 0x12345678));
            sym.regs->set(X86_EDX, exprcst(32, 0x12345678));
            
            // add BYTE PTR [eax], 0x42
            code = string("\x80\x00\x42",3);
            sym.mem->write(0x1110, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1110+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1110, 1);
            nb += _assert(  sym.mem->read(0x2000, 1)->concretize(sym.vars) == 0x42,
                            "ArchX86: failed to disassembly and/or execute ADD");
            // add DWORD PTR [ebx], 0xffffffff
            code = string("\x83\x03\xFF", 3);
            sym.mem->write(0x1120, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1120+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1120, 1);
            nb += _assert(  sym.mem->read(0x2010, 4)->eq(exprcst(32, 0xffffffff)),
                            "ArchX86: failed to disassembly and/or execute ADD");
            /* ADD MEM, REG */
            sym.regs->set(X86_EAX, exprcst(32, 0x2100));
            sym.regs->set(X86_EBX, exprcst(32, 0x2110));
            sym.regs->set(X86_ECX, exprcst(32, 0x12345678));
            sym.regs->set(X86_EDX, exprcst(32, 0x12345678));
            // add BYTE PTR [eax], cl
            code = string("\x00\x08", 2);
            sym.mem->write(0x1130, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1130+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1130, 1);
            nb += _assert(  sym.mem->read(0x2100, 1)->eq(exprcst(8, 0x78)),
                            "ArchX86: failed to disassembly and/or execute ADD");
            // add DWORD PTR [ebx], edi
            sym.regs->set(X86_EDI, exprcst(32, 0x10));
            sym.mem->write(0x2110, exprcst(32, 0x12345678), sym.vars);
            code = string("\x01\x3B", 2); 
            sym.mem->write(0x1140, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1140+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1140, 1);
            nb += _assert(  sym.mem->read(0x2110, 4)->concretize(sym.vars) == 0x12345688,
                            "ArchX86: failed to disassembly and/or execute ADD");
            // 0x10 + 0x20
            sym.regs->set(X86_EAX, exprcst(32, 0x10));
            sym.regs->set(X86_EBX, exprcst(32, 0x20));
            code = string("\x01\xD8", 2); // add eax, ebx
            sym.mem->write(0x1150, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1150+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1150, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            // -1 + -3
            sym.regs->set(X86_EAX, exprcst(32, -1));
            sym.regs->set(X86_EBX, exprcst(32, -3));
            code = string("\x01\xD8", 2); // add eax, ebx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            // 16 + 56
            sym.regs->set(X86_EAX, exprcst(32, 16));
            sym.regs->set(X86_EBX, exprcst(32, 56));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
                            
            // 0x7fff0000 + 0x0f000000
            sym.regs->set(X86_EAX, exprcst(32, 0x7fff0000));
            sym.regs->set(X86_EBX, exprcst(32, 0x0f000000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
                            
            // 0x7fff0000 + 0x7000001f
            sym.regs->set(X86_EAX, exprcst(32, 0x7fff0000));
            sym.regs->set(X86_EBX, exprcst(32, 0x0f00001f));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            // 0x8fff0000 + 0x80000001
            sym.regs->set(X86_EAX, exprcst(32, 0x8fff0000));
            sym.regs->set(X86_EBX, exprcst(32, 0x80000001));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            
            // 0xffffffff + 0xfffffffe
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_EBX, exprcst(32, 0xfffffffe));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
                            
            // 0xffffff00 + 0x00000100
            sym.regs->set(X86_EAX, exprcst(32, 0xffffff00));
            sym.regs->set(X86_EBX, exprcst(32, 0x00000100));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADD");
            return nb;
        }
        
        
        unsigned int disass_adc(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);

            /* Test ADC with carry set */
            // 0x10 + 0x20
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x10));
            sym.regs->set(X86_EBX, exprcst(32, 0x20));
            code = string("\x11\xD8", 2); // adc eax, ebx
            sym.mem->write(0x1150, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1150+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1150, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x31)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            // -1 + -3
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, -1));
            sym.regs->set(X86_EBX, exprcst(32, -3));
            code = string("\x11\xD8", 2); // adc eax, ebx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e").c_str(), 2);
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, -3)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            // 16 + 56
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 16));
            sym.regs->set(X86_EBX, exprcst(32, 56));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 73)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            
            // 0x7fff0000 + 0x0f000000
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x7fff0000));
            sym.regs->set(X86_EBX, exprcst(32, 0x0f000000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x8eff0001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            // 0x7fff0000 + 0x7000001f
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x7fff0000));
            sym.regs->set(X86_EBX, exprcst(32, 0x0f00001f));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x8eff0020)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            
            // 0x8fff0000 + 0x80000001
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x8fff0000));
            sym.regs->set(X86_EBX, exprcst(32, 0x80000001));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0fff0002)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            
            // 0xffffffff + 0xfffffffe
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_EBX, exprcst(32, 0xfffffffe));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xfffffffe)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
                            
            // 0xffffff00 + 0x00000100
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0xffffff00));
            sym.regs->set(X86_EBX, exprcst(32, 0x00000100));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADC");
            return nb;
        }
        
        unsigned int disass_aaa(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\x37", 1); // aaa
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Test with AF set */
            // AL = 7 
            sym.regs->set(X86_AF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0b0111));
            sym.execute_from(0x1000, 1);
            
            
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0b100001101)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            // AL = 7 
            sym.regs->set(X86_AF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0b1101));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0b100000011)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
                            
            // AL = 3 
            sym.regs->set(X86_AF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0b0011));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0b100001001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            
             /* Test when the 4 LSB are > 9 and AF not set*/
            // AL = 10 
            sym.regs->set(X86_AF, exprcst(32, 0)); // Clear carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0b1010));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0b100000000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            // AL = 15 
            sym.regs->set(X86_AF, exprcst(32, 0)); // Clear carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0b1111));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0b100000101)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAA");
            
             /* Test when the 4 LSB are <= 9 and AF not set*/
            // AL = 0b11110000
            sym.regs->set(X86_AF, exprcst(32, 0)); // Clear carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0b11110000));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAA");
            // AL = 0x59
            sym.regs->set(X86_AF, exprcst(32, 0)); // Clear carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x59));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x09)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAA");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAA");
            
            return nb;
        }
        
        unsigned int disass_adcx(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\x66\x0F\x38\xF6\xC3", 5); // adcx eax, ebx
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // 0x10 + 0x20 with CF set
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x10));
            sym.regs->set(X86_EBX, exprcst(32, 0x20));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x31)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            
            // 0x10 + 0x20 with CF cleared
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_EAX, exprcst(32, 0x10));
            sym.regs->set(X86_EBX, exprcst(32, 0x20));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x30)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            
                            
            // 0xffffffff + 0xfffffffd with carry 
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_EBX, exprcst(32, 0xfffffffd));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xfffffffd)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADCX");
                            
            // 0xffffffff + 0xfffffffd with CF cleared 
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_EBX, exprcst(32, 0xfffffffd));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xfffffffc)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            
            // 0x7fff0000 + 0x0f000000
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x7fff0000));
            sym.regs->set(X86_EBX, exprcst(32, 0x0f000000));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x8eff0001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            
            // 0x8fff0000 + 0x80000001
            sym.regs->set(X86_CF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x8fff0000));
            sym.regs->set(X86_EBX, exprcst(32, 0x80000001));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0fff0002)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADCX");
                            
            // 0xffffff00 + 0x00000100
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_EAX, exprcst(32, 0xffffff00));
            sym.regs->set(X86_EBX, exprcst(32, 0x00000100));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ADCX");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ADCX");
            return nb;
        }
        
        unsigned int disass_aad(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\xD5\x0A", 2); // aad
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // AX = 7 
            sym.regs->set(X86_EAX, exprcst(32, 7));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 7)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
                            
            // AX =  0x107
            sym.regs->set(X86_EAX, exprcst(32, 0x107));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 17)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
                            
            // AX =  0xd01
            sym.regs->set(X86_EAX, exprcst(32, 0xd01));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x83)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            
            // AX =  0x8000
            sym.regs->set(X86_EAX, exprcst(32, 0x8000));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            
            // AX =  0xc88
            sym.regs->set(X86_EAX, exprcst(32, 0xc88));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAD");
            
            return nb;
        }
        
        unsigned int disass_aam(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\xD4\x0A", 2); // aam
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // AX = 7
            sym.regs->set(X86_EAX, exprcst(32, 7));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 7)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
                            
            // AX =  0x107
            sym.regs->set(X86_EAX, exprcst(32, 0x107));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 7)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
                            
            // AX =  33
            sym.regs->set(X86_EAX, exprcst(32, 33));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0303)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
            
            // AX =  89
            sym.regs->set(X86_EAX, exprcst(32, 89));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0809)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
            
            // AX =  123
            sym.regs->set(X86_EAX, exprcst(32, 123));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xc03)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
                            
            // AX =  0xa
            sym.regs->set(X86_EAX, exprcst(32, 0xa));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x100)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAM");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAM");
            
            return nb;
        }
        
        
        unsigned int disass_aas(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\x3F", 1); // aas
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Test with AF set */
            // AX = 0x107 
            sym.regs->set(X86_AF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x107));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            
            // AX = 0x007 
            sym.regs->set(X86_AF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x007));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xff01)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
                            
            // AL = 0x203 
            sym.regs->set(X86_AF, exprcst(32, 1)); // Set carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x203));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10d)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            
             /* Test when the 4 LSB are > 9 and AF not set*/
            // AX = 0x30a 
            sym.regs->set(X86_AF, exprcst(32, 0)); // Clear carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x30a));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x204)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            // AL = 0x00f 
            sym.regs->set(X86_AF, exprcst(32, 0)); // Clear carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x00f));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xff09)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AAS");
            
             /* Test when the 4 LSB are <= 9 and AF not set*/
            // AL = 0b11110000
            sym.regs->set(X86_AF, exprcst(32, 0)); // Clear carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0b11110000));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            // AL = 0x59
            sym.regs->set(X86_AF, exprcst(32, 0)); // Clear carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x59));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x09)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
                            
            // AX = 0x259
            sym.regs->set(X86_AF, exprcst(32, 0)); // Clear carry flag
            sym.regs->set(X86_EAX, exprcst(32, 0x259));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x209)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AAS");
            return nb;
        }
                
        unsigned int disass_and(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            // On 32 bits
            // 678 & 0xfff.....
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_EBX, exprcst(32, 678));
            code = string("\x21\xD8", 2); // and eax, ebx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            
            // 0xfffff000 & 0x000fffff
            sym.regs->set(X86_EAX, exprcst(32, 0xfffff000));
            sym.regs->set(X86_EBX, exprcst(32, 0x000fffff));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x000ff000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
                            
            // 0x8000000 + 0x80000001
            sym.regs->set(X86_EAX, exprcst(32, 0x80000001));
            sym.regs->set(X86_EBX, exprcst(32, 0x80000001));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x80000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
                            
            // On 16 bits... 
            // 0xa00000f0 & 0x0b0000ff
            sym.regs->set(X86_EAX, exprcst(32, 0xa00000f0));
            sym.regs->set(X86_EBX, exprcst(32, 0x0b0000ff));
            code = string("\x66\x21\xD8", 3); // and ax, bx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xa00000f0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            
            // 0xab00000f & 0xba0000f0
            sym.regs->set(X86_EAX, exprcst(32, 0xab00000f));
            sym.regs->set(X86_EBX, exprcst(32, 0xba0000f0));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xab000000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute AND");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute AND");
            return nb;
        }
        
        unsigned int disass_andn(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\xC4\xE2\x78\xF2\xC3", 5); // andn eax, eax, ebx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0xfff..... n& 678
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_EBX, exprcst(32, 678));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            
            // 0xfffff000 n& 0x000fffff
            sym.regs->set(X86_EAX, exprcst(32, 0xfffff000));
            sym.regs->set(X86_EBX, exprcst(32, 0x000fffff));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x00000fff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
                            
            // 0x7ffffffe n& 0x80000001
            sym.regs->set(X86_EAX, exprcst(32, 0x7ffffffe));
            sym.regs->set(X86_EBX, exprcst(32, 0x80000001));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x80000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute ANDN");
            return nb;
        }
        
        unsigned int disass_blsi(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\xC4\xE2\x78\xF3\xDB", 5); // blsi eax, ebx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0x00001010
            sym.regs->set(X86_EBX, exprcst(32,0x00001010));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            
            // 0xffffff01
            sym.regs->set(X86_EBX, exprcst(32, 0xffffff01));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
                            
            // 0
            sym.regs->set(X86_EBX, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
                            
            // 0x80000000
            sym.regs->set(X86_EBX, exprcst(32, 0x80000000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x80000000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSI");
            return nb;
        }
        
        unsigned int disass_blsmsk(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\xC4\xE2\x78\xF3\xD3", 5); // blsmsk eax, ebx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0x00001010 : 0x00000010
            sym.regs->set(X86_EAX, exprcst(32,0x00001010));
            sym.regs->set(X86_EBX, exprcst(32,0x00000010));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x001f)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            
            // 0x00001010 : 0x00100000
            sym.regs->set(X86_EAX, exprcst(32,0x00001010));
            sym.regs->set(X86_EBX, exprcst(32,0x00100000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x001fffff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
                            
            // 0 : 0
            sym.regs->set(X86_EAX, exprcst(32, 0));
            sym.regs->set(X86_EBX, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xffffffff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
                            
            // 0xffffffff : 0x00200000
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_EBX, exprcst(32, 0x00200000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x003fffff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            return nb;
        }
        
        unsigned int disass_blsr(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            code = string("\xC4\xE2\x78\xF3\xCB", 5); // blsr eax, ebx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // On 32 bits
            //  0x000000f0
            sym.regs->set(X86_EBX, exprcst(32,0x000000f0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xe0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            
            // 0x00100000
            sym.regs->set(X86_EBX, exprcst(32,0x00100000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
                            
            // 0
            sym.regs->set(X86_EBX, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
                            
            // 0xffffffff
            sym.regs->set(X86_EBX, exprcst(32, 0xffffffff));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xfffffffe)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BLSMSK");
            return nb;
        }
        
        unsigned int disass_bsf(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 16 bits */
            code = string("\x66\x0F\xBC\xC3", 4); // bsf ax, bx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bsf 0x1100
            sym.regs->set(X86_EBX, exprcst(32,0x00001100));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 8)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
            // bsf 0x0
            sym.regs->set(X86_EBX, exprcst(32,0x0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BSF");
            // bsf 0x8000
            sym.regs->set(X86_EBX, exprcst(32,0x8000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 15)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
            
            // bsf 0x10000
            sym.regs->set(X86_EBX, exprcst(32,0x10000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BSF");
            
            /* On 32 bits */
            code = string("\x0F\xBC\xC3", 3); // bsf eax, ebx
            sym.mem->write(0x1200, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bsf 0x1100
            sym.regs->set(X86_EBX, exprcst(32,0x00001100));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 8)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
                            
                            
            // bsf 0x80000000
            sym.regs->set(X86_EBX, exprcst(32,0x80000000));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 31)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
                            
            // bsf 0
            sym.regs->set(X86_EBX, exprcst(32,0));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BSF");         
            return nb;
        }
        
        unsigned int disass_bsr(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 16 bits */
            code = string("\x66\x0F\xBD\xC3", 4); // bsr ax, bx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bsf 0x1100
            sym.regs->set(X86_EBX, exprcst(16,0x00001100));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 12)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
            // bsf 0x0
            sym.regs->set(X86_EBX, exprcst(16,0x0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BSF");
            // bsf 0x8000
            sym.regs->set(X86_EBX, exprcst(16,0x8000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 15)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
            
            // bsf 0x10000
            sym.regs->set(X86_EBX, exprcst(16,0x10000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BSF");
            
            /* On 32 bits */
            code = string("\x0F\xBD\xC3", 3); // bsr eax, ebx
            sym.mem->write(0x1200, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // bsf 0x1100
            sym.regs->set(X86_EBX, exprcst(32,0x00001100));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 12)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
                            
                            
            // bsf 0x80000000
            sym.regs->set(X86_EBX, exprcst(32,0x80000000));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 31)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSF");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute BSF");
                            
            // bsf 0
            sym.regs->set(X86_EBX, exprcst(32,0));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute BSF");         
            return nb;
        }
        
        unsigned int disass_bswap(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 32 bits */
            code = string("\x0F\xC8", 2); // bswap eax
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bswap 0x12345678
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.execute_from(0x1160, 1);
            
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x78563412)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSWAP");
                            
            // bswap 0x00111100
            sym.regs->set(X86_EAX, exprcst(32,0x00111100));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x00111100)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSWAP");
             
            // On vars
            Expr eax = exprvar(32, sym.regs->make_var(X86_EAX, "eax"));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 
                (concat(concat(concat(extract(eax, 7,0),
                               extract(eax, 15, 8)),
                               extract(eax,23,16)),
                               extract(eax, 31, 24)))->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BSWAP");
            return nb;
        }
    
    
        unsigned int disass_bt(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 16 bits */
            code = string("\x66\x0F\xA3\xD8", 4); // bt ax, bx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bit(0x8, 3)
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,3));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BT");

            // bit(0x8, 4)
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,4));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            // bit(0x8, 19) --> 19 = 3%16
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,19));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BT");
            
            // from memory
            code = string("\x66\x0F\xA3\x18", 4); // bt word ptr [eax], bx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1700, exprcst(32, 0xffffffff), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32,0x1701));
            sym.regs->set(X86_EBX, exprcst(32,8));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            /* On 32 bits */
            code = string("\x0F\xA3\xD8", 3); // bt eax, ebx
            sym.mem->write(0x1180, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bit(0x10000000, 28)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,28));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            // bit(0x10000000, 29)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,29));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            // bit(0x10000000, 60)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,60));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            /* With an imm */
            code = string("\x0F\xBA\xE0\x0D", 4); // bt eax, 13
            sym.mem->write(0x1190, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x2000));
            sym.regs->set(X86_EBX, exprcst(32,13));
            sym.execute_from(0x1190, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BT");
                            
            code = string("\x0F\xBA\xE0\x0C", 4); // bt eax, 12
            sym.mem->write(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x2000));
            sym.regs->set(X86_EBX, exprcst(32,13));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BT");
            return nb;
        }
        
        unsigned int disass_bts(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 16 bits */
            code = string("\x66\x0F\xAB\xD8", 4); // bts ax, bx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            // bit(0x8, 3)
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,3));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x8)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");

            // bit(0x8, 4)
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,4));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x18)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x8, 19) --> 19 = 3%16
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,19));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            
            // from memory
            code = string("\x66\x0F\xAB\x18", 4); // bts word ptr [eax], bx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1700, exprcst(16, 0xfffe), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.regs->set(X86_EBX, exprcst(32,0));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 2)->concretize(sym.vars) == exprcst(16 , 0xffff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            /* On 32 bits */
            code = string("\x0F\xAB\xD8", 3); // bts eax, ebx
             sym.mem->write(0x1180, (uint8_t*)code.c_str(), 3);
             sym.mem->write(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // bit(0x10000000, 28)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,28));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x10000000, 29)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,29));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x30000000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x10000000, 60)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,60));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            /* With an imm */
            code = string("\x0F\xBA\xE8\x0D", 4); // bts eax, 13
            sym.mem->write(0x1190, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x2000));
            sym.execute_from(0x1190, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x2000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            code = string("\x0F\xBA\xE8\x0C", 4); // bts eax, 12
            sym.mem->write(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x2000));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x3000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            return nb;
        }
        
        unsigned int disass_btc(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 16 bits */
            code = string("\x66\x0F\xBB\xD8", 4); // btc ax, bx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // bit(0x8, 3)
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,3));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");

            // bit(0x8, 4)
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,4));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x18)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x8, 19) --> 19 = 3%16
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,19));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            
            // from memory
            code = string("\x66\x0F\xBB\x18", 4); // btc word ptr [eax], bx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1700, exprcst(16, 0xfffe), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.regs->set(X86_EBX, exprcst(32,0));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 2)->concretize(sym.vars) == exprcst(16 , 0xffff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            /* On 32 bits */
            code = string("\x0F\xBB\xD8", 3); // btc eax, ebx
            sym.mem->write(0x1180, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
             
            // bit(0x10000000, 28)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,28));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x10000000, 29)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,29));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x30000000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x10000000, 60)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,60));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            /* With an imm */
            code = string("\x0F\xBA\xF8\x0D", 4); // btc eax, 13
            sym.mem->write(0x1190, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x2000));
            sym.execute_from(0x1190, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            code = string("\x0F\xBA\xF8\x0C", 4); // btc eax, 12
            sym.mem->write(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x2000));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x3000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            return nb;
        }
    
        unsigned int disass_btr(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 16 bits */
            code = string("\x66\x0F\xB3\xD8", 4); // btr ax, bx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            // bit(0x8, 3)
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,3));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");

            // bit(0x8, 4)
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,4));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x8)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x8, 19) --> 19 = 3%16
            sym.regs->set(X86_EAX, exprcst(32,0x8));
            sym.regs->set(X86_EBX, exprcst(32,19));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            
            // from memory
            code = string("\x66\x0F\xB3\x18", 4); // btr word ptr [eax], bx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1700, exprcst(16, 0xffff), sym.vars);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.regs->set(X86_EBX, exprcst(32,0));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 2)->concretize(sym.vars) == exprcst(16 , 0xfffe)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            /* On 32 bits */
            code = string("\x0F\xB3\xD8", 3); // btr eax, ebx
            sym.mem->write(0x1180, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2); 
             
            // bit(0x10000000, 28)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,28));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x10000000, 29)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,29));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            // bit(0x10000000, 60)
            sym.regs->set(X86_EAX, exprcst(32,0x10000000));
            sym.regs->set(X86_EBX, exprcst(32,60));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            /* With an imm */
            code = string("\x0F\xBA\xF0\x0D", 4); // bts eax, 13
            sym.mem->write(0x1190, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x2000));
            sym.execute_from(0x1190, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
                            
            code = string("\x0F\xBA\xF0\x0C", 4); // bts eax, 12
            sym.mem->write(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x2000));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x2000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BTS");
            return nb;
        }
        
        unsigned int disass_bzhi(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 32 bits */
            code = string("\xC4\xE2\x70\xF5\xC3", 5); // bzhi eax, ebx, ecx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Normal */
            sym.regs->set(X86_EAX, exprcst(32,0x0));
            sym.regs->set(X86_EBX, exprcst(32,0xff0f000f));
            sym.regs->set(X86_ECX, exprcst(32,8));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xf)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");

            /* Index on more than 8 bits */
            sym.regs->set(X86_EAX, exprcst(32,0x0));
            sym.regs->set(X86_EBX, exprcst(32,0xff0f000f));
            sym.regs->set(X86_ECX, exprcst(32,0x1008));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xf)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
                            
            /* Index on more than 8 bits */
            sym.regs->set(X86_EAX, exprcst(32,0x0));
            sym.regs->set(X86_EBX, exprcst(32,0xff0f000f));
            sym.regs->set(X86_ECX, exprcst(32,0x1008));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xf)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
                            
            /* Index bigger than operand size */
            sym.regs->set(X86_EAX, exprcst(32,0x0));
            sym.regs->set(X86_EBX, exprcst(32,0xff0f000f));
            sym.regs->set(X86_ECX, exprcst(32,33));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == sym.regs->get(X86_EBX)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
                            
            /* Index zero */
            sym.regs->set(X86_EAX, exprcst(32,0x12345));
            sym.regs->set(X86_EBX, exprcst(32,0xff0f000f));
            sym.regs->set(X86_ECX, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32,0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute BZHI");
                            
            return nb;
        }
    
        unsigned int disass_cbw(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x66\x98", 2); // cbw
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x10));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CBW");

            sym.regs->set(X86_EAX, exprcst(32,0x7f));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x7f)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CBW");
                            
            sym.regs->set(X86_EAX, exprcst(32,0x80));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xff80)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CBW");
                            
            sym.regs->set(X86_EAX, exprcst(32,0x10000106));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000006)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CBW");

            return nb;
        }
        
        unsigned int disass_cwd(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x66\x99", 2); // cwd
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x10));
            sym.regs->set(X86_EDX, exprcst(32,0x1234));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWD");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWD");

            sym.regs->set(X86_EAX, exprcst(32,0x7f98));
            sym.regs->set(X86_EDX, exprcst(32,0x1234));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x7f98)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWD");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWD");
                            
            sym.regs->set(X86_EAX, exprcst(32,0x8000));
            sym.regs->set(X86_EDX, exprcst(32,0x1234));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x8000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWD");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0xffff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWD");
                            
            sym.regs->set(X86_EAX, exprcst(32,0x10000106));
            sym.regs->set(X86_EDX, exprcst(32,0x1234));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000106)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWD");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWD");

            return nb;
        }
        
        unsigned int disass_cwde(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x98", 1); // cwde
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x10));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWDE");

            sym.regs->set(X86_EAX, exprcst(32,0x7f98));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x7f98)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWDE");
                            
            sym.regs->set(X86_EAX, exprcst(32,0x8000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xffff8000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWDE");
                            
            sym.regs->set(X86_EAX, exprcst(32,0x10000106));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x00000106)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CWDE");

            return nb;
        }
        
        unsigned int disass_cdq(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x99", 1); // cdq
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x10));
            sym.regs->set(X86_EDX, exprcst(32,0x12345678));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CDQ");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CDQ");

            sym.regs->set(X86_EAX, exprcst(32,0x7f980000));
            sym.regs->set(X86_EDX, exprcst(32,0x12345678));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x7f980000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CDQ");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0x0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CDQ");
                            
            sym.regs->set(X86_EAX, exprcst(32,0x80000001));
            sym.regs->set(X86_EDX, exprcst(32,0x12345678));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x80000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CDQ");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0xffffffff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CDQ");

            sym.regs->set(X86_EAX, exprcst(32,0x10000106));
            sym.regs->set(X86_EDX, exprcst(32,0x12345678));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000106)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CDQ");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CDQ");

            return nb;
        }
        
        unsigned int disass_clc(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\xF8", 1); // clc
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_CF, exprcst(32,0x1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CLC");
                            
            sym.regs->set(X86_CF, exprcst(32,0x0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CLC");
            return nb;
        }
        
        unsigned int disass_cld(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\xFC", 1); // cld
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_DF, exprcst(32,0x1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_DF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CLD");
                            
            sym.regs->set(X86_DF, exprcst(32,0x0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_DF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CLD");
            return nb;
        }
        
        unsigned int disass_cli(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\xFA", 1); // cli
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_IF, exprcst(32,0x1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_IF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CLI");
                            
            sym.regs->set(X86_IF, exprcst(32,0x0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_IF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CLI");
            return nb;
        }
        
        unsigned int disass_cmc(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\xF5", 1); // cmc
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_CF, exprcst(32,0x1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMC");
                            
            sym.regs->set(X86_CF, exprcst(32,0x0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMC");
            return nb;
        }
        
        unsigned int disass_cmova(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With zf == 0 && cf == 0 */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,0));
            
            /* 16 bits */
            code = string("\x66\x0F\x47\xC3", 4); // cmova ax, bx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
            
            /* 32 bits */
            code = string("\x0F\x47\xC3", 3); // cmova eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
                            
            /* With condition not verified */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
                            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVA");
            return nb;
        }
        
        unsigned int disass_cmovae(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_CF, exprcst(32,0));
            code = string("\x0F\x43\xC3", 3); // cmovae eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVAE");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVAE");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVAE");
                            
            /* With condition not verified */
            sym.regs->set(X86_CF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVAE");
                            
            return nb;
        }
        
        unsigned int disass_cmovb(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_CF, exprcst(32,1));
            code = string("\x0F\x42\xC3", 3); // cmovb eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVB");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVB");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVB");
                            
            /* With condition not verified */
            sym.regs->set(X86_CF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVB");
                            
            return nb;
        }
        
        unsigned int disass_cmovbe(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,0));
            code = string("\x0F\x46\xC3", 3); // cmovbe eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVBE");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVBE");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVBE");
                            
            /* With condition not verified */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVBE");
            
            return nb;
        }
        
        unsigned int disass_cmove(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_ZF, exprcst(32,1));
            code = string("\x0F\x44\xC3", 3); // cmove eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVE");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVE");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVE");
                            
            /* With condition not verified */
            sym.regs->set(X86_ZF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVE");
                            
            return nb;
        }
         
        unsigned int disass_cmovg(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            code = string("\x0F\x4F\xC3", 3); // cmovg eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
                            
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
                            
            /* With condition not verified */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
                            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
                            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVG");
            
            return nb;
        }
        
        unsigned int disass_cmovge(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            code = string("\x0F\x4D\xC3", 3); // cmovge eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
            
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
                            
            
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
                            
            /* With condition not verified */
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
                            
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVGE");
            
            return nb;
        }
        
        unsigned int disass_cmovl(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            code = string("\x0F\x4C\xC3", 3); // cmovl eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVL");
            
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVL");
                            
            
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVL");
                            
            /* With condition not verified */
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVL");
                            
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVL");
            
            return nb;
        }
         
        unsigned int disass_cmovle(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            code = string("\x0F\x4E\xC3", 3); // cmovle eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);

            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
                            
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
                            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
                            
            /* With condition not verified */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
                            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVLE");
            
            return nb;
        } 
     
        unsigned int disass_cmovne(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_ZF, exprcst(32,0));
            code = string("\x0F\x45\xC3", 3); // cmovne eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNE");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNE");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNE");
                            
            /* With condition not verified */
            sym.regs->set(X86_ZF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNE");
                            
            return nb;
        }
        
        unsigned int disass_cmovno(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_OF, exprcst(32,0));
            code = string("\x0F\x41\xC3", 3); // cmovno eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNO");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNO");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNO");
                            
            /* With condition not verified */
            sym.regs->set(X86_OF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNO");
                            
            return nb;
        }
        
        unsigned int disass_cmovnp(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_PF, exprcst(32,0));
            code = string("\x0F\x4B\xC3", 3); // cmovnp eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNP");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNP");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNP");
                            
            /* With condition not verified */
            sym.regs->set(X86_PF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNP");
                            
            return nb;
        }
         
        unsigned int disass_cmovns(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_SF, exprcst(32,0));
            code = string("\x0F\x49\xC3", 3); // cmovns eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNS");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNS");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNS");
                            
            /* With condition not verified */
            sym.regs->set(X86_SF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVNS");
                            
            return nb;
        }
        
        unsigned int disass_cmovo(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_OF, exprcst(32,1));
            code = string("\x0F\x40\xC3", 3); // cmovo eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVO");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVO");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVO");
                            
            /* With condition not verified */
            sym.regs->set(X86_OF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVO");
                            
            return nb;
        }
        
        unsigned int disass_cmovp(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_PF, exprcst(32,1));
            code = string("\x0F\x4A\xC3", 3); // cmovp eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            /* With condition not verified */
            sym.regs->set(X86_PF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            return nb;
        }
        
        unsigned int disass_cmovs(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* Condition verified */
            sym.regs->set(X86_SF, exprcst(32,1));
            code = string("\x0F\x48\xC3", 3); // cmovs eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x10000001));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x12340000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12340000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            /* With condition not verified */
            sym.regs->set(X86_SF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x12345678)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMOVP");
                            
            return nb;
        }
        
        unsigned int disass_cmp(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            /* cmp reg, imm */
            code = string("\x3C\x0f", 2); // cmp al(ff), f
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0xff));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
                            
            sym.regs->set(X86_EAX, exprcst(32,0x10ff));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
                            
            code = string("\x3C\x81", 2); // cmp al(0x80), 0x81
            sym.mem->write(0x1190, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x80));
            sym.execute_from(0x1190, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            
            
            code = string("\x66\x3d\xff\x00", 4); // cmp ax, ff
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1ffff));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
                            
            code = string("\x66\x83\xF8\x01", 4); // cmp ax, 1
            sym.mem->write(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0xfa000009));
            sym.execute_from(0x1200, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            
            
            code = string("\x83\xF8\x48", 3); // cmp eax, 0x48
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32,0xff000000));
            sym.execute_from(0x1010, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            
            
            code = string("\x3D\x34\x12\x00\x00", 5); // cmp eax, 0x1234
            sym.mem->write(0x1020, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32,0x10001235));
            sym.execute_from(0x1020, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            
            
            code = string("\x3D\x00\x00\x00\xFF", 5); // cmp eax, 0xff000000
            sym.mem->write(0x1030, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32,0xffff0000));
            sym.execute_from(0x1030, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
                            
            code = string("\x3D\x00\x00\xFF\xFF", 5); // cmp eax, 0xffff0000
            sym.mem->write(0x1040, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32,0xff000000));
            sym.execute_from(0x1040, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            
            /* cmp reg,reg */
            code = string("\x38\xFC", 2); // cmp ah, bh
            sym.mem->write(0x1050, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32,0xf800));
            sym.regs->set(X86_EBX, exprcst(32,0x7900));
            sym.execute_from(0x1050, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
                            
            /* cmp imm, mem */
            code = string("\x80\x3d\x00\x17\x00\x00\x03", 7); // cmp byte ptr [0x1700], 0x3 
            sym.mem->write(0x1080, (uint8_t*)code.c_str(), 7);
            sym.mem->write(0x1080+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0x01f62303), sym.vars);
            sym.execute_from(0x1080, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            
            /* cmp reg,mem */
            code = string("\x3B\x03", 2); // cmp eax, dword ptr [ebx] 
            sym.mem->write(0x1060, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0xAAAA), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32,0xAAAA));
            sym.regs->set(X86_EBX, exprcst(32,0x1700));
            sym.execute_from(0x1060, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
                            
            /* cmp mem,reg */
            code = string("\x39\x18", 2); // cmp dword ptr [eax], ebx 
            sym.mem->write(0x1070, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1070+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0xffffffff), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32,0x1800));
            sym.regs->set(X86_EBX, exprcst(32,0xffffffff));
            sym.execute_from(0x1070, 1);
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMP");
            
            return nb;
        }
        
        unsigned int disass_cmpsb(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\xA6", 1); // cmpsb
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1000, exprcst(8, 0xff), sym.vars);
            sym.mem->write(0x1500, exprcst(8, 0xf), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 1));
            sym.regs->set(X86_ESI, exprcst(32,0x1000));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ESI)->concretize(sym.vars) == exprcst(32, 0xfff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x14ff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            
            sym.mem->write(0x1000, exprcst(8, 0x1), sym.vars);
            sym.mem->write(0x1500, exprcst(8, 0xff), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.regs->set(X86_ESI, exprcst(32,0x1000));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ESI)->concretize(sym.vars) == exprcst(32, 0x1001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x1501)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSB");
            
            return nb;
        }
        
        unsigned int disass_cmpsd(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\xA7", 1); // cmpsd
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1000, exprcst(32, 0xAAAA), sym.vars);
            sym.mem->write(0x1500, exprcst(32, 0xAAAA), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 1));
            sym.regs->set(X86_ESI, exprcst(32,0x1000));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ESI)->concretize(sym.vars) == exprcst(32, 0xffc)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x14fc)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            
            sym.mem->write(0x1000, exprcst(32, 0x1234), sym.vars);
            sym.mem->write(0x1500, exprcst(32, 0x1235), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.regs->set(X86_ESI, exprcst(32,0x1000));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ESI)->concretize(sym.vars) == exprcst(32, 0x1004)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x1504)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSD");
            
            return nb;
        }
        
        unsigned int disass_cmpsq(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\x48\xA7", 2); // cmpsq
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1000, exprcst(16, 0xAAAA000011110001), sym.vars);
            sym.mem->write(0x1500, exprcst(16, 0xAAAA000011110000), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 1));
            sym.regs->set(X86_ESI, exprcst(32,0x1000));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ESI)->concretize(sym.vars) == exprcst(32, 0xff8)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x14f8)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            
            sym.mem->write(0x1000, exprcst(32, 0x1000000000001234), sym.vars);
            sym.mem->write(0x1500, exprcst(32, 0x1000000000001235), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.regs->set(X86_ESI, exprcst(32,0x1000));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ESI)->concretize(sym.vars) == exprcst(32, 0x1008)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x1508)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            
            return nb;
        }
        
        unsigned int disass_cmpsw(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\x66\xA7", 2); // cmpsw
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1000, exprcst(16, 0xAAAA), sym.vars);
            sym.mem->write(0x1500, exprcst(16, 0xAAAA), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 1));
            sym.regs->set(X86_ESI, exprcst(32,0x1000));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ESI)->concretize(sym.vars) == exprcst(32, 0xffe)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x14fe)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            
            sym.mem->write(0x1000, exprcst(32, 0x1234), sym.vars);
            sym.mem->write(0x1500, exprcst(32, 0x1235), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.regs->set(X86_ESI, exprcst(32,0x1000));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_ESI)->concretize(sym.vars) == exprcst(32, 0x1002)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x1502)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPSW");
            
            return nb;
        }
        
        unsigned int disass_cmpxchg(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            /* On 8 bits */
            code = string("\x0F\xB0\xEF", 3); // cmpxchg bh, ch
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x21));
            sym.regs->set(X86_EBX, exprcst(32,0x2100));
            sym.regs->set(X86_ECX, exprcst(32,0x4200));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x21)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_EBX)->concretize(sym.vars) == exprcst(32, 0x4200)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_ECX)->concretize(sym.vars) == exprcst(32, 0x4200)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            
            /* On 16 bits */
            code = string("\x66\x0F\xB1\x0B", 4); // cmpxchg word ptr [ebx], cx
            sym.mem->write(0x1180, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
        
            sym.mem->write(0x1700, exprcst(16, 0x1111), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32,0x4321));
            sym.regs->set(X86_EBX, exprcst(32,0x1700));
            sym.regs->set(X86_ECX, exprcst(32,0x1000BBBB));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x1111)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_EBX)->concretize(sym.vars) == exprcst(32, 0x1700)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_ECX)->concretize(sym.vars) == exprcst(32, 0x1000BBBB)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute CMPXCHG");
            return nb;
        }
        
        unsigned int disass_dec(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\x48", 1); // dec eax
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_EAX, exprcst(32,0x21));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x20)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            
           sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_EAX, exprcst(32,0xffffff01));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xffffff00)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DEC");
            return nb;
        }
        
        unsigned int disass_div(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 8 bits */
            code = string("\xF6\xF3", 2); // div bl
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x10000015));
            sym.regs->set(X86_EBX, exprcst(32,0x4));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000105)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DIV");
            
            
            /* On 16 bits */
            code = string("\x66\xF7\xF3", 3); // div bx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x10000015));
            sym.regs->set(X86_EBX, exprcst(32,0x4));
            sym.regs->set(X86_EDX, exprcst(32,0x10000000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x10000005)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DIV");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0x10000001)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DIV");
                            
            /* On 32 bits */
            code = string("\xF7\x33", 2); // div dword ptr [ebx]
            sym.mem->write(0x1180, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1700, exprcst(32, 24), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32,243));
            sym.regs->set(X86_EBX, exprcst(32,0x1700));
            sym.regs->set(X86_EDX, exprcst(32,0x11111000));
            sym.execute_from(0x1180, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 10)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DIV");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 3)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute DIV");
            
            return nb;
        }
        
        unsigned int disass_idiv(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* On 8 bits */
            code = string("\xF6\xFB", 2); // idiv bl
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x10000015));
            sym.regs->set(X86_EBX, exprcst(32,-4));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x100001fb)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute IDIV");
            
            
            /* On 16 bits */
            code = string("\x66\xF7\xFB", 3); // idiv bx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
			sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,-21));
            sym.regs->set(X86_EBX, exprcst(32,0x4));
            sym.regs->set(X86_EDX, exprcst(32,0x10000000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, -5)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute IDIV");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0x1000ffff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute IDIV");
                            
            sym.regs->set(X86_EAX, exprcst(32,-24));
            sym.regs->set(X86_EBX, exprcst(32,0x67));
            sym.regs->set(X86_EDX, exprcst(32,0x10000000));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xffff0000)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute IDIV");
            nb += _assert(  sym.regs->get(X86_EDX)->concretize(sym.vars) == exprcst(32, 0x1000ffe8)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute IDIV");
            
            return nb;
        }
        
        unsigned int disass_inc(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\x40", 1); // inc eax
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_EAX, exprcst(32,0x22));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0x23)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_EAX, exprcst(32,0xffffff01));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0xffffff02)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute INC");
            return nb;
        }
        
        unsigned int disass_leave(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\xC9", 1); // leave
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 1);sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_ESP, exprcst(32,0x0));
            sym.regs->set(X86_EBP, exprcst(32,0x1704));
            sym.mem->write(0x1704, exprcst(32, 0x1234), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->concretize(X86_ESP) == 0x1708, "ArchX86: failed to disassembly and/or execute LEAVE");
            nb += _assert(  sym.regs->concretize(X86_EBP) == 0x1234, "ArchX86: failed to disassembly and/or execute LEAVE");
            
            return nb;
        }
        
        unsigned int disass_imul(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* One-operand */
            code = string("\xF6\xEB", 2); // imul bl
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,48));
            sym.regs->set(X86_EBX, exprcst(32, 4));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x00C0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 4, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute IMUL");
            
            sym.regs->set(X86_EAX, exprcst(32,0x4200fc));
            sym.regs->set(X86_EBX, exprcst(32, 4));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x42fff0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 4, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute IMUL");
            
            code = string("\x66\xF7\xEB", 3); // imul bx
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,48));
            sym.regs->set(X86_EBX, exprcst(32, 4));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_EDX, exprcst(32, 0x11001234));
            sym.execute_from(0x1010, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0xC0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 4, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EDX) == 0x11000000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1013, "ArchX86: failed to disassembly and/or execute IMUL");
            
            code = string("\xF7\xEB", 2); // imul ebx
            sym.mem->write(0x1020, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,4823424));
            sym.regs->set(X86_EBX, exprcst(32, -423));
            sym.regs->set(X86_EDX, exprcst(32, 0x11001234));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1020, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0xffffffff86635d80, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == -423, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EDX) == -1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1022, "ArchX86: failed to disassembly and/or execute IMUL");
            
            /* Two-operands */
            code = string("\x66\x0F\xAF\xC3", 4); // imul ax, bx
            sym.mem->write(0x1030, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x10000002)); // 2 * -2 
            sym.regs->set(X86_EBX, exprcst(32, 0x1000fffe));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1030, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x1000fffc, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0x1000fffe, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1034, "ArchX86: failed to disassembly and/or execute IMUL");
            
            code = string("\x0F\xAF\xC3", 3); // imul eax, ebx
            sym.mem->write(0x1040, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x2)); // 2 * -2 
            sym.regs->set(X86_EBX, exprcst(32, 0x80000001));
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.execute_from(0x1040, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x00000002, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1043, "ArchX86: failed to disassembly and/or execute IMUL");
            
            /* Three-operands */
            code = string("\x6B\xC3\x07", 3); // imul eax, ebx, 7
            sym.mem->write(0x1050, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32, 0x00100000));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1050, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x00700000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0x00100000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1053, "ArchX86: failed to disassembly and/or execute IMUL");
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1050, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == -7, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == -1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1053, "ArchX86: failed to disassembly and/or execute IMUL");
            
            code = string("\x69\xC3\x00\x00\x00\x10", 6); // imul eax, ebx, 0x10000000
            sym.mem->write(0x1060, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32, 17));
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.execute_from(0x1060, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x10000000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 17, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1066, "ArchX86: failed to disassembly and/or execute IMUL");
            
            sym.regs->set(X86_EAX, exprcst(32,0x12345678));
            sym.regs->set(X86_EBX, exprcst(32, -1));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1060, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0xfffffffff0000000, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == -1, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute IMUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1066, "ArchX86: failed to disassembly and/or execute IMUL");
            
            return nb;
        }
        
        unsigned int disass_ja(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x77\x10", 2); // ja 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JA");
            
            
            
            code = string("\x0f\x87\x50\x34\x12\x00", 6 ); // ja 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2006, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JA");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JA");
            
            return nb;
        }
        
        unsigned int disass_jae(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x73\x10", 2); // jae 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JAE");
            
            /* Not taken */
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JAE");
            
            
            code = string("\x0f\x83\x50\x34\x12\x00", 6 ); // jae 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JAE");
            
            /* Not taken */
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JAE");
            
            
            return nb;
        }
        
        unsigned int disass_jb(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x72\x10", 2); // jb 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JB");
            
            /* Not taken */
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JB");
            
            
            code = string("\x0f\x82\x50\x34\x12\x00", 6 ); // jb 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JB");
            
            /* Not taken */
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JB");
            
            
            return nb;
        }
        
        unsigned int disass_jbe(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x76\x10", 2); // jbe 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JBE");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JBE");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JBE");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JBE");
            
            
            
            code = string("\x0f\x86\x50\x34\x12\x00", 6 ); // jbe 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JBE");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JBE");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JBE");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JBE");
            
            return nb;
        }
        
        unsigned int disass_jcxz(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x67\xe3\x0f", 3); // jcxz 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ECX, exprcst(32,0x12340000));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JCXZ");
            
            /* Not taken */
            sym.regs->set(X86_ECX, exprcst(32,2));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1003, "ArchX86: failed to disassembly and/or execute JCXZ");
            
            return nb;
        }
        
        unsigned int disass_je(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x74\x10", 2); // je 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JE");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JE");
            
            
            code = string("\x0f\x84\x50\x34\x12\x00", 6 ); // je 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JE");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JE");
            
            
            return nb;
        }
        
        unsigned int disass_jecxz(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\xe3\x10", 2); // jecxz 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ECX, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JCXZ");
            
            /* Not taken */
            sym.regs->set(X86_ECX, exprcst(32,0x80000000));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JCXZ");
            
            return nb;
        }
        
        unsigned int disass_jg(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x7f\x10", 2); // jg 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JG");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JG");
            
            
            
            code = string("\x0f\x8f\x50\x34\x12\x00", 6 ); // jg 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JG");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JG");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JG");
            
            return nb;
        }
     
        unsigned int disass_jge(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x7d\x10", 2); // jge 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JGE");
            
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JGE");
            
            /* Not taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JGE");
            
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JGE");
            
            
            
            code = string("\x0f\x8d\x50\x34\x12\x00", 6 ); // jge 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JGE");
            
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JGE");
            
            /* Not taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JGE");
            
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JGE");
            
            return nb;
        }
        
        unsigned int disass_jl(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x7c\x10", 2); // jl 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JL");
            
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JL");
            
            /* Not taken */
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JL");
            
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JL");
            
            
            
            code = string("\x0f\x8c\x50\x34\x12\x00", 6 ); // jl 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JL");
            
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JL");
            
            /* Not taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JL");
            
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JL");
            
            return nb;
        }
        
        unsigned int disass_jle(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x7e\x10", 2); // jle 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JLE");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JLE");
            
            
            
            code = string("\x0f\x8e\x50\x34\x12\x00", 6 ); // jle 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JLE");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JLE");
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JLE");
            
            
            return nb;
        }
        
        unsigned int disass_jne(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x75\x10", 2); // jne 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JNE");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JNE");
            
            
            code = string("\x0f\x85\x50\x34\x12\x00", 6 ); // jne 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JNE");
            
            /* Not taken */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JNE");
            
            
            return nb;
        }
        
        unsigned int disass_jno(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x71\x10", 2); // jno 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JNO");
            
            /* Not taken */
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JNO");
            
            
            code = string("\x0f\x81\x50\x34\x12\x00", 6 ); // jno 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JNO");
            
            /* Not taken */
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JNO");
            
            
            return nb;
        }
        
        unsigned int disass_jnp(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x7b\x10", 2); // jnp 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_PF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JNP");
            
            /* Not taken */
            sym.regs->set(X86_PF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JNP");
            
            
            code = string("\x0f\x8b\x50\x34\x12\x00", 6 ); // jnp 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_PF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JNP");
            
            /* Not taken */
            sym.regs->set(X86_PF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JNP");
            
            
            return nb;
        }
        
        unsigned int disass_jns(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x79\x10", 2); // jns 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JNS");
            
            /* Not taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JNS");
            
            
            code = string("\x0f\x89\x50\x34\x12\x00", 6 ); // jns 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JNS");
            
            /* Not taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JNS");
            
            
            return nb;
        }
        
        unsigned int disass_jo(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x70\x10", 2); // jo 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JO");
            
            /* Not taken */
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JO");
            
            
            code = string("\x0f\x80\x50\x34\x12\x00", 6 ); // jo 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JO");
            
            /* Not taken */
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JO");
            
            
            return nb;
        }
        
        unsigned int disass_jp(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x7a\x10", 2); // jp 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_PF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JP");
            
            /* Not taken */
            sym.regs->set(X86_PF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JP");
            
            
            code = string("\x0f\x8a\x50\x34\x12\x00", 6 ); // jp 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_PF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JP");
            
            /* Not taken */
            sym.regs->set(X86_PF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JP");
            
            
            return nb;
        }
        
        unsigned int disass_js(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\x78\x10", 2); // js 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1002+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JS");
            
            /* Not taken */
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute JS");
            
            
            code = string("\x0f\x88\x50\x34\x12\x00", 6 ); // js 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 6);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            /* Taken */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JS");
            
            /* Not taken */
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x2006, "ArchX86: failed to disassembly and/or execute JS");
            
            
            return nb;
        }
        
        unsigned int disass_jmp(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\xeb\x10", 2); // jmp 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.execute_from(0x1000, 1);
            
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute JMP");
            
            
            code = string("\xe9\x51\x34\x12\x00", 5 ); // jmp 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute JMP");
            
            code = string("\x66\xff\xe0", 3 ); // jmp ax
            sym.regs->set(X86_EAX, exprcst(32, 0x1234));
            sym.mem->write(0x3000, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1234, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x3000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x3000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1234, "ArchX86: failed to disassembly and/or execute JMP");
            
            code = string("\xff\xe0", 2 ); // jmp eax
            sym.regs->set(X86_EAX, exprcst(32, 0x00123456));
            sym.mem->write(0x5000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x123456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x5000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x5000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x00123456, "ArchX86: failed to disassembly and/or execute JMP");
            
            code = string("\xff\x20", 2 ); // jmp dword ptr [eax]
            sym.regs->set(X86_EAX, exprcst(32, 0x4010));
            sym.mem->write(0x4000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x4010, exprcst(32, 0x111111), sym.vars);
            sym.mem->write(0x111111, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x4000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x4000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x111111, "ArchX86: failed to disassembly and/or execute JMP");
            
            return nb;
        }
        
        unsigned int disass_lahf(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\x9f", 1); // lahf
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0));
            sym.regs->set(X86_SF, exprcst(32, 1));
            sym.regs->set(X86_ZF, exprcst(32, 1));
            sym.regs->set(X86_AF, exprcst(32, 1));
            sym.regs->set(X86_PF, exprcst(32, 1));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0b1101011100000000, "ArchX86: failed to disassembly and/or execute LAHF");
           
            sym.regs->set(X86_EAX, exprcst(32, 0b0010101000000000));
            sym.regs->set(X86_SF, exprcst(32, 1));
            sym.regs->set(X86_ZF, exprcst(32, 1));
            sym.regs->set(X86_AF, exprcst(32, 1));
            sym.regs->set(X86_PF, exprcst(32, 1));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0b1101011100000000, "ArchX86: failed to disassembly and/or execute LAHF");
            return nb;
        }
        
        unsigned int disass_lea(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\x8d\x04\x9d\x02\x00\x00\x00", 7); // lea eax, dword ptr [ebx*4 + 2]
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 7);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0));
            sym.regs->set(X86_EBX, exprcst(32, 0x20));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x82, "ArchX86: failed to disassembly and/or execute LEA");
           
            code = string("\x8d\x04\x9d\x02\x00\x01\x00", 7); // lea eax, dword ptr[ 0x10000 + ebx*4 + 2]
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), 7);
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32, 0));
            sym.regs->set(X86_EBX, exprcst(32, 0x20));
            sym.execute_from(0x1010, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x10082, "ArchX86: failed to disassembly and/or execute LEA");
            
            code = string("\x66\x8d\x04\x9d\x02\x00\x01\x00", 8); // lea ax, dword ptr[ 0x10000 + ebx*4 + 2]
            sym.mem->write(0x1020, (uint8_t*)code.c_str(), 8);
            sym.mem->write(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32, 0));
            sym.regs->set(X86_EBX, exprcst(32, 0x20));
            sym.execute_from(0x1020, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x82, "ArchX86: failed to disassembly and/or execute LEA");
            
            code = string("\x67\x8D\x87\x34\x12", 5); // lea eax, [ 0x1234 + bx]
            sym.mem->write(0x1030, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32, 34));
            sym.regs->set(X86_EBX, exprcst(32, 0x10020));
            sym.execute_from(0x1030, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x1254, "ArchX86: failed to disassembly and/or execute LEA");
            
            return nb;
        }
        
        unsigned int disass_lodsb(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\xac", 1); // lodsb
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(8, 0xAA), sym.vars);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1234));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x12AA, "ArchX86: failed to disassembly and/or execute LODSB");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x1801, "ArchX86: failed to disassembly and/or execute LODSB");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1234));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x12AA, "ArchX86: failed to disassembly and/or execute LODSB");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x17ff, "ArchX86: failed to disassembly and/or execute LODSB");
            
            return nb;
        }
        
        unsigned int disass_lodsd(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\xad", 1); // lodsd
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0x12345678), sym.vars);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x2));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x12345678, "ArchX86: failed to disassembly and/or execute LODSD");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x1804, "ArchX86: failed to disassembly and/or execute LODSD");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x12));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x12345678, "ArchX86: failed to disassembly and/or execute LODSD");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x17fc, "ArchX86: failed to disassembly and/or execute LODSD");
            
            return nb;
        }
        
        unsigned int disass_lodsw(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\x66\xad", 2); // lodsw
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(16, 0x1234), sym.vars);
            
            sym.regs->set(X86_EAX, exprcst(32, 42));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x1234, "ArchX86: failed to disassembly and/or execute LODSW");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x1802, "ArchX86: failed to disassembly and/or execute LODSW");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10000));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x11234, "ArchX86: failed to disassembly and/or execute LODSW");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x17fe, "ArchX86: failed to disassembly and/or execute LODSW");
            
            return nb;
        }
        
        unsigned int disass_mov(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\xb0\x12", 2); // mov al, 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1100));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x1112, "ArchX86: failed to disassembly and/or execute MOV");
            
            code = string("\x66\xb8\x34\x12", 4); // mov ax, 0x1234
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1100));
            sym.execute_from(0x1010, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x1234, "ArchX86: failed to disassembly and/or execute MOV");
            
            code = string("\xa1\x00\x17\x00\x00", 5); // mov eax, dword ptr [0x1700]
            sym.mem->write(0x1020, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1700, exprcst(32, 0x07654321), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32, 0x11dd00));
            sym.execute_from(0x1020, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x07654321, "ArchX86: failed to disassembly and/or execute MOV");
            
            code = string("\x88\x18", 2); // mov byte ptr [eax], bl
            sym.mem->write(0x1030, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1800));
            sym.regs->set(X86_EBX, exprcst(32, 0x1234));
            sym.execute_from(0x1030, 1);
            nb += _assert(  sym.mem->read(0x1800, 1)->concretize(sym.vars) == 0x34, "ArchX86: failed to disassembly and/or execute MOV");
            
            return nb;
        }
        
        unsigned int disass_movsb(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\xa4", 1); // movsb
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(8, 0x12), sym.vars);
            sym.mem->write(0x1900, exprcst(8, 0x23), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x18ff, "ArchX86: failed to disassembly and/or execute MOVSB");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x17ff, "ArchX86: failed to disassembly and/or execute MOVSB");
            nb += _assert(  sym.mem->read(0x1900, 1)->concretize(sym.vars) == 0x12, "ArchX86: failed to disassembly and/or execute MOVSB");
            
            sym.mem->write(0x1800, exprcst(16, 0x12), sym.vars);
            sym.mem->write(0x1900, exprcst(16, 0x23), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x1901, "ArchX86: failed to disassembly and/or execute MOVSB");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x1801, "ArchX86: failed to disassembly and/or execute MOVSB");
            nb += _assert(  sym.mem->read(0x1900, 1)->concretize(sym.vars) == 0x12, "ArchX86: failed to disassembly and/or execute MOVSB");
            
            return nb;
        }
        
        unsigned int disass_movsd(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\xA5", 1); // movsd
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(32, 0x1000babe), sym.vars);
            sym.mem->write(0x1900, exprcst(32, 0xAAAAAAAA), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x18fc, "ArchX86: failed to disassembly and/or execute MOVSD");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x17fc, "ArchX86: failed to disassembly and/or execute MOVSD");
            nb += _assert(  sym.mem->read(0x1900, 4)->concretize(sym.vars) == 0x1000babe, "ArchX86: failed to disassembly and/or execute MOVSD");
            
            sym.mem->write(0x1800, exprcst(32, 0x1000babe), sym.vars);
            sym.mem->write(0x1900, exprcst(32, 0xAAAAAAAA), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x1904, "ArchX86: failed to disassembly and/or execute MOVSD");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x1804, "ArchX86: failed to disassembly and/or execute MOVSD");
            nb += _assert(  sym.mem->read(0x1900, 4)->concretize(sym.vars) == 0x1000babe, "ArchX86: failed to disassembly and/or execute MOVSD");
            
            return nb;
        }
        
        unsigned int disass_movsw(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\x66\xA5", 2); // movsw
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(16, 0x1234), sym.vars);
            sym.mem->write(0x1900, exprcst(16, 0xAAAA), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x18fe, "ArchX86: failed to disassembly and/or execute MOVSW");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x17fe, "ArchX86: failed to disassembly and/or execute MOVSW");
            nb += _assert(  sym.mem->read(0x1900, 2)->concretize(sym.vars) == 0x1234, "ArchX86: failed to disassembly and/or execute MOVSW");
            
            sym.mem->write(0x1800, exprcst(16, 0x1234), sym.vars);
            sym.mem->write(0x1900, exprcst(16, 0xAAAA), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_ESI, exprcst(32, 0x1800));
            sym.regs->set(X86_DF, exprcst(32, 0x0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x1902, "ArchX86: failed to disassembly and/or execute MOVSW");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x1802, "ArchX86: failed to disassembly and/or execute MOVSW");
            nb += _assert(  sym.mem->read(0x1900, 2)->concretize(sym.vars) == 0x1234, "ArchX86: failed to disassembly and/or execute MOVSW");
            
            return nb;
        }
        
        unsigned int disass_movsx(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\x66\x0F\xBE\xC3", 4); // movsx ax, bl
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1234));
            sym.regs->set(X86_EBX, exprcst(32, 0x1A));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x1A, "ArchX86: failed to disassembly and/or execute MOVSX");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0x1A, "ArchX86: failed to disassembly and/or execute MOVSX");
            
            
            code = string("\x0F\xBF\x03", 3); // movsx eax, word ptr [ebx]
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(16, 0xAAAA), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32, 0x1234));
            sym.regs->set(X86_EBX, exprcst(32, 0x1800));
            sym.execute_from(0x1010, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0xffffAAAA, "ArchX86: failed to disassembly and/or execute MOVSX");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0x1800, "ArchX86: failed to disassembly and/or execute MOVSX");
            
            return nb;
        }
        
        unsigned int disass_movzx(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\x66\x0F\xB6\xC3", 4); // movzx ax, bl
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1234));
            sym.regs->set(X86_EBX, exprcst(32, 0xff));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0xff, "ArchX86: failed to disassembly and/or execute MOVZX");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0xff, "ArchX86: failed to disassembly and/or execute MOVZX");
            
            
            code = string("\x0F\xB7\x03", 3); // movzx eax, word ptr [ebx]
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(16, 0xAAAA), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32, 0x12345678));
            sym.regs->set(X86_EBX, exprcst(32, 0x1800));
            sym.execute_from(0x1010, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0xAAAA, "ArchX86: failed to disassembly and/or execute MOVZX");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0x1800, "ArchX86: failed to disassembly and/or execute MOVZX");
            
            return nb;
        }
        
        unsigned int disass_mul(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* One-operand */
            code = string("\xF6\xE3", 2); // mul bl
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x23));
            sym.regs->set(X86_EBX, exprcst(32, 0x10));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x230, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0x10, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute MUL");
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_EBX, exprcst(32, 3));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 6, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 3, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute MUL");
            
            
            code = string("\x66\xF7\xE3", 3); // mul bx
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x10001234));
            sym.regs->set(X86_EBX, exprcst(32, 0xffff));
            sym.regs->set(X86_EDX, exprcst(32, 0x11001234));
            sym.execute_from(0x1010, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x1000edcc, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0xffff, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EDX) == 0x11001233, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1013, "ArchX86: failed to disassembly and/or execute MUL");
            
            sym.regs->set(X86_EAX, exprcst(32,0x1234));
            sym.regs->set(X86_EBX, exprcst(32, 0x0));
            sym.regs->set(X86_EDX, exprcst(32, 0x11001234));
            sym.execute_from(0x1010, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x0000, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0x0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EDX) == 0x11000000, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1013, "ArchX86: failed to disassembly and/or execute MUL");
            
            
            code = string("\xf7\xe3", 2); // mul ebx
            sym.mem->write(0x1020, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x4823424));
            sym.regs->set(X86_EBX, exprcst(32, 0x12345678));
            sym.regs->set(X86_EDX, exprcst(32, 0xAAAAAA));
            sym.execute_from(0x1020, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0xf9dc88e0, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EBX) == 0x12345678, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EDX) == 0x5213a2, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute MUL");
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1022, "ArchX86: failed to disassembly and/or execute MUL");
            
            return nb;
            
        }
        
        unsigned int disass_neg(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\xF6\xDC", 2); // neg ah
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x8000));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x8000, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_SF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_AF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_PF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_ZF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            
            sym.regs->set(X86_EAX, exprcst(32, 0xff00));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x0100, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_SF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_AF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_PF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_ZF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            
            code = string("\xF7\xD8", 2); // neg eax
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1));
            sym.execute_from(0x1010, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0xffffffff, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_SF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_AF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_PF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_ZF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x0));
            sym.execute_from(0x1010, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_SF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_AF) == 0, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_PF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            nb += _assert(  sym.regs->concretize(X86_ZF) == 1, "ArchX86: failed to disassembly and/or execute NEG");
            
            return nb;
        }
        
        unsigned int disass_nop(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\x90", 1); // nop
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1001, "ArchX86: failed to disassembly and/or execute NOP");
            
            return nb;
        }
        
        unsigned int disass_not(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\xF6\xD4", 2); // not ah
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x11110f11));
            sym.execute_from(0x1000, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x1111f011, "ArchX86: failed to disassembly and/or execute NOT");
            
            code = string("\xF7\xD0", 2); // not eax
            sym.mem->write(0x1010, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1010+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x80000000));
            sym.execute_from(0x1010, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x7fffffff, "ArchX86: failed to disassembly and/or execute NOT");
            
            return nb;
        }
        
        unsigned int disass_or(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            // On 32 bits
            // 678 | 0xfff.....
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_EBX, exprcst(32, 678));
            code = string("\x09\xD8", 2); // or eax, ebx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_EAX)->concretize(sym.vars) == 0xffffffff,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
            
            // 0xff000000 | 0x000000ff
            sym.regs->set(X86_EAX, exprcst(32, 0xff000000));
            sym.regs->set(X86_EBX, exprcst(32, 0xff));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_EAX)->concretize(sym.vars) == 0xff0000ff,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
                            
            // 0 | 0 
            sym.regs->set(X86_EAX, exprcst(32, 0));
            sym.regs->set(X86_EBX, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute OR");
                            
            // On 16 bits... 
            // 0xa00000f0 | 0x0b0000ff
            sym.regs->set(X86_EAX, exprcst(32, 0xa00000f0));
            sym.regs->set(X86_EBX, exprcst(32, 0x0b0000fe));
            code = string("\x66\x09\xD8", 3); // or ax, bx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_EAX)->concretize(sym.vars) == 0xa00000fe,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute OR");
            
            return nb;
        }
        
        unsigned int disass_pop(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_ESP, exprcst(32, 0x1800));
            code = string("\x58", 1); // pop eax
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(32, 0x12345678), sym.vars);
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_EAX)->concretize(sym.vars) == 0x12345678,
                            "ArchX86: failed to disassembly and/or execute POP");
            nb += _assert(  (uint32_t)sym.regs->get(X86_ESP)->concretize(sym.vars) == 0x1804,
                            "ArchX86: failed to disassembly and/or execute POP");
                            
                            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.regs->set(X86_ESP, exprcst(32, 0x1800));
            code = string("\x66\x8F\x00", 3); // pop word ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(16, 0x1234), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_EAX)->concretize(sym.vars) == 0x1700,
                            "ArchX86: failed to disassembly and/or execute POP");
            nb += _assert(  (uint32_t)sym.regs->get(X86_ESP)->concretize(sym.vars) == 0x1802,
                            "ArchX86: failed to disassembly and/or execute POP");
            nb += _assert(  sym.mem->read(0x1700, 2)->concretize(sym.vars) == 0x1234,
                            "ArchX86: failed to disassembly and/or execute POP");
            return nb;
        }
        
        unsigned int disass_popad(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            sym.regs->set(X86_ESP, exprcst(32, 0x1800));
            code = string("\x61", 1); // popad
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1800, exprcst(32, 0xAAAAAAAA), sym.vars);
            sym.mem->write(0x1804, exprcst(32, 0xBBBBBBBB), sym.vars);
            sym.mem->write(0x1808, exprcst(32, 0xCCCCCCCC), sym.vars);
            sym.mem->write(0x180C, exprcst(32, 0x12345678), sym.vars);
            sym.mem->write(0x1810, exprcst(32, 0xDDDDDDDD), sym.vars);
            sym.mem->write(0x1814, exprcst(32, 0xEEEEEEEE), sym.vars);
            sym.mem->write(0x1818, exprcst(32, 0xFFFFFFFF), sym.vars);
            sym.mem->write(0x181c, exprcst(32, 0x11111111), sym.vars);
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_EDI)->concretize(sym.vars) == 0xAAAAAAAA,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.regs->get(X86_ESI)->concretize(sym.vars) == 0xBBBBBBBB,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.regs->get(X86_EBP)->concretize(sym.vars) == 0xCCCCCCCC,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.regs->get(X86_EBX)->concretize(sym.vars) == 0xDDDDDDDD,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.regs->get(X86_EDX)->concretize(sym.vars) == 0xEEEEEEEE,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.regs->get(X86_ECX)->concretize(sym.vars) == 0xFFFFFFFF,
                            "ArchX86: failed to disassembly and/or execute POPAD");
            nb += _assert(  (uint32_t)sym.regs->get(X86_EAX)->concretize(sym.vars) == 0x11111111,
                            "ArchX86: failed to disassembly and/or execute POPAD");
                            
            nb += _assert(  (uint32_t)sym.regs->get(X86_ESP)->concretize(sym.vars) == 0x1820,
                            "ArchX86: failed to disassembly and/or execute POPAD");

            return nb;
        }
        
        unsigned int disass_push(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_ESP, exprcst(32, 0x1804));
            code = string("\x50", 1); // push eax
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_ESP)->concretize(sym.vars) == 0x1800,
                            "ArchX86: failed to disassembly and/or execute PUSH");
            nb += _assert(  (uint32_t)sym.mem->read(0x1800, 4)->concretize(sym.vars) == 0xffffffff,
                            "ArchX86: failed to disassembly and/or execute PUSH");
                            
            sym.regs->set(X86_EAX, exprcst(32, 0x1900));
            sym.regs->set(X86_ESP, exprcst(32, 0x1804));
            code = string("\x66\xFF\x30", 3); // push word ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1900, exprcst(16, 0x1234), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_ESP)->concretize(sym.vars) == 0x1802,
                            "ArchX86: failed to disassembly and/or execute PUSH");
            nb += _assert(  (uint16_t)sym.mem->read(0x1802, 2)->concretize(sym.vars) == 0x1234,
                            "ArchX86: failed to disassembly and/or execute PUSH");
                            
            sym.regs->set(X86_ESP, exprcst(32, 0x1804));
            code = string("\x66\xFF\x34\x24", 4); // push word ptr [esp]
            sym.mem->write(0x1180, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1180+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1804, exprcst(16, 0xABCD), sym.vars);
            sym.execute_from(0x1180, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_ESP)->concretize(sym.vars) == 0x1802,
                            "ArchX86: failed to disassembly and/or execute PUSH");
            nb += _assert(  (uint16_t)sym.mem->read(0x1802, 2)->concretize(sym.vars) == 0xABCD,
                            "ArchX86: failed to disassembly and/or execute PUSH");
               
            return nb;
        }
        
        unsigned int disass_pushad(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            sym.regs->set(X86_ESP, exprcst(32, 0x1820));
            code = string("\x60", 1); // pushad
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0xAAAAAAAA));
            sym.regs->set(X86_ECX, exprcst(32, 0xBBBBBBBB));
            sym.regs->set(X86_EDX, exprcst(32, 0xCCCCCCCC));
            sym.regs->set(X86_EBX, exprcst(32, 0xDDDDDDDD));
            sym.regs->set(X86_ESP, exprcst(32, 0x1820));
            sym.regs->set(X86_EBP, exprcst(32, 0xEEEEEEEE));
            sym.regs->set(X86_ESI, exprcst(32, 0xFFFFFFFF));
            sym.regs->set(X86_EDI, exprcst(32, 0x11111111));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x181c, 4)->concretize(sym.vars) == 0xAAAAAAAA,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1818, 4)->concretize(sym.vars) == 0xBBBBBBBB,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1814, 4)->concretize(sym.vars) == 0xCCCCCCCC,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1810, 4)->concretize(sym.vars) == 0xDDDDDDDD,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x180c, 4)->concretize(sym.vars) == 0x1820,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1808, 4)->concretize(sym.vars) == 0xEEEEEEEE,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1804, 4)->concretize(sym.vars) == 0xFFFFFFFF,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");
            nb += _assert(  (uint32_t)sym.mem->read(0x1800, 4)->concretize(sym.vars) == 0x11111111,
                            "ArchX86: failed to disassembly and/or execute PUSHAD");

            return nb;
        }
        
        
        unsigned int disass_rcl(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x66\xC1\xD0\x07", 4); // rcl ax, 7
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10201));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_OF, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x100c0, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute RCL");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10010));
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10800, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute RCL");
            
            code = string("\xD1\x10", 2); // rcl dword ptr [eax], 1
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
               
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_OF, exprcst(32, 0));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x44444445, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute RCL");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000000), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute RCL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute RCL");
            
            return nb;
        }
        
        unsigned int disass_rcr(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x66\xc1\xd8\x07", 4); // rcr ax, 7
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x11200));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10224, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute RCR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x11240));
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_OF, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10024, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute RCR");
            
            code = string("\xD1\x18", 2); // rcr dword ptr [eax], 1
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);   
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_OF, exprcst(32, 0));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x91111111, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute RCR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x10000001), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x08000000, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute RCR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute RCR");
            
            return nb;
        }
        
        unsigned int disass_ret(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\xC3", 1); // ret
            sym.regs->set(X86_ESP, exprcst(32, 0x1800));
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1700, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0x1700), sym.vars);
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_ESP)->concretize(sym.vars) == 0x1804,
                            "ArchX86: failed to disassembly and/or execute RET");
            nb += _assert(  (uint32_t)sym.regs->get(X86_EIP)->concretize(sym.vars) == 0x1700,
                            "ArchX86: failed to disassembly and/or execute RET");
                            
            
            code = string("\xc2\x30\x00", 3); // ret 0x30
            sym.regs->set(X86_ESP, exprcst(32, 0x1800));
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1700, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0x1700), sym.vars);
            
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_ESP)->concretize(sym.vars) == 0x1834,
                            "ArchX86: failed to disassembly and/or execute RET");
            nb += _assert(  (uint32_t)sym.regs->get(X86_EIP)->concretize(sym.vars) == 0x1700,
                            "ArchX86: failed to disassembly and/or execute RET");
               
            return nb;
        }
        
        unsigned int disass_rol(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x66\xC1\xC0\x07", 4); // rol ax, 7
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10201));
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10081, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute ROL");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10010));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10800, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute ROL");
            
            code = string("\xD1\x00", 2); // rol dword ptr [eax], 1
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
               
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x44444444, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute ROL");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000001), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_OF, exprcst(32, 0));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 3, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute ROL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute ROL");
            
            return nb;
        }
        
        unsigned int disass_ror(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x66\xC1\xC8\x07", 4); // ror ax, 7
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10201));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10204, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute ROR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10018));
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x13000, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute ROR");
            
            code = string("\xD1\x08", 2); // ror dword ptr [eax], 1
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);   
               
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x11111111, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute ROR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000000), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x40000000, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute ROR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute ROR");
            
            return nb;
        }
        
        unsigned int disass_sal(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x66\xc1\xe0\x04", 4); // sal ax, 4
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10201));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x12010, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute SAL");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x11010));
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10100, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute SAL");
            
            code = string("\xd1\x20", 2); // sal dword ptr [eax], 1
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
               
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x44444444, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute SAL");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000001), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_OF, exprcst(32, 0));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 2, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute SAL");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute SAL");
            
            return nb;
        }
        
        unsigned int disass_sar(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x66\xc1\xf8\x04", 4); // sar ax, 4
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10201));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10020, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute SAR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1f008));
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x1ff00, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute SAR");
            
            code = string("\xd1\x38", 2); // sar dword ptr [eax], 1
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x11111111, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute SAR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000001), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0xc0000000, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute SAR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute SAR");
            
            return nb;
        }
        
        unsigned int disass_shr(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            code = string("\x66\xc1\xe8\x04", 4); // sar ax, 4
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32, 0x10201));
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10020, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute SHR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1f008));
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0x10f00, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute SHR");
            
            code = string("\xd1\x28", 2); // shr dword ptr [eax], 1
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
               
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x22222222), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 1));
            sym.regs->set(X86_OF, exprcst(32, 1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x11111111, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute SHR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0x1700));
            sym.mem->write(0x1700, exprcst(32, 0x80000001), sym.vars);
            sym.regs->set(X86_CF, exprcst(32, 0));
            sym.regs->set(X86_OF, exprcst(32, 0));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) == 0x40000000, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_CF) == 1, "ArchX86: failed to disassembly and/or execute SHR");
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_OF) == 1, "ArchX86: failed to disassembly and/or execute SHR");
            
            return nb;
        }
        
        unsigned int disass_scasb(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\xae", 1); // scasb
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1500, exprcst(8, 0xf), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 1));
            sym.regs->set(X86_EAX, exprcst(32,0xff));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x14ff)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            
            sym.mem->write(0x1500, exprcst(8, 0xff), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.regs->set(X86_EAX, exprcst(32,0x1));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x1501)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASB");
            
            return nb;
        }
        
        unsigned int disass_scasd(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\xAf", 1); // scasd
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1500, exprcst(32, 0xAAAA), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 1));
            sym.regs->set(X86_EAX, exprcst(32,0xAAAA));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x14fc)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            
            sym.mem->write(0x1500, exprcst(32, 0x1235), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.regs->set(X86_EAX, exprcst(32,0x1234));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x1504)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASD");
            
            return nb;
        }
        
        unsigned int disass_scasw(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            
            code = string("\x66\xAf", 2); // scasw
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1500, exprcst(16, 0xAAAA), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 1));
            sym.regs->set(X86_EAX, exprcst(32,0xAAAA));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x14fe)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            
            sym.mem->write(0x1500, exprcst(32, 0x1235), sym.vars);
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.regs->set(X86_EAX, exprcst(32,0x1234));
            sym.regs->set(X86_EDI, exprcst(32,0x1500));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->get(X86_EDI)->concretize(sym.vars) == exprcst(32, 0x1502)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SCASW");
            
            return nb;
        }
     
        unsigned int disass_seta(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With zf == 0 && cf == 0 */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,0));
            
            /* Reg */
            code = string("\x0f\x97\xc0", 3); // seta al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SETA");
            
            
            /* Mem */
            code = string("\x0f\x97\x00", 3); // seta byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETA");
                            
            /* With condition not verified */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETA");
                            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETA");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETA");
            return nb;
        }
        
        unsigned int disass_setae(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With cf == 0 */
            sym.regs->set(X86_CF, exprcst(32,0));
            
            /* Reg */
            code = string("\x0f\x93\xc0", 3); // setae al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SETAE");
            
            
            /* Mem */
            code = string("\x0f\x93\x00", 3); // setae byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETAE");
                            
            /* With condition not verified */
            sym.regs->set(X86_CF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETAE");
                            
            
            return nb;
        }
        
        unsigned int disass_setb(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With cf == 1 */
            sym.regs->set(X86_CF, exprcst(32,1));
            
            /* Reg */
            code = string("\x0f\x92\xc0", 3); // setb al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETB");
            
            
            /* Mem */
            code = string("\x0f\x92\x00", 3); // setb byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETB");
                            
            /* With condition not verified */
            sym.regs->set(X86_CF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETB");
                            
            
            return nb;
        }
        
        unsigned int disass_setbe(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With zf == 0 && cf == 0 */
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,0));
            
            /* Reg */
            code = string("\x0f\x96\xc0", 3); // setbe al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SETBE");
            
            
            /* Mem */
            code = string("\x0f\x96\x00", 3); // setbe byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETBE");
                            
            /* With condition -verified- */
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETBE");
                            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_CF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETBE");
            
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETBE");
            return nb;
        }
        
        unsigned int disass_setg(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With zf == 0 && sf == of */

            /* Reg */
            code = string("\x0f\x9f\xc0", 3); // setg al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SETG");
                            
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SETG");
            
            /* Mem */
            code = string("\x0f\x9f\x00", 3); // setg byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETG");
                            
            /* With condition not verified */
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETG");
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETG");
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETG");
            
            return nb;
        }
        
        unsigned int disass_setge(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With sf == of */
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            
            /* Reg */
            code = string("\x0f\x9d\xc0", 3); // setge al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETGE");
            
            
            /* Mem */
            code = string("\x0f\x9d\x00", 3); // setge byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETGE");
                            
            /* With condition not verified */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETGE");
                            
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETGE");
            
            return nb;
        }
        
        unsigned int disass_setl(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With sf != of */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            
            /* Reg */
            code = string("\x0f\x9c\xc0", 3); // setl al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETL");
            
            
            /* Mem */
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            code = string("\x0f\x9c\x00", 3); // setl byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETL");
                            
            /* With condition not verified */
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETL");
                            
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETL");
            
            return nb;
        }
        
        unsigned int disass_setle(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With zf == 1 || sf != of */

            /* Reg */
            code = string("\x0f\x9e\xc0", 3); // setle al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SETLE");
                            
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SETLE");
            
            /* Mem */
            code = string("\x0f\x9e\x00", 3); // setle byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETLE");
                            
            /* With condition not verified */
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETLE");
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,0));
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETLE");
            
            return nb;
        }
        
        unsigned int disass_sete(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With zf == 1 */
            sym.regs->set(X86_ZF, exprcst(32,1));
            
            /* Reg */
            code = string("\x0f\x94\xc0", 3); // sete al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETE");
            
            
            /* Mem */
            code = string("\x0f\x94\x00", 3); // sete byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETE");
                            
            /* With condition not verified */
            sym.regs->set(X86_ZF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETE");
                            
            
            return nb;
        }
        
        unsigned int disass_setne(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With zf == 0 */
            sym.regs->set(X86_ZF, exprcst(32,0));
            
            /* Reg */
            code = string("\x0f\x95\xc0", 3); // setne al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETNE");
            
            
            /* Mem */
            code = string("\x0f\x95\x00", 3); // setne byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETNE");
                            
            /* With condition not verified */
            sym.regs->set(X86_ZF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETNE");
                            
            
            return nb;
        }
        
        unsigned int disass_setno(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With of == 0 */
            sym.regs->set(X86_OF, exprcst(32,0));
            
            /* Reg */
            code = string("\x0f\x91\xc0", 3); // setno al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETNO");
            
            
            /* Mem */
            code = string("\x0f\x91\x00", 3); // setno byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETNO");
                            
            /* With condition not verified */
            sym.regs->set(X86_OF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETNO");
                            
            
            return nb;
        }
        
        unsigned int disass_setnp(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With pf == 0 */
            sym.regs->set(X86_PF, exprcst(32,0));
            
            /* Reg */
            code = string("\x0f\x9b\xc0", 3); // setnp al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETNP");
            
            
            /* Mem */
            code = string("\x0f\x9b\x00", 3); // setnp byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETNP");
                            
            /* With condition not verified */
            sym.regs->set(X86_PF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETNP");                   
            return nb;
        }
        
        unsigned int disass_setns(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With sf == 0 */
            sym.regs->set(X86_SF, exprcst(32,0));
            
            /* Reg */
            code = string("\x0f\x99\xc0", 3); // setns al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETNS");
            
            
            /* Mem */
            code = string("\x0f\x99\x00", 3); // setns byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETNS");
                            
            /* With condition not verified */
            sym.regs->set(X86_SF, exprcst(32,1));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETNS");                   
            return nb;
        }
        
        unsigned int disass_seto(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With of == 1 */
            sym.regs->set(X86_OF, exprcst(32,1));
            
            /* Reg */
            code = string("\x0f\x90\xc0", 3); // seto al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETO");
            
            
            /* Mem */
            code = string("\x0f\x90\x00", 3); // seto byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETO");
                            
            /* With condition not verified */
            sym.regs->set(X86_OF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETO");
                            
            
            return nb;
        }
        
        unsigned int disass_setp(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With pf == 1 */
            sym.regs->set(X86_PF, exprcst(32,1));
            
            /* Reg */
            code = string("\x0f\x9a\xc0", 3); // setp al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETP");
            
            
            /* Mem */
            code = string("\x0f\x9a\x00", 3); // setp byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETP");
                            
            /* With condition not verified */
            sym.regs->set(X86_PF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETP");                   
            return nb;
        }
        
        unsigned int disass_sets(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* With sf == 1 */
            sym.regs->set(X86_SF, exprcst(32,1));
            
            /* Reg */
            code = string("\x0f\x98\xc0", 3); // sets al
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,2));
            
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_EAX)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETS");
            
            
            /* Mem */
            code = string("\x0f\x98\x00", 3); // sets byte ptr [eax]
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute SETS");
                            
            /* With condition not verified */
            sym.regs->set(X86_SF, exprcst(32,0));
            
            sym.regs->set(X86_EAX, exprcst(32,0x1700));
            sym.mem->write(0x1700, exprcst(8, 12), sym.vars);
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.mem->read(0x1700, 1)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute SETS");                   
            return nb;
        }
        
        unsigned int disass_stc(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            sym.regs->set(X86_CF, exprcst(32,0));

            code = string("\xf9", 1); // stc
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute STC");

            return nb;
        }
        
        unsigned int disass_std(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            sym.regs->set(X86_DF, exprcst(32,0));

            code = string("\xfd", 1); // stc
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_DF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute STD");

            return nb;
        }
        
        unsigned int disass_sti(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            sym.regs->set(X86_IF, exprcst(32,0));

            code = string("\xfb", 1); // sti
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x1160, 1);
            nb += _assert(  sym.regs->get(X86_IF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute STI");

            return nb;
        }
        
        unsigned int disass_stosb(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\xaa", 1); // stosb
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1900, exprcst(8, 0x23), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_EAX, exprcst(32, 0x12));
            sym.regs->set(X86_DF, exprcst(32, 0x1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x18ff, "ArchX86: failed to disassembly and/or execute STOSB");
            nb += _assert(  sym.mem->read(0x1900, 1)->concretize(sym.vars) == 0x12, "ArchX86: failed to disassembly and/or execute STOSB");
            
            sym.mem->write(0x1900, exprcst(16, 0x23), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_EAX, exprcst(32, 0x12));
            sym.regs->set(X86_DF, exprcst(32, 0x0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x1901, "ArchX86: failed to disassembly and/or execute STOSB");
            nb += _assert(  sym.mem->read(0x1900, 1)->concretize(sym.vars) == 0x12, "ArchX86: failed to disassembly and/or execute STOSB");
            
            return nb;
        }
        
        unsigned int disass_stosd(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\xab", 1); // stosd
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 1);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1900, exprcst(32, 0x23), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_EAX, exprcst(32, 0x12345678));
            sym.regs->set(X86_DF, exprcst(32, 0x1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x18fc, "ArchX86: failed to disassembly and/or execute STOSD");
            nb += _assert(  sym.mem->read(0x1900, 4)->concretize(sym.vars) == 0x12345678, "ArchX86: failed to disassembly and/or execute STOSD");
            
            sym.mem->write(0x1900, exprcst(32, 0x23), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_EAX, exprcst(32, 0x12345678));
            sym.regs->set(X86_DF, exprcst(32, 0x0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x1904, "ArchX86: failed to disassembly and/or execute STOSD");
            nb += _assert(  sym.mem->read(0x1900, 4)->concretize(sym.vars) == 0x12345678, "ArchX86: failed to disassembly and/or execute STOSD");
            
            return nb;
        }
        
        unsigned int disass_stosw(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            code = string("\x66\xab", 2); // stosw
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x1900, exprcst(16, 0x23), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_EAX, exprcst(32, 0x12345678));
            sym.regs->set(X86_DF, exprcst(32, 0x1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x18fe, "ArchX86: failed to disassembly and/or execute STOSW");
            nb += _assert(  sym.mem->read(0x1900, 2)->concretize(sym.vars) == 0x5678, "ArchX86: failed to disassembly and/or execute STOSW");
            
            sym.mem->write(0x1900, exprcst(32, 0x23), sym.vars);
            sym.regs->set(X86_EDI, exprcst(32, 0x1900));
            sym.regs->set(X86_EAX, exprcst(32, 0x12345678));
            sym.regs->set(X86_DF, exprcst(32, 0x0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x1902, "ArchX86: failed to disassembly and/or execute STOSW");
            nb += _assert(  sym.mem->read(0x1900, 2)->concretize(sym.vars) == 0x5678, "ArchX86: failed to disassembly and/or execute STOSW");
            
            return nb;
        }
        
        unsigned int disass_sub(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            /* sub reg, imm */
            code = string("\x2c\x0f", 2); // sub al(ff), f
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0xff));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0xf0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
                            
            sym.regs->set(X86_EAX, exprcst(32,0x10ff));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x10f0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
                            
            code = string("\x2c\x81", 2); // sub al(0x80), 0x81
            sym.mem->write(0x1190, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1190+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x80));
            sym.execute_from(0x1190, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0xff,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            
            
            code = string("\x66\x2d\xff\x00", 4); // sub ax, ff
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0x1ffff));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x1ff00,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
                            
            code = string("\x66\x83\xe8\x01", 4); // sub ax, 1
            sym.mem->write(0x1200, (uint8_t*)code.c_str(), 4);
            sym.mem->write(0x1200+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32,0xfa000009));
            sym.execute_from(0x1200, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0xfa000008,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            
            
            code = string("\x2d\x34\x12\x00\x00", 5); // sub eax, 0x1234
            sym.mem->write(0x1020, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1020+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32,0x10001235));
            sym.execute_from(0x1020, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x10000001,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            
            
            code = string("\x2d\x00\x00\x00\xff", 5); // sub eax, 0xff000000
            sym.mem->write(0x1030, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1030+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32,0xffff0000));
            sym.execute_from(0x1030, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x00ff0000,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            
            /* sub reg,reg */
            code = string("\x28\xfc", 2); // sub ah, bh
            sym.mem->write(0x1050, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1050+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_EAX, exprcst(32,0xf800));
            sym.regs->set(X86_EBX, exprcst(32,0x7900));
            sym.execute_from(0x1050, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x7f00,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
                            
            /* sub reg,mem */
            code = string("\x2B\x03", 2); // sub eax, dword ptr [ebx] 
            sym.mem->write(0x1060, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1060+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0xAAAA), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32,0xAAAA));
            sym.regs->set(X86_EBX, exprcst(32,0x1700));
            sym.execute_from(0x1060, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) == 0x0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
                            
            /* sub mem,reg */
            code = string("\x29\x18", 2); // sub dword ptr [eax], ebx 
            sym.mem->write(0x1070, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1070+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1800, exprcst(32, 0xffffffff), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32,0x1800));
            sym.regs->set(X86_EBX, exprcst(32,0xffffffff));
            sym.execute_from(0x1070, 1);
            nb += _assert(  sym.mem->read(0x1800, 4)->concretize(sym.vars) == 0x0,
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == exprcst(32, 1)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            nb += _assert(  sym.regs->get(X86_AF)->concretize(sym.vars) == exprcst(32, 0)->concretize(sym.vars),
                            "ArchX86: failed to disassembly and/or execute SUB");
            
            return nb;
        }
        
        
        unsigned int disass_test(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            

            code = string("\x85\xd8", 2); // test eax, ebx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.regs->set(X86_EAX, exprcst(32,0));
            sym.regs->set(X86_EBX, exprcst(32,0x16545));
            sym.regs->set(X86_ZF, exprcst(32,0));
            sym.regs->set(X86_SF, exprcst(32,1));
            sym.regs->set(X86_PF, exprcst(32,0));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->concretize(X86_ZF) == 1, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.regs->concretize(X86_SF) == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.regs->concretize(X86_PF) == 1, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute TEST");
            
            
            sym.regs->set(X86_EAX, exprcst(32,0X81230004));
            sym.regs->set(X86_EBX, exprcst(32,0x80001234));
            sym.regs->set(X86_ZF, exprcst(32,1));
            sym.regs->set(X86_SF, exprcst(32,0));
            sym.regs->set(X86_PF, exprcst(32,1));
            sym.regs->set(X86_OF, exprcst(32,1));
            sym.regs->set(X86_CF, exprcst(32,1));
            sym.execute_from(0x1170, 1);
            nb += _assert(  sym.regs->concretize(X86_ZF) == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.regs->concretize(X86_SF) == 1, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.regs->concretize(X86_PF) == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.regs->concretize(X86_OF) == 0, "ArchX86: failed to disassembly and/or execute TEST");
            nb += _assert(  sym.regs->concretize(X86_CF) == 0, "ArchX86: failed to disassembly and/or execute TEST");
                            
            return nb;
        }
        
        
        unsigned int disass_xadd(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);

            // xadd al,bl
            code = string("\x0f\xc0\xd8",3);
            sym.regs->set(X86_EAX, exprcst(32, 0x23));
            sym.regs->set(X86_EBX, exprcst(32, 0x1));
            sym.mem->write(0x1040, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x1040, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) ==  0x24, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_EBX) ==  0x23, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_ZF) ==  0x0, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_SF) ==  0x0, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_PF) ==  0x1, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_CF) ==  0x0, "ArchX86: failed to disassembly and/or execute XADD");
            nb += _assert(  sym.regs->concretize(X86_OF) ==  0x0, "ArchX86: failed to disassembly and/or execute XADD");
            
            // xadd DWORD PTR [ecx], ecx 
            code = string("\x0f\xc1\x09", 3);
            sym.mem->write(0x1100, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1100+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0x7fffffff), sym.vars);
            sym.regs->set(X86_ECX, exprcst(32, 0x1700));
            sym.regs->set(X86_EBX, exprcst(32, 0x1));
            sym.execute_from(0x1100, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) ==  0x800016ff, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_ECX) ==  0x7fffffff, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_ZF) ==  0x0, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_SF) ==  0x1, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_PF) ==  0x1, "ArchX86: failed to disassembly and/or execute XADD"); 
            nb += _assert(  sym.regs->concretize(X86_CF) ==  0x0, "ArchX86: failed to disassembly and/or execute XADD");
            nb += _assert(  sym.regs->concretize(X86_OF) ==  0x1, "ArchX86: failed to disassembly and/or execute XADD");
            
            return nb;
        }
        
        unsigned int disass_xchg(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x0000, 0x2000);

            // xchg al,bl
            code = string("\x86\xd8",2);
            sym.regs->set(X86_EAX, exprcst(32, 0x23));
            sym.regs->set(X86_EBX, exprcst(32, 0x1));
            sym.mem->write(0x1040, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1040+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x1040, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) ==  0x1, "ArchX86: failed to disassembly and/or execute XCHG"); 
            nb += _assert(  sym.regs->concretize(X86_EBX) ==  0x23, "ArchX86: failed to disassembly and/or execute XCHG"); 
            
            // xchg DWORD PTR [ecx], ecx 
            code = string("\x87\x09", 2);
            sym.mem->write(0x1100, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1100+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x1700, exprcst(32, 0x12345678), sym.vars);
            sym.regs->set(X86_ECX, exprcst(32, 0x1700));
            sym.execute_from(0x1100, 1);
            nb += _assert(  (uint32_t)sym.mem->read(0x1700, 4)->concretize(sym.vars) ==  0x1700, "ArchX86: failed to disassembly and/or execute XCHG"); 
            nb += _assert(  sym.regs->concretize(X86_ECX) ==  0x12345678, "ArchX86: failed to disassembly and/or execute XCHG"); 
            
            // xchg al, BYTE PTR [bx]
            code = string("\x67\x86\x07", 3);
            sym.mem->write(0x1110, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1110+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x20, exprcst(32, 0x12), sym.vars);
            sym.regs->set(X86_EAX, exprcst(32, 0xfAA));
            sym.regs->set(X86_EBX, exprcst(32, 0x10020));
            sym.execute_from(0x1110, 1);
            nb += _assert(  sym.regs->concretize(X86_EAX) ==  0xf12, "ArchX86: failed to disassembly and/or execute XCHG");
            nb += _assert(  (uint8_t)sym.mem->read(0x20, 1)->concretize(sym.vars) ==  0xAA, "ArchX86: failed to disassembly and/or execute XCHG");
            return nb;
        }
        
        unsigned int disass_xor(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x2000);
            
            // On 32 bits
            sym.regs->set(X86_EAX, exprcst(32, 0xffffffff));
            sym.regs->set(X86_EBX, exprcst(32, 0x0000ffff));
            code = string("\x31\xd8", 2); // xor eax, ebx
            sym.mem->write(0x1160, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1160+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0xffff0000, 
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0xfffff000));
            sym.regs->set(X86_EBX, exprcst(32, 0x000fffff));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->concretize(X86_EAX) == 0xfff00fff, 
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
                            
            sym.regs->set(X86_EAX, exprcst(32, 0x80000001));
            sym.regs->set(X86_EBX, exprcst(32, 0x80000001));
            sym.execute_from(0x1160, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_EAX)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
                            
            // On 16 bits 
            sym.regs->set(X86_EAX, exprcst(32, 0xa0000001));
            sym.regs->set(X86_EBX, exprcst(32, 0x0b000000));
            code = string("\x66\x31\xd8", 3); // xor ax, bx
            sym.mem->write(0x1170, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1170+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_EAX)->concretize(sym.vars) == 0xa0000001,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            
            sym.regs->set(X86_EAX, exprcst(32, 0xab00000f));
            sym.regs->set(X86_EBX, exprcst(32, 0xba00000f));
            sym.execute_from(0x1170, 1);
            nb += _assert(  (uint32_t)sym.regs->get(X86_EAX)->concretize(sym.vars) == 0xab000000,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_ZF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_CF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_OF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_SF)->concretize(sym.vars) == 0,
                            "ArchX86: failed to disassembly and/or execute XOR");
            nb += _assert(  sym.regs->get(X86_PF)->concretize(sym.vars) == 1,
                            "ArchX86: failed to disassembly and/or execute XOR");
            return nb;
        }
        
        unsigned int disass_call(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\xe8\x0d\x00\x00\x00", 5); // call 0x12
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x1012, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_ESP, exprcst(32, 0x10004));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1012, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.regs->concretize(X86_ESP) == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4)->concretize(sym.vars) == 0x1005, "ArchX86: failed to disassembly and/or execute CALL");
            
            
            code = string("\xe8\x51\x34\x12\x00", 5 ); // call 0x123456
            sym.mem->write(0x2000, (uint8_t*)code.c_str(), 5);
            sym.mem->write(0x125456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_ESP, exprcst(32, 0x10004));
            sym.execute_from(0x2000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x125456, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.regs->concretize(X86_ESP) == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4)->concretize(sym.vars) == 0x2005, "ArchX86: failed to disassembly and/or execute CALL");
            
            
            
            code = string("\x66\xff\xd0", 3 ); // call ax
            sym.regs->set(X86_EAX, exprcst(32, 0x1234));
            sym.mem->write(0x3000, (uint8_t*)code.c_str(), 3);
            sym.mem->write(0x1234, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_ESP, exprcst(32, 0x10004));
            sym.execute_from(0x3000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1234, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.regs->concretize(X86_ESP) == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4)->concretize(sym.vars) == 0x3003, "ArchX86: failed to disassembly and/or execute CALL");
            
            
            code = string("\xff\xd0", 2 ); // call eax
            sym.regs->set(X86_EAX, exprcst(32, 0x00123456));
            sym.mem->write(0x5000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x123456, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_ESP, exprcst(32, 0x10004));
            sym.execute_from(0x5000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x00123456, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.regs->concretize(X86_ESP) == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4)->concretize(sym.vars) == 0x5002, "ArchX86: failed to disassembly and/or execute CALL");
            
            
            code = string("\xff\x10", 2 ); // call dword ptr [eax]
            sym.regs->set(X86_EAX, exprcst(32, 0x4010));
            sym.mem->write(0x4000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x4010, exprcst(32, 0x111111), sym.vars);
            sym.mem->write(0x111111, (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.regs->set(X86_ESP, exprcst(32, 0x10004));
            sym.execute_from(0x4000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x111111, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.regs->concretize(X86_ESP) == 0x10000, "ArchX86: failed to disassembly and/or execute CALL");
            nb += _assert(  sym.mem->read(0x10000, 4)->concretize(sym.vars) == 0x4002, "ArchX86: failed to disassembly and/or execute CALL");
            
            return nb;
        }
       
        unsigned int disass_rep(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            
            code = string("\xf3\xa4", 2); // rep movsb
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x2000, (uint8_t*)string("ABCDEFGH").c_str(), 4);
            
            sym.mem->write(0x3000, (uint8_t*)string("\x00\x00\x00\x00").c_str(), 4);
            sym.regs->set(X86_ESI, exprcst(32, 0x2000));
            sym.regs->set(X86_EDI, exprcst(32, 0x3000));
            sym.regs->set(X86_ECX, exprcst(32, 4));
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x3004, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x2004, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.mem->read(0x3000, 8)->concretize(sym.vars) == 0x0000000044434241, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            
            sym.mem->write(0x3000, (uint8_t*)string("\x00\x00\x00\x00").c_str(), 4);
            sym.regs->set(X86_ESI, exprcst(32, 0x2000));
            sym.regs->set(X86_EDI, exprcst(32, 0x3000));
            sym.regs->set(X86_ECX, exprcst(32, 0));
            sym.regs->set(X86_DF, exprcst(32, 1));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x3000, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x2000, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            nb += _assert(  sym.mem->read(0x3000, 8)->concretize(sym.vars) == 0, "ArchX86: failed to disassembly and/or execute REP MOVSB");
            
            return nb;
        }
        
        unsigned int disass_repe(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            code = string("\xf3\xa6", 2); // repe cmpsb
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            
            sym.mem->write(0x2000, (uint8_t*)string("ABCDEFGH").c_str(), 8);
            sym.mem->write(0x3000, (uint8_t*)string("ABCDA").c_str(), 5);
            sym.regs->set(X86_ESI, exprcst(32, 0x2000));
            sym.regs->set(X86_EDI, exprcst(32, 0x3000));
            sym.regs->set(X86_ECX, exprcst(32, 7));
            sym.regs->set(X86_ZF, exprcst(32, 1));
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x3005, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x2005, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            
            sym.regs->set(X86_ESI, exprcst(32, 0x2000));
            sym.regs->set(X86_EDI, exprcst(32, 0x3000));
            sym.regs->set(X86_ECX, exprcst(32, 3));
            sym.regs->set(X86_ZF, exprcst(32, 1));
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x3003, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            nb += _assert(  sym.regs->concretize(X86_ESI) == 0x2003, "ArchX86: failed to disassembly and/or execute REPE CMPSB");
            
            return nb;
        }
        
        unsigned int disass_repne(){
            unsigned int nb = 0;
            string code;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            
            sym.mem->new_segment(0x1000, 0x200000);
            
            code = string("\xf2\xae", 2); // repne scasb
            sym.mem->write(0x1000, (uint8_t*)code.c_str(), 2);
            sym.mem->write(0x1000+code.size(), (uint8_t*)string("\xeb\x0e", 2).c_str(), 2);
            sym.mem->write(0x2000, (uint8_t*)string("ABCDEFGH").c_str(), 8);
            sym.regs->set(X86_EDI, exprcst(32, 0x2000));
            sym.regs->set(X86_EAX, exprcst(32, 0x47)); // "G"
            sym.regs->set(X86_ECX, exprcst(32, 7));
            sym.regs->set(X86_ZF, exprcst(32, 0));
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x2007, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            nb += _assert(  sym.regs->concretize(X86_ZF) == 1, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            
            
            sym.regs->set(X86_EDI, exprcst(32, 0x2000));
            sym.regs->set(X86_EAX, exprcst(32, 0x47)); // "G"
            sym.regs->set(X86_ECX, exprcst(32, 4));
            sym.regs->set(X86_ZF, exprcst(32, 0));
            sym.regs->set(X86_DF, exprcst(32, 0));
            sym.execute_from(0x1000, 1);
            nb += _assert(  sym.regs->concretize(X86_EIP) == 0x1002, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            nb += _assert(  sym.regs->concretize(X86_EDI) == 0x2004, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            nb += _assert(  sym.regs->concretize(X86_ZF) == 0, "ArchX86: failed to disassembly and/or execute REPNE SCASB");
            
            return nb;
        }
        
        
        
        /* =================================== */
        
        unsigned int block_branch_info(){
            unsigned int nb = 0;
            DisassemblerX86 disasm = DisassemblerX86(CPUMode::X86); 
            string code;
            
            IRBlock* block;
            IRBasicBlock bblkid;
            
            /* Undefined single jmp */
            code = string("\xff\xe0", 2); // jmp eax
            block = disasm.disasm_block(0, (code_t)code.c_str());
            nb += _assert( block->branch_type == BranchType::UNDEFINED, "IRBlock: got wrong branching info after 'jmp eax'");
            delete block;
            
            /* Single jmp */
            code = string("\xe8\x2f\x12\x00\x00", 5); // call 0x1234
            block = disasm.disasm_block(0, (code_t)code.c_str());
            nb += _assert( block->branch_type == BranchType::BRANCH, "IRBlock: got wrong branching info after 'call 0x1234'");
            nb += _assert( block->branch_target[1] == 0x1234, "IRBlock: got wrong branching info after 'call 0x1234'");
            delete block;
            
            /* Multibranch */
            code = string("\x77\x0e", 2); // ja 0x10
            block = disasm.disasm_block(0, (code_t)code.c_str());
            nb += _assert( block->branch_type == BranchType::MULTIBRANCH, "IRBlock: got wrong branching info after 'ja 0x10'");
            nb += _assert( block->branch_target[1] == 0x2, "IRBlock: got wrong branching info after 'ja 0x10'");
            nb += _assert( block->branch_target[0] == 0x10, "IRBlock: got wrong branching info after 'ja 0x10'");
            delete block;
            
            return nb;
            
        }
    }
}

using namespace test::archX86; 
// All unit tests 
void test_archX86(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing arch X86 support... " << std::flush;  
    
    total += reg_translation();
    total += disass_aaa();
    total += disass_aad();
    total += disass_aam();
    total += disass_aas();
    total += disass_adc();
    total += disass_adcx();
    total += disass_add();
    total += disass_and();
    total += disass_andn();
    total += disass_blsi();
    total += disass_blsmsk();
    total += disass_blsr();
    total += disass_bsf();
    total += disass_bsr();
    total += disass_bswap();
    total += disass_bt();
    total += disass_btc();
    total += disass_btr();
    total += disass_bts();
    total += disass_bzhi();
    total += disass_call();
    total += disass_cbw();
    total += disass_cdq();
    total += disass_clc();
    total += disass_cld();
    total += disass_cli();
    total += disass_cmc();
    total += disass_cmova();
    total += disass_cmovae();
    total += disass_cmovb();
    total += disass_cmovbe();
    total += disass_cmove();
    total += disass_cmovg();
    total += disass_cmovge();
    total += disass_cmovl();
    total += disass_cmovle();
    total += disass_cmovne();
    total += disass_cmovno();
    total += disass_cmovnp();
    total += disass_cmovns();
    total += disass_cmovo();
    total += disass_cmovp();
    total += disass_cmovs();
    total += disass_cmp();
    total += disass_cmpsb();
    total += disass_cmpsd();
    total += disass_cmpsw();
    total += disass_cmpxchg();
    total += disass_cwd();
    total += disass_cwde();
    total += disass_dec();
    total += disass_div();
    total += disass_idiv();
    total += disass_imul();
    total += disass_inc();
    total += disass_ja();
    total += disass_jae();
    total += disass_jb();
    total += disass_jbe();
    total += disass_jcxz();
    total += disass_je();
    total += disass_jecxz();
    total += disass_jg();
    total += disass_jge();
    total += disass_jl();
    total += disass_jle();
    total += disass_jmp();
    total += disass_jne();
    total += disass_jno();
    total += disass_jnp();
    total += disass_jns();
    total += disass_jo();
    total += disass_jp();
    total += disass_js();
    total += disass_lahf();
    total += disass_lea();
    total += disass_leave();
    total += disass_lodsb();
    total += disass_lodsd();
    total += disass_lodsw();
    total += disass_mov();
    total += disass_movsb();
    total += disass_movsd();
    total += disass_movsw();
    total += disass_movsx();
    total += disass_movzx();
    total += disass_mul();
    total += disass_neg();
    total += disass_nop();
    total += disass_not();
    total += disass_or();
    total += disass_pop();
    total += disass_popad();
    total += disass_push();
    total += disass_pushad();
    total += disass_rcl();
    total += disass_rcr();
    total += disass_ret();
    total += disass_rol();
    total += disass_ror();
    total += disass_sal();
    total += disass_sar();
    total += disass_scasb();
    total += disass_scasd();
    total += disass_scasw();
    total += disass_seta();
    total += disass_setae();
    total += disass_setb();
    total += disass_setbe();
    total += disass_sete();
    total += disass_setg();
    total += disass_setge();
    total += disass_setl();
    total += disass_setle();
    total += disass_setne();
    total += disass_setno();
    total += disass_setnp();
    total += disass_setns();
    total += disass_seto();
    total += disass_setp();
    total += disass_sets();
    total += disass_shr();
    total += disass_stc();
    total += disass_std();
    total += disass_sti();
    total += disass_stosb();
    total += disass_stosd();
    total += disass_stosw();
    total += disass_sub();
    total += disass_test();
    total += disass_xadd();
    total += disass_xchg();
    total += disass_xor();
    
    // Prefixes 
    total += disass_rep();
    total += disass_repe();
    total += disass_repne();
    
    // Other
    total += block_branch_info();
    //total += some_bench();
    
    cout << "\t" << total << "/" << total << green << "\tOK" << def << endl;
}
