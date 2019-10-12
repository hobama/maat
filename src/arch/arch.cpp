#include "arch.hpp"
#include <iostream>


Arch::Arch(int _bits, int _octets, int _nb, CPUMode _mode, Disassembler* _disasm): 
    bits(_bits), octets(_octets), nb_regs(_nb), mode(_mode), disasm(_disasm){}
    
Arch::~Arch(){
    delete disasm;
    disasm = nullptr;
}
