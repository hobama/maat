#include "memory.hpp"
#include "symbolic.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>

using std::cout;
using std::endl; 
using std::string;
using std::strlen;

namespace test{
    namespace hash{
        
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int _x86_assert_algo_1(SymbolicEngine& sym, uint32_t in, uint32_t out){
            /* Init stack */
            sym.regs->set(X86_ESP, exprcst(32, 0x9000));
            sym.regs->set(X86_EBP, exprcst(32, 0x9000));
            /* Set input at esp + 0x4 */
            sym.mem->write(sym.regs->concretize(X86_ESP)+4, exprcst(32, in));

            sym.breakpoint.add(BreakpointType::ADDR, "end", 0x5a6);

            /* Execute */
            sym.execute_from(0x56d);
            sym.breakpoint.remove_all();
            
            /* Check res in eax */
            return _assert((uint32_t)sym.regs->concretize(X86_EAX) == out, "Hash emulation test: simple_algo_1: failed");
        }
        
        unsigned int x86_simple_algo_1(){
            unsigned int nb = 0;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            // hash function: 
            uint8_t code[] = {0x55,0x89,0xe5,0x83,0xec,0x10,0xc7,0x45,0xfc,0x0,0x0,0x0,0x0,0xeb,0x20,0x81,0x75,0x8,0x1,0x1,0x1,0x11,0x8b,0x45,0x8,0x8d,0x14,0xc5,0x0,0x0,0x0,0x0,0x8b,0x45,0x8,0xc1,0xe8,0x2,0x31,0xd0,0x89,0x45,0x8,0x83,0x45,0xfc,0x1,0x83,0x7d,0xfc,0x63,0x7e,0xda,0x8b,0x45,0x8,0xc9,0xc3};
            /* Argument is a uint32_t in [esp + 4]  
             * Res in eax 
             *         0x0000056d <+0>:	    push   %ebp
                       0x0000056e <+1>:	    mov    %esp,%ebp
                       0x00000570 <+3>:	    sub    $0x10,%esp
                       0x00000573 <+6>:	    movl   $0x0,-0x4(%ebp)
                       0x0000057a <+13>:	jmp    0x59c <transform+47>
                       0x0000057c <+15>:	xorl   $0x11010101,0x8(%ebp)
                       0x00000583 <+22>:	mov    0x8(%ebp),%eax
                       0x00000586 <+25>:	lea    0x0(,%eax,8),%edx
                       0x0000058d <+32>:	mov    0x8(%ebp),%eax
                       0x00000590 <+35>:	shr    $0x2,%eax
                       0x00000593 <+38>:	xor    %edx,%eax
                       0x00000595 <+40>:	mov    %eax,0x8(%ebp)
                       0x00000598 <+43>:	addl   $0x1,-0x4(%ebp)
                       0x0000059c <+47>:	cmpl   $0x63,-0x4(%ebp)
                       0x000005a0 <+51>:	jle    0x57c <transform+15>
                       0x000005a2 <+53>:	mov    0x8(%ebp),%eax
                       0x000005a5 <+56>:	leave
                       0x000005a6 <+57>:	ret
            */
            
            // code
            sym.mem->new_segment(0x0, 0x1000, MEM_FLAG_RWX);
            sym.mem->write(0x56d, code, 58);
            // stack
            sym.mem->new_segment(0x3000, 0x10000, MEM_FLAG_RW);
            
            nb += _x86_assert_algo_1(sym, 0, 0x219e5c12);
            nb += _x86_assert_algo_1(sym, 100, 0x6f8cdcd6);
            nb += _x86_assert_algo_1(sym, 200, 0x2d9c7d5e);
            nb += _x86_assert_algo_1(sym, 300, 0x6b8cfc96);
            nb += _x86_assert_algo_1(sym, 400, 0x08941f1e);
            nb += _x86_assert_algo_1(sym, 500, 0x46869fda);
            nb += _x86_assert_algo_1(sym, 600, 0x049e7f4a);
            nb += _x86_assert_algo_1(sym, 700, 0x428eff8a);
            nb += _x86_assert_algo_1(sym, 800, 0x63869d0a);
            nb += _x86_assert_algo_1(sym, 900, 0x21961d8a);
            nb += _x86_assert_algo_1(sym, 1000, 0x6f84bc46);
            nb += _x86_assert_algo_1(sym, 1100, 0x2d9c7dff);
            nb += _x86_assert_algo_1(sym, 1200, 0x4a849e37);
            nb += _x86_assert_algo_1(sym, 1300, 0x08941fbf);
            nb += _x86_assert_algo_1(sym, 1400, 0x4686be73);
            nb += _x86_assert_algo_1(sym, 1500, 0x04963ef3);
            nb += _x86_assert_algo_1(sym, 1600, 0x25961c63);
            nb += _x86_assert_algo_1(sym, 1700, 0x63869ca3);
            nb += _x86_assert_algo_1(sym, 1800, 0x21963c23);
            nb += _x86_assert_algo_1(sym, 1900, 0x6f84bce7);
            nb += _x86_assert_algo_1(sym, 2000, 0x0c9c5f6f);
            nb += _x86_assert_algo_1(sym, 2100, 0x4e8496d4);
            nb += _x86_assert_algo_1(sym, 2200, 0x0c94375c);
            nb += _x86_assert_algo_1(sym, 2300, 0x4286b798);
            nb += _x86_assert_algo_1(sym, 2400, 0x638ed518);
            nb += _x86_assert_algo_1(sym, 2500, 0x219e5598);
            nb += _x86_assert_algo_1(sym, 2600, 0x6786b548);
            nb += _x86_assert_algo_1(sym, 2700, 0x259635c8);
            nb += _x86_assert_algo_1(sym, 2800, 0x4a8cd604);
            nb += _x86_assert_algo_1(sym, 2900, 0x089c578c);
            nb += _x86_assert_algo_1(sym, 3000, 0x4e8cf644);
            nb += _x86_assert_algo_1(sym, 3100, 0x0c9437fd);
            nb += _x86_assert_algo_1(sym, 3200, 0x2d9c5475);
            nb += _x86_assert_algo_1(sym, 3300, 0x638ed4b1);
            nb += _x86_assert_algo_1(sym, 3400, 0x219e7431);
            nb += _x86_assert_algo_1(sym, 3500, 0x678ef4f1);
            nb += _x86_assert_algo_1(sym, 3600, 0x049e5661);
            nb += _x86_assert_algo_1(sym, 3700, 0x4a8cd6a5);
            nb += _x86_assert_algo_1(sym, 3800, 0x089c772d);
            nb += _x86_assert_algo_1(sym, 3900, 0x4e8cf6e5);
            nb += _x86_assert_algo_1(sym, 4000, 0x6f84956d);
            nb += _x86_assert_algo_1(sym, 4100, 0x21de4c16);
            nb += _x86_assert_algo_1(sym, 4200, 0x6fccedda);
            nb += _x86_assert_algo_1(sym, 4300, 0x2ddc6d5a);
            nb += _x86_assert_algo_1(sym, 4400, 0x4ac48f9a);
            nb += _x86_assert_algo_1(sym, 4500, 0x08d40f1a);
            nb += _x86_assert_algo_1(sym, 4600, 0x46c6aed6);
            nb += _x86_assert_algo_1(sym, 4700, 0x04de6f4e);
            nb += _x86_assert_algo_1(sym, 4800, 0x25d60cc6);
            nb += _x86_assert_algo_1(sym, 4900, 0x63c68d0e);
            nb += _x86_assert_algo_1(sym, 5000, 0x21d62c86);
            nb += _x86_assert_algo_1(sym, 5100, 0x6fc4ac42);
            nb += _x86_assert_algo_1(sym, 5200, 0x0cd40ef3);
            nb += _x86_assert_algo_1(sym, 5300, 0x4ac48e33);
            nb += _x86_assert_algo_1(sym, 5400, 0x08d42eb3);
            nb += _x86_assert_algo_1(sym, 5500, 0x46c6ae77);
            nb += _x86_assert_algo_1(sym, 5600, 0x67cecdff);
            nb += _x86_assert_algo_1(sym, 5700, 0x25d60c67);
            nb += _x86_assert_algo_1(sym, 5800, 0x63c6adaf);
            nb += _x86_assert_algo_1(sym, 5900, 0x21d62c27);
            nb += _x86_assert_algo_1(sym, 6000, 0x4ecccfeb);
            nb += _x86_assert_algo_1(sym, 6100, 0x0cdc4f6b);
            nb += _x86_assert_algo_1(sym, 6200, 0x4ec4a7d8);
            nb += _x86_assert_algo_1(sym, 6300, 0x0cd42758);
            nb += _x86_assert_algo_1(sym, 6400, 0x2ddc45d8);
            nb += _x86_assert_algo_1(sym, 6500, 0x63cec51c);
            nb += _x86_assert_algo_1(sym, 6600, 0x21de6494);
            nb += _x86_assert_algo_1(sym, 6700, 0x67c6a54c);
            nb += _x86_assert_algo_1(sym, 6800, 0x04de46c4);
            nb += _x86_assert_algo_1(sym, 6900, 0x4accc600);
            nb += _x86_assert_algo_1(sym, 7000, 0x08dc6680);
            nb += _x86_assert_algo_1(sym, 7100, 0x4ecce640);
            nb += _x86_assert_algo_1(sym, 7200, 0x6fccc4f1);
            nb += _x86_assert_algo_1(sym, 7300, 0x2ddc4471);
            nb += _x86_assert_algo_1(sym, 7400, 0x63cee5bd);
            nb += _x86_assert_algo_1(sym, 7500, 0x21de6435);
            nb += _x86_assert_algo_1(sym, 7600, 0x46c687fd);
            nb += _x86_assert_algo_1(sym, 7700, 0x04de4665);
            nb += _x86_assert_algo_1(sym, 7800, 0x4acce7a9);
            nb += _x86_assert_algo_1(sym, 7900, 0x08dc6729);
            nb += _x86_assert_algo_1(sym, 8000, 0x29d405a9);
            nb += _x86_assert_algo_1(sym, 8100, 0x6fc48569);
            nb += _x86_assert_algo_1(sym, 8200, 0x219e7d12);
            nb += _x86_assert_algo_1(sym, 8300, 0x6f8cfdd6);
            nb += _x86_assert_algo_1(sym, 8400, 0x0c941e5e);
            nb += _x86_assert_algo_1(sym, 8500, 0x4a849f96);
            nb += _x86_assert_algo_1(sym, 8600, 0x08943e1e);
            nb += _x86_assert_algo_1(sym, 8700, 0x4686beda);
            nb += _x86_assert_algo_1(sym, 8800, 0x67869c4a);
            nb += _x86_assert_algo_1(sym, 8900, 0x25961cca);
            nb += _x86_assert_algo_1(sym, 9000, 0x6386bc0a);
            nb += _x86_assert_algo_1(sym, 9100, 0x21963c8a);
            nb += _x86_assert_algo_1(sym, 9200, 0x4e8cdf46);
            nb += _x86_assert_algo_1(sym, 9300, 0x0c941eff);
            nb += _x86_assert_algo_1(sym, 9400, 0x4a84bf37);
            nb += _x86_assert_algo_1(sym, 9500, 0x08943ebf);
            nb += _x86_assert_algo_1(sym, 9600, 0x299c5d37);
            nb += _x86_assert_algo_1(sym, 9700, 0x678eddf3);
            nb += _x86_assert_algo_1(sym, 9800, 0x25963d63);
            nb += _x86_assert_algo_1(sym, 9900, 0x6386bda3);
            
            return nb;
            
        }
                
        unsigned int _x86_assert_md5(char*in, uint32_t out0, uint32_t out1, uint32_t out2, uint32_t out3){            
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            sym.enable(SymbolicEngineOption::OPTIMIZE_IR);
            
            // map md5 function at address 0x08048960
            std::ifstream file("tests/ressources/md5/md5_0x08048960_546.bin", std::ios::binary | std::ios::ate);
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            
            std::vector<char> buffer(size);
            if( ! file.read(buffer.data(), size)){
                cout << "\nFailed to get ressource to launch tests !" << endl << std::flush; 
                throw test_exception();
            }
            
            sym.mem->new_segment(0x8048950, 0x8050000 , MEM_FLAG_RWX);
            sym.mem->write(0x8048960, (uint8_t*)string(buffer.begin(), buffer.end()).c_str(), size);
            
            // memcpy function at address 0x806ae50
            std::ifstream file2("tests/ressources/md5/memcpy_0x0806ae50_115.bin", std::ios::binary | std::ios::ate);
            size = file2.tellg();
            file2.seekg(0, std::ios::beg);
            
            buffer = std::vector<char>(size);
            if( ! file2.read(buffer.data(), size)){
                cout << "\nFailed to get ressource to launch tests !" << endl << std::flush; 
                throw test_exception();
            }
            
            sym.mem->new_segment(0x806ae50, 0x8070000 , MEM_FLAG_RWX);
            sym.mem->write(0x806ae50, (uint8_t*)string(buffer.begin(), buffer.end()).c_str(), size);
            
            // many data sections
            std::ifstream file3("tests/ressources/md5/rodata_0x80ab000_0x2fff.bin", std::ios::binary | std::ios::ate);
            size = file3.tellg();
            file3.seekg(0, std::ios::beg);
            
            buffer = std::vector<char>(size);
            if( ! file3.read(buffer.data(), size)){
                cout << "\nFailed to get ressource to launch tests !" << endl << std::flush; 
                throw test_exception(); 
            }
            sym.mem->new_segment(0x80a0000, 0x80df000 , MEM_FLAG_RW);
            sym.mem->write(0x80ab000, (uint8_t*)string(buffer.begin(), buffer.end()).c_str(), size);
            
            // stack
            sym.mem->new_segment(0xffff0000, 0xffffe000, MEM_FLAG_RW);
            // argument to hash
            sym.mem->new_segment(0x11000, 0x12000, MEM_FLAG_RW);
            
            /* Init stack */
            sym.regs->set(X86_ESP, exprcst(32, 0xffffd15c));
            sym.regs->set(X86_EBP, exprcst(32, 0xffffd15c));
            /* Set input string at esp+4 and length at esp+8 ??? */
            sym.mem->write(0x11000, (uint8_t*)in, strlen(in));
            sym.mem->write((uint32_t)sym.regs->concretize(X86_ESP)+4, exprcst(32, 0x11000));
            sym.mem->write((uint32_t)sym.regs->concretize(X86_ESP)+8, exprcst(32, strlen(in)));
            
            sym.breakpoint.add(BreakpointType::ADDR, "end", 0x8048b81 );

            /* Execute */
            sym.execute_from(0x8048960);
            sym.breakpoint.remove_all();
            
            /* Check res at 0x80dbca4  */
            return _assert( (uint32_t)sym.mem->read(0x80dbcac, 4)->concretize(sym.vars) == out0 &&
                            (uint32_t)sym.mem->read(0x80dbca4, 4)->concretize(sym.vars) == out1 &&
                            (uint32_t)sym.mem->read(0x80dbca8, 4)->concretize(sym.vars) == out2 &&
                            (uint32_t)sym.mem->read(0x80dbcb0, 4)->concretize(sym.vars) == out3
                            , "Hash emulation test: md5: failed");
        }
        
        unsigned int x86_md5(){
            /* md5 binary compiled with:
             * gcc -m32 -fno-pie -mno-mmx -mno-sse -mno-sse2 -O2 -fno-stack-protector md5.c -o md5
             */
            
            unsigned int nb = 0;
            
            nb += _x86_assert_md5((char*)"msul", 0xec04d6b3, 0xf4d9196c, 0x9015e930, 0xbb668ece);
            nb += _x86_assert_md5((char*)"ixtykuaw", 0xfadace91, 0x86a333a8, 0xce0cc2f0, 0x97524cdc);
            nb += _x86_assert_md5((char*)"hzgvwzbumqca", 0xff70d0f1, 0x0c08605c, 0xe0b1bc1a, 0x3db4837b);
            nb += _x86_assert_md5((char*)"ulfqvcfosnzuzrhf", 0x352d0acc, 0x2b1f2cec, 0x07654b0c, 0x193e2328);
            nb += _x86_assert_md5((char*)"fieuoqwdnazaeqelxawe", 0x1848c685, 0x02fc8360, 0x31812820, 0x37721897);
            nb += _x86_assert_md5((char*)"bsezeoggylqoxdujjyktqvrb", 0x65e1e27e, 0x7844616d, 0xb70e1400, 0x9708798f);
            nb += _x86_assert_md5((char*)"dznkzisambwwhieughjmuvegbtyj", 0x81cac364, 0xd0f5575c, 0xfb9be7c0, 0x1b3b761a);
            nb += _x86_assert_md5((char*)"qcsikxrystkgqwuacwlgaqzcqqdsvqdo", 0x2375a159, 0xe4a7510d, 0x9ef8afb0, 0xf89d0483);
            nb += _x86_assert_md5((char*)"wrosmjwowzzktacowgcjunnhgvhhfqqxwnwm", 0x69e78e84, 0xbc36bf0d, 0x12643cde, 0xc4b7808e);
            nb += _x86_assert_md5((char*)"kbhczluprlqjviquiqqguoxdohyuswnnueelijoe", 0xa5197bd1, 0xda7493c5, 0xdfc4ab3f, 0xa3833f8f);
            nb += _x86_assert_md5((char*)"howutpbbdrvokubqfczqpfspgsxnynsdmgeybdwltgjd", 0x2fb4e535, 0x78bf0624, 0xbb865b55, 0x3dfbf6c7);
            nb += _x86_assert_md5((char*)"qovjjukmucykhyglreiejjlaqfcyfjufmgbwffnlqbiycguu", 0x68757050, 0xc0de7040, 0x634128a4, 0x1a1e4f72);
            nb += _x86_assert_md5((char*)"vleuoyfqkczxzcxsdnfbukqnxkbdlxdfziaaffmittomfxiahaxd", 0xdfc57543, 0xc3ef028c, 0xa5f8b207, 0x2fe0558e);
            nb += _x86_assert_md5((char*)"afuismarynwhfenbhqgvwuakhmivrtozjqhodfsjfknrslmkgappeyiz", 0xaadee9ed, 0xd6f18088, 0x4bad2e63, 0x125a8bf9);
            nb += _x86_assert_md5((char*)"lutimgtisetqpsyjuactstgtayqyldjifmoegkbobixbllspwkhuqtmmsyuh", 0xeca24a93, 0x98a52ec1, 0xcdb7843e, 0x5a0d3e7c);
            nb += _x86_assert_md5((char*)"uhwdudmkfwtpiinkysbpithjjwajdjoizgujcdibtmujvcyzumisejcrxmkzompj", 0x1808705a, 0x0f8eb710, 0xb8cfcdcc, 0xdc991b7a);
            nb += _x86_assert_md5((char*)"czhpnrgyogstuxihwxaxrfnnnhaijeamnaqsurketpzhylktnmrenbbukzswvtmakrno", 0x88942048, 0x2ac69f81, 0x6a863a05, 0xd030616d);
            nb += _x86_assert_md5((char*)"znocaqtxynsifzvujjjbabtkbbvqmfntgxtfmdzkgnghquguaqwqondhcpvkbtoxzfunmdoq", 0xa8dae03d, 0x073da867, 0x92e2279f, 0xbcfd11cc);
            nb += _x86_assert_md5((char*)"zeflsjrhdluymxroaxbnyotchfmcroaawhiraveavvsopgqnpbbjjpipuppuibmbasxyffekotez", 0x147137e7, 0x69a38149, 0x4d7c3a4f, 0xb0a0394e);
            nb += _x86_assert_md5((char*)"wuzqhuprrwdlflysnqekmlmnzecohjfrjrvvjxenmrhzsewkduzhzesahwvyckbownqzmbccykqlhktz", 0xe506a6be, 0xd10b3111, 0xb112d311, 0x177946a2);
            nb += _x86_assert_md5((char*)"ughtvwpsarhhcwshtudlofzkngrzdcnakfczkobykojbsvwqqyhmnkndqgkytcmgmbwwyatghefobkblaxti", 0x0f5881d8, 0xc7bfb729, 0x1c80eae5, 0x69685dd4);
            nb += _x86_assert_md5((char*)"lzxwrihlhxcvdowajorjthxhwprepbsqdlyzdfcwpqnuyyscpuavavczxxfpgnzkpxltnneptvrqbqwkeqfhmjxi", 0x979a7cc2, 0x7d0a94f0, 0x00cc5ccb, 0x64cb42c9);
            nb += _x86_assert_md5((char*)"anistqsfqyovheyggdlzrxssgoheqomjeukfbwdqqdrptmlaidglzvvuqowzvljwjdvfaylinwonnkbnenursnifpsfn", 0x4be34004, 0x7447c735, 0xac23e502, 0xb752723a);
            nb += _x86_assert_md5((char*)"haxhplsdizyeprwvwifzhmchgxkcgebvdptlzahorytwymnpbkpponzsnivxifntatksgmsqhthoviepqiajuqkbbqrzjqcn", 0xf0d1b693, 0x7b04af02, 0x68a8a9d3, 0x00bff087);

            return nb;
            
        }
    }
}

using namespace test::hash; 
// All unit tests 
void test_hash(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing hash algos emulation... " << std::flush;  
    total += x86_simple_algo_1();
    total += x86_md5();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
