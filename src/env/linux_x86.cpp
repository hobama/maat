#include "environment.hpp"
#include "exception.hpp"
#include "linux_x86.hpp"
#include "libc_common.hpp"
#include <vector>
#include <cstdlib>
#include <sstream>
#include <ctime>

using std::stringstream;

/* ==============================================
 *              Linux X86 functions
 * ============================================= */

extern int _global_stdin_read_count;


// ============ __libc_start_main ===============  
// int __libc_start_main(int *(main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
vector<size_t> _simu_linux_x86_libc_start_main_args{4, 4, 4, 4, 4, 4, 4 };
EnvCallbackReturn _simu_linux_x86_libc_start_main(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t main = (args[0]->as_unsigned(sym.vars));
    addr_t argc = (args[1]->as_unsigned(sym.vars));
    addr_t argv = (args[2]->as_unsigned(sym.vars));
    //addr_t init = (args[3]->as_unsigned(sym.vars));
    //addr_t fini = (args[4]->as_unsigned(sym.vars));
    //addr_t rtld_fini = (args[5]->as_unsigned(sym.vars));
    //addr_t end_stack = (args[6]->as_unsigned(sym.vars));

    // Push argc, argv
    sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 4) );
    sym.mem->write(sym.regs->as_unsigned(X86_ESP), argv, 4);
    sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 4) );
    sym.mem->write(sym.regs->as_unsigned(X86_ESP), argc, 4);
    
    // Push return address after main
    sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 4) );
    sym.mem->write(sym.regs->as_unsigned(X86_ESP), sym.get_symbol_address("exit"), 4);
    
    // HACK: set return address of __libc_start_main to main so that when we 
    // execute _abi_return we go to main :)
    sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 4) );
    sym.mem->write(sym.regs->as_unsigned(X86_ESP), main, 4);
    
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS); 
}

// ============ __ctype_b_loc ===============  
// const unsigned short int **ctype_b_loc(void);
vector<size_t> _simu_linux_x86_ctype_b_loc_args{};
EnvCallbackReturn _simu_linux_x86_ctype_b_loc(SymbolicEngine& sym, vector<Expr> args){
    // Return the table
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, exprcst(32,sym.env->ctype_b_loc_table_ptr));
}

// ============ abort =============== 
// void abort(void);
vector<size_t> _simu_linux_x86_abort_args{};

// ============ atoi =============== 
// int atoi (const char * str);
vector<size_t> _simu_linux_x86_atoi_args{4};

// ============ calloc =============== 
// void* calloc (size_t num, size_t size);
vector<size_t> _simu_linux_x86_calloc_args{4, 4};

// ============ exit =============== 
vector<size_t> _simu_linux_x86_exit_args{4};

// ============ fflush =============== 
// int fflush ( FILE * stream );
vector<size_t> _simu_linux_x86_fflush_args{4};

// ============ free =============== 
// void free (void* ptr);
vector<size_t> _simu_linux_x86_free_args{4};

// ============ getenv =============== 
// char* getenv (const char* name);
vector<size_t> _simu_linux_x86_getenv_args{4};

// ============ getpagesize =============== 
vector<size_t> _simu_linux_x86_getpagesize_args{};

// ============ malloc =============== 
// void* malloc (size_t size);
vector<size_t> _simu_linux_x86_malloc_args{4};

// ============ memcmp =============== 
// int memcmp ( const void * ptr1, const void * ptr2, size_t num );
vector<size_t> _simu_linux_x86_memcmp_args{4, 4, 4};
IRBlock* _ir_simu_linux_x86_memcmp(){
    IRBlock* irblock = new IRBlock("memcmp emulation", 0, 0);
    vector<IROperand> args = _ir_abi_get_args(ABI::X86_CDECL, _simu_linux_x86_memcmp_args, *irblock);
    IROperand cmp = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IROperand mem1 = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IROperand mem2 = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IRBasicBlockId bblkid, test_num, ret, inc_loop;
    
    bblkid = irblock->new_bblock();
    test_num = irblock->new_bblock();
    inc_loop = irblock->new_bblock();
    ret = irblock->new_bblock();
    
    // load the two chars 
    irblock->add_instr(bblkid, ir_ldm(mem1, args[0], 0x0));
    irblock->add_instr(bblkid, ir_ldm(mem2, args[1], 0x0));
    irblock->add_instr(bblkid, ir_sub(cmp, mem1, mem2, 0x0));
    // exit if they are different (warning! we don't actually check which one is bigger than the other)
    irblock->add_instr(bblkid, ir_bcc(cmp, ir_cst(ret, 31, 0), ir_cst(test_num, 31, 0), 0x0));
    
    // test if num is 0
    irblock->add_instr(test_num, ir_sub(args[2], args[2], ir_cst(1, 31, 0), 0x0));
    irblock->add_instr(test_num, ir_bcc(args[2], ir_cst(inc_loop, 31, 0), ir_cst(ret, 31, 0), 0x0));
    
    //increment counters and loop
    irblock->add_instr(inc_loop, ir_add(args[0], args[0], ir_cst(1, args[0].size-1, 0x0), 0x0));
    irblock->add_instr(inc_loop, ir_add(args[1], args[1], ir_cst(1, args[1].size-1, 0x0), 0x0));
    irblock->add_instr(inc_loop, ir_bcc(ir_cst(1, 31, 0), ir_cst(bblkid, 31, 0), ir_none(), 0x0));

    // return value in EAX
    irblock->add_instr(ret, ir_mov(ir_var(X86_EAX, 31, 0), ir_cst(0, 31, 0), 0x0));
    irblock->add_instr(ret, ir_add(ir_var(X86_EAX, 7, 0), ir_var(X86_EAX, 7, 0), cmp, 0x0));
    
    _ir_abi_return(ABI::X86_CDECL, *irblock);
    return irblock;
}

// ============ memset =============== 
// void * memset ( void * ptr, int value, size_t num );
vector<size_t> _simu_linux_x86_memset_args{4, 4, 4};

// ============ memcpy =============== 
// void *memcpy(void *dest, const void *src, size_t n);
vector<size_t> _simu_linux_x86_memcpy_args{4, 4, 4};

// ============ puts =============== 
// int puts ( const char * str );
vector<size_t> _simu_linux_x86_puts_args{4};

// ============ printf =============== 
// int printf ( const char * format, ... );
vector<size_t> _simu_linux_x86_printf_args{4};

// ============ rand =============== 
// int rand (void);
vector<size_t> _simu_linux_x86_rand_args{};

// ============ scanf =============== 
// int scanf ( const char * format, ... );
vector<size_t> _simu_linux_x86_scanf_args{4};

// ============ sprintf =============== 
// int sprintf ( char * str, const char * format, ... );
vector<size_t> _simu_linux_x86_sprintf_args{4, 4};

// ============ srand =============== 
// void srand (unsigned int seed);
vector<size_t> _simu_linux_x86_srand_args{4};

// ============ strchr =============== 
// char * strchr ( char * str, int character );
vector<size_t> _simu_linux_x86_strchr_args{4, 4};
IRBlock* _ir_simu_linux_x86_strchr(){
    IRBlock* irblock = new IRBlock("strchr emulation", 0, 0);
    vector<IROperand> args = _ir_abi_get_args(ABI::X86_CDECL, _simu_linux_x86_strchr_args, *irblock);
    IROperand cmp = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IROperand character = ir_tmp(args[1].tmp(), 7, 0); // Extract lower 8 bits to convert int into unsigned char
    IROperand c = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IRBasicBlockId bblkid, test_end_str, end, inc_loop, found, not_found;
    
    bblkid = irblock->new_bblock();
    test_end_str = irblock->new_bblock();
    inc_loop = irblock->new_bblock();
    found = irblock->new_bblock();
    not_found = irblock->new_bblock();
    end = irblock->new_bblock();
    
    // load char from the string and compare
    irblock->add_instr(bblkid, ir_ldm(c, args[0], 0x0));
    irblock->add_instr(bblkid, ir_sub(cmp, c , character , 0x0));
    // exit if they are different (warning! we don't actually check which one is bigger than the other)
    irblock->add_instr(bblkid, ir_bcc(cmp, ir_cst(test_end_str, 31, 0), ir_cst(found, 31, 0), 0x0));
    
    // test if end of string
    irblock->add_instr(test_end_str, ir_bcc(c, ir_cst(inc_loop, 31, 0), ir_cst(not_found, 31, 0), 0x0));
    
    // increment counters and loop
    irblock->add_instr(inc_loop, ir_add(args[0], args[0], ir_cst(1, args[0].size-1, 0x0), 0x0));
    irblock->add_instr(inc_loop, ir_bcc(ir_cst(1, 31, 0), ir_cst(bblkid, 31, 0), ir_none(), 0x0));

    // found, return the pointer
    irblock->add_instr(found, ir_mov(ir_var(X86_EAX, 31, 0), args[0], 0x0));
    irblock->add_instr(found, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), 0x0));
    
    // not found, return nullptr
    irblock->add_instr(not_found, ir_mov(ir_var(X86_EAX, 31, 0), ir_cst(0, 31, 0), 0x0));
    irblock->add_instr(not_found, ir_bcc(ir_cst(1, 31, 0), ir_cst(end, 31, 0), ir_none(), 0x0));

    _ir_abi_return(ABI::X86_CDECL, *irblock);
    return irblock;
}

// ============ strcmp =============== 
// int strcmp ( const char * str1, const char * str2 );
vector<size_t> _simu_linux_x86_strcmp_args{4, 4};
// Simulate as IR
IRBlock* _ir_simu_linux_x86_strcmp(){
    IRBlock* irblock = new IRBlock("strcmp emulation", 0, 0);
    vector<IROperand> args = _ir_abi_get_args(ABI::X86_CDECL, _simu_linux_x86_strcmp_args, *irblock);
    IROperand cmp = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IROperand str1 = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IROperand str2 = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IRBasicBlockId bblkid, test_str1_zero, test_str2_zero, ret, inc_loop;
    bblkid = irblock->new_bblock();
    test_str1_zero = irblock->new_bblock();
    test_str2_zero = irblock->new_bblock();
    inc_loop = irblock->new_bblock();
    ret = irblock->new_bblock();
    // load the two chars 
    irblock->add_instr(bblkid, ir_ldm(str1, args[0], 0x0));
    irblock->add_instr(bblkid, ir_ldm(str2, args[1], 0x0));
    irblock->add_instr(bblkid, ir_sub(cmp, str1, str2, 0x0));
    // exit if they are different (warning! we don't actually check which one is bigger than the other)
    irblock->add_instr(bblkid, ir_bcc(cmp, ir_cst(test_str1_zero, 31, 0), ir_cst(ret, 31, 0), 0x0));
    
    // test if str1 is null
    irblock->add_instr(test_str1_zero, ir_bcc(str1, ir_cst(test_str2_zero, 31, 0), ir_cst(ret, 31, 0), 0x0));
    // test if str2 is null
    irblock->add_instr(test_str2_zero, ir_bcc(str2, ir_cst(inc_loop, 31, 0), ir_cst(ret, 31, 0), 0x0));
    
    //increment counters and loop
    irblock->add_instr(inc_loop, ir_add(args[0], args[0], ir_cst(1, args[0].size-1, 0x0), 0x0));
    irblock->add_instr(inc_loop, ir_add(args[1], args[1], ir_cst(1, args[1].size-1, 0x0), 0x0));
    irblock->add_instr(inc_loop, ir_bcc(ir_cst(1, 31, 0), ir_cst(bblkid, 31, 0), ir_none(), 0x0));

    // return value in EAX
    irblock->add_instr(ret, ir_mov(ir_var(X86_EAX, 31, 0), ir_cst(0, 31, 0), 0x0));
    irblock->add_instr(ret, ir_add(ir_var(X86_EAX, 7, 0), ir_var(X86_EAX, 7, 0), cmp, 0x0));
    
    _ir_abi_return(ABI::X86_CDECL, *irblock);
    return irblock;
}

// ============ strcpy =============== 
// char * strcpy ( char * destination, const char * source );
vector<size_t> _simu_linux_x86_strcpy_args{4, 4};

// ============ strlen =============== 
// size_t strlen ( const char * str );
vector<size_t> _simu_linux_x86_strlen_args{4};
// As IR
IRBlock* _ir_simu_linux_x86_strlen(){
    IRBlock* irblock = new IRBlock("strlen emulation", 0, 0);
    vector<IROperand> args = _ir_abi_get_args(ABI::X86_CDECL, _simu_linux_x86_strlen_args, *irblock);
    IROperand counter = ir_tmp(irblock->_nb_tmp_vars++, 31, 0);
    IROperand c = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IRBasicBlockId init, test_zero, inc_loop, ret;
    init = irblock->new_bblock();
    test_zero = irblock->new_bblock();
    inc_loop = irblock->new_bblock();
    ret = irblock->new_bblock();
    
    /* Init counter */
    irblock->add_instr(init, ir_mov(counter, ir_cst(0, 31, 0), 0x0));
    irblock->add_instr(init, ir_bcc(ir_cst(1, 31, 0), ir_cst(test_zero, 31, 0), ir_none(), 0x0));
    
    /* Test zero */
    irblock->add_instr(test_zero, ir_ldm(c, args[0], 0x0));
    irblock->add_instr(test_zero, ir_bcc(c, ir_cst(inc_loop, 31, 0), ir_cst(ret, 31, 0), 0x0));
    
    /* Increment and loop */
    irblock->add_instr(inc_loop, ir_add(counter, counter, ir_cst(1, 31, 0), 0x0));
    irblock->add_instr(inc_loop, ir_add(args[0], args[0], ir_cst(1, 31, 0), 0x0));
    irblock->add_instr(inc_loop, ir_bcc(ir_cst(1, 31, 0), ir_cst(test_zero, 31, 0), ir_none(), 0x0));
    
    /* Return */
    irblock->add_instr(ret, ir_mov(ir_var(X86_EAX, 31, 0), counter, 0x0));
    
    _ir_abi_return(ABI::X86_CDECL, *irblock);
    return irblock;
}

// ============ strrchr =============== 
// char * strchr ( char * str, int character );
vector<size_t> _simu_linux_x86_strrchr_args{4, 4};
// As IR
IRBlock* _ir_simu_linux_x86_strrchr(){
    IRBlock* irblock = new IRBlock("strrchr emulation", 0, 0);
    vector<IROperand> args = _ir_abi_get_args(ABI::X86_CDECL, _simu_linux_x86_strrchr_args, *irblock);
    IROperand cmp = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IROperand character = ir_tmp(args[1].tmp(), 7, 0); // Extract lower 8 bits to convert int into unsigned char
    IROperand c = ir_tmp(irblock->_nb_tmp_vars++, 7, 0);
    IROperand last = ir_tmp(irblock->_nb_tmp_vars++, 31, 0); // return value, last occurence of character
    IRBasicBlockId loop_body, test_end_str, end, inc_loop, init, found;
    
    init = irblock->new_bblock();
    loop_body = irblock->new_bblock();
    test_end_str = irblock->new_bblock();
    inc_loop = irblock->new_bblock();
    found = irblock->new_bblock();
    end = irblock->new_bblock();
    
    // init res to nullptr
    irblock->add_instr(init, ir_mov(last, ir_cst(0, 31, 0), 0x0));
    irblock->add_instr(init, ir_bcc(ir_cst(1, 31, 0), ir_cst(loop_body, 31, 0), ir_none(), 0x0));
    
    // load char from the string and compare
    irblock->add_instr(loop_body, ir_ldm(c, args[0], 0x0));
    irblock->add_instr(loop_body, ir_sub(cmp, c , character , 0x0));
    // if they are different test if end of string, otherwise update 'last'
    irblock->add_instr(loop_body, ir_bcc(cmp, ir_cst(test_end_str, 31, 0), ir_cst(found, 31, 0), 0x0));
    
    // found, update 'last'
    irblock->add_instr(found, ir_mov(last, args[0], 0x0));
    irblock->add_instr(found, ir_bcc(ir_cst(1, 31, 0), ir_cst(test_end_str, 31, 0), ir_none(), 0x0));
    
    // test if end of string
    irblock->add_instr(test_end_str, ir_bcc(c, ir_cst(inc_loop, 31, 0), ir_cst(end, 31, 0), 0x0));
    
    // increment counters and loop
    irblock->add_instr(inc_loop, ir_add(args[0], args[0], ir_cst(1, args[0].size-1, 0), 0x0));
    irblock->add_instr(inc_loop, ir_bcc(ir_cst(1, 31, 0), ir_cst(loop_body, 31, 0), ir_none(), 0x0));

    // return value is 'last' 
    irblock->add_instr(end, ir_mov(ir_var(X86_EAX, 31, 0), last, 0x0));

    _ir_abi_return(ABI::X86_CDECL, *irblock);
    return irblock;
}

/* ==============================================
 *             System calls functions
 * ============================================= */ 

// ============ sys_brk =============== 
/* int brk(void *addr); */
vector<size_t> _simu_linux_x86_sys_brk_args{4};
EnvCallbackReturn _simu_linux_x86_sys_brk(SymbolicEngine& sym, vector<Expr> args){
    addr_t addr = args[0]->as_unsigned(sym.vars);
    bool found_heap = false;
    
    // Find the heap's end address
    for( MemSegment* seg : sym.mem->segments()){
        if( seg->name == "Heap" ){
            found_heap = true;
            break;
        }
    }
    if( !found_heap ){
        throw env_exception("Linux X86 syscall brk(): didn't find 'Heap' segment!");
    }
    
    // We don't actually resize the heap, segments resizing is to implement later
    // if needed. So we simulate success by returning the 'addr' argument as if it
    // is the new break even though it's not
    
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, addr);
}

// ============ sys_getpid =============== 
// pid_t getpid(void);
vector<size_t> _simu_linux_x86_sys_getpid_args{};
EnvCallbackReturn _simu_linux_x86_sys_getpid(SymbolicEngine& sym, vector<Expr> args){    
    // Arbitrary PID 0x1234
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, 0x1234);
}

// ============ sys_newuname =============== 
/* Takes a pointer to a struct and fills it: 
 * struct utsname {
               char sysname[];    // Operating system name (e.g., "Linux") 
               char nodename[];   // Name within "some implementation-defined
                                     network" 
               char release[];    // Operating system release (e.g., "2.6.28") 
               char version[];    // Operating system version 
               char machine[];    // Hardware identifier 
               char domainname[]; // NIS or YP domain name
           };
    With arrays of size 65
*/
vector<size_t> _simu_linux_x86_sys_newuname_args{4};
EnvCallbackReturn _simu_linux_x86_sys_newuname(SymbolicEngine& sym, vector<Expr> args){
    // With stdcall
    addr_t utsname = args[0]->as_unsigned(sym.vars);
    
    // Write OS name
    sym.mem->write(utsname, (uint8_t*)"Linux", 6);
    // Write OS release and version
    sym.mem->write(utsname + 65*2, (uint8_t*)"4.15.0", 7);
    sym.mem->write(utsname + 65*3, (uint8_t*)"4.15.0", 7);
    // Fill other fields with null string
    sym.mem->write(utsname + 65, 0, (unsigned int)4);
    sym.mem->write(utsname + 65*5, 0, (unsigned int)4);
    sym.mem->write(utsname + 65*6, 0, (unsigned int)4);
    
    // On success return zero in EAX
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, 0);
}

// ============ sys_ptrace =============== 
// long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
vector<size_t> _simu_linux_x86_sys_ptrace_args{4, 4, 4, 4};
EnvCallbackReturn _simu_linux_x86_sys_ptrace(SymbolicEngine& sym, vector<Expr> args){
    // Supported requests
    int PTRACEME = 0;
    // With cdecl ABI
    cst_t request = args[0]->as_unsigned(sym.vars);
    // Process request
    if( request == PTRACEME ){
        // Just return a positive value to indicate success
        return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, 0);
    }else{
        return EnvCallbackReturn(ENV_CALLBACK_FAIL);
    }
}

// =============== sys_read ===============
/* ssize_t read(int fd, void *buf, size_t count);
   Ret value in eax so it works for all linux calling conventions, cdecl, sysenter, and int80 :) */
vector<size_t> _simu_linux_x86_sys_read_args{4, 4, 4};
EnvCallbackReturn _simu_linux_x86_sys_read(SymbolicEngine& sym, vector<Expr> args){
    int fd = (int32_t)(args[0]->concretize(sym.vars));
    addr_t buf = args[1]->as_unsigned(sym.vars);
    size_t count = args[2]->as_unsigned(sym.vars);
    int res;
    int i;
    char c;
    
    /* If stdout or stdin */
    if( fd >= 0 && fd < 2 ){
        for( i = 0; i < count; i++){
            std::stringstream ss;
            ss << "stdin_" << std::dec << _global_stdin_read_count << "_" << i;
            std::cin.get(c);
            // What we read from stdin is tainted !
            sym.vars->set(ss.str(), (cst_t)c);
            sym.mem->write(buf++, exprvar(8, ss.str(), Taint::TAINTED), sym.vars);
            if( c == '\0' || c == '\n' )
                break;
        }
        res = i;
    }else if( fd == 2 ){
            throw env_exception("Linux x86 read() emulation: reading from stderr not supported!");
    }else{
        EnvFile* file = sym.env->filesystem.file_by_num(fd);
        if( file == nullptr ){
            throw env_exception("Linux x86 read() emulation: got invalid fd!");
        }
        res = file->read_to_buffer(sym, buf, count);
    }

    _global_stdin_read_count++;
    // Return number of bytes written
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, res);
}

// =============== sys_signal ===============
//     typedef void (*sighandler_t)(int);
//     sighandler_t signal(int signum, sighandler_t handler);
/* Ret value in eax so it works for all linux calling conventions, cdecl, sysenter, and int80 :) */
vector<size_t> _simu_linux_x86_sys_signal_args{4, 4};
EnvCallbackReturn _simu_linux_x86_sys_signal(SymbolicEngine& sym, vector<Expr> args){
    int signum = (int32_t)(args[0]->concretize(sym.vars));
    addr_t new_handler = args[1]->as_unsigned(sym.vars);
    addr_t prev_handler;
    unordered_map<int, addr_t>::iterator it;
    // Find previous signal handler
    if( (it = sym.env->current_signal_handlers.find(signum)) == sym.env->current_signal_handlers.end()){
        //prev_handler = -1; // SIG_ERR
        throw env_exception(ExceptionFormatter() << "signal() with signum = " << std::dec << signum 
                << ": can not return previous handler because none is defined for this signal!"  );
    }else{
        prev_handler = it->second;
    }
    // Set new handler
    sym.env->current_signal_handlers[signum] = new_handler;
    
    // Return value is the previous handler address
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, prev_handler);
}

// =============== sys_time ===============
// time_t time(time_t *tloc);
/* Ret value in eax so it works for all linux calling conventions, cdecl, sysenter, and int80 :) */
vector<size_t> _simu_linux_x86_sys_time_args{4, 4};
EnvCallbackReturn _simu_linux_x86_sys_time(SymbolicEngine& sym, vector<Expr> args){
    addr_t tloc = args[0]->as_unsigned(sym.vars);
    // Get time
    time_t t = time(NULL);
    
    // If arg not null, store the return value there
    if( tloc != 0 ){
        sym.mem->write(tloc, t, (unsigned int)sizeof(time_t));
    }
    
    // Return value is in EAX
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, t);
}

// =============== sys_write ===============
/* ssize_t write(int fd, const void *buf, size_t count);  */
/* Ret value in eax so it works for all linux calling conventions, cdecl, sysenter, and int80 :) */
vector<size_t> _simu_linux_x86_sys_write_args{4, 4, 4};
EnvCallbackReturn _simu_linux_x86_sys_write(SymbolicEngine& sym, vector<Expr> args){
    int fd = (int32_t)(args[0]->concretize(sym.vars));
    addr_t buf = args[1]->as_unsigned(sym.vars);
    size_t count = args[2]->as_unsigned(sym.vars);
    int res;
    int i;
    
    /* If stdout or stderr or stdin */
    if( fd >= 0 && fd < 3 ){
        for( i = 0; i < count; i++){
            char c = (char)sym.mem->read(buf++, 1)->concretize(sym.vars);
            switch(fd){
                case 0: case 1: std::cout << c; break;
                case 2: std::cerr << c; break;
            }
        }
        res = i;
    }else{
        EnvFile* file = sym.env->filesystem.file_by_num(fd);
        if( file == nullptr ){
            throw env_exception("Linux x86 write() emulation: got invalid fd!");
        }
        res = file->write_from_buffer(sym, buf, count);
    }

    // Return number of bytes written
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, res);
}

/* ==============================================
 *             Signals & Handlers
 * ============================================= */ 

vector<size_t> _simu_linux_x86_signal_handler_args{4};
EnvCallbackReturn _simu_linux_x86_sigtrap_handler(SymbolicEngine& sym, vector<Expr> args){
    // Debug exception, do nothing
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS);
}

vector<EnvFunction*> default_linux_x86_simulated_functions(){
    return vector<EnvFunction*>{
    /* Functions */
    new EnvFunction(_simu_libc_common_not_implemented, ENV_CALLBACK_NOT_IMPLEMENTED_NAME, ABI::X86_CDECL, vector<size_t>()),
    new EnvFunction(_simu_linux_x86_ctype_b_loc, "__ctype_b_loc", ABI::X86_CDECL, _simu_linux_x86_ctype_b_loc_args),
    new EnvFunction(_simu_linux_x86_libc_start_main, "__libc_start_main", ABI::X86_CDECL, _simu_linux_x86_libc_start_main_args),
    new EnvFunction(_simu_libc_common_abort, "abort", ABI::X86_CDECL, _simu_linux_x86_abort_args),
    new EnvFunction(_simu_libc_common_atoi, "atoi", ABI::X86_CDECL, _simu_linux_x86_atoi_args),
    new EnvFunction(_simu_libc_common_calloc, "calloc", ABI::X86_CDECL, _simu_linux_x86_calloc_args),
    new EnvFunction(_simu_libc_common_exit, "exit", ABI::X86_CDECL, _simu_linux_x86_exit_args),
    new EnvFunction(_simu_libc_common_fflush, "fflush", ABI::X86_CDECL, _simu_linux_x86_fflush_args),
    new EnvFunction(_simu_libc_common_free, "free", ABI::X86_CDECL, _simu_linux_x86_free_args),
    new EnvFunction(_simu_libc_common_getenv, "getenv", ABI::X86_CDECL, _simu_linux_x86_getenv_args),
    new EnvFunction(_simu_libc_common_getpagesize, "getpagesize", ABI::X86_CDECL, _simu_linux_x86_getpagesize_args),
    new EnvFunction(_simu_linux_x86_sys_getpid, "getpid", ABI::X86_CDECL, _simu_linux_x86_sys_getpid_args),
    new EnvFunction(_simu_libc_common_malloc, "malloc", ABI::X86_CDECL, _simu_linux_x86_malloc_args),
    new EnvFunction(_ir_simu_linux_x86_memcmp(), "memcmp", ABI::X86_CDECL, _simu_linux_x86_memcmp_args),
    new EnvFunction(_simu_libc_common_memcpy, "memcpy", ABI::X86_CDECL, _simu_linux_x86_memcpy_args),
    new EnvFunction(_simu_libc_common_memset, "memset", ABI::X86_CDECL, _simu_linux_x86_memset_args),
    new EnvFunction(_simu_linux_x86_sys_ptrace, "ptrace", ABI::X86_CDECL, _simu_linux_x86_sys_ptrace_args),
    new EnvFunction(_simu_libc_common_puts, "puts", ABI::X86_CDECL, _simu_linux_x86_puts_args),
    new EnvFunction(_simu_libc_common_printf, "printf", ABI::X86_CDECL, _simu_linux_x86_printf_args),
    new EnvFunction(_simu_libc_common_rand, "rand", ABI::X86_CDECL, _simu_linux_x86_rand_args),
    new EnvFunction(_simu_libc_common_scanf, "scanf", ABI::X86_CDECL, _simu_linux_x86_scanf_args),
    new EnvFunction(_simu_libc_common_scanf, "__isoc99_scanf", ABI::X86_CDECL, _simu_linux_x86_scanf_args),
    new EnvFunction(_simu_linux_x86_sys_read, "read", ABI::X86_CDECL, _simu_linux_x86_sys_read_args),
    new EnvFunction(_simu_linux_x86_sys_signal, "signal", ABI::X86_CDECL, _simu_linux_x86_sys_signal_args),
    new EnvFunction(_simu_libc_common_sprintf, "sprintf", ABI::X86_CDECL, _simu_linux_x86_sprintf_args),
    new EnvFunction(_simu_libc_common_srand, "srand", ABI::X86_CDECL, _simu_linux_x86_srand_args),
    new EnvFunction(_ir_simu_linux_x86_strchr(), "strchr", ABI::X86_CDECL, _simu_linux_x86_strchr_args),
    new EnvFunction(_ir_simu_linux_x86_strcmp(), "strcmp", ABI::X86_CDECL, _simu_linux_x86_strcmp_args),
    new EnvFunction(_simu_libc_common_strcpy, "strcpy", ABI::X86_CDECL, _simu_linux_x86_strcpy_args),
    new EnvFunction(_ir_simu_linux_x86_strlen(), "strlen", ABI::X86_CDECL, _simu_linux_x86_strlen_args),
    new EnvFunction(_ir_simu_linux_x86_strrchr(), "strrchr", ABI::X86_CDECL, _simu_linux_x86_strrchr_args),
    new EnvFunction(_simu_linux_x86_sys_time, "time", ABI::X86_CDECL, _simu_linux_x86_sys_time_args),
    new EnvFunction(_simu_linux_x86_sys_write, "write", ABI::X86_CDECL, _simu_linux_x86_sys_write_args),
    /* Syscalls */
    new EnvFunction(_simu_linux_x86_sys_brk, "sys_brk", ABI::X86_LINUX_CUSTOM_SYSCALL, _simu_linux_x86_sys_brk_args),
    new EnvFunction(_simu_linux_x86_sys_getpid, "sys_getpid", ABI::X86_LINUX_CUSTOM_SYSCALL, _simu_linux_x86_sys_getpid_args),
    new EnvFunction(_simu_linux_x86_sys_newuname, "sys_newuname", ABI::X86_LINUX_CUSTOM_SYSCALL, _simu_linux_x86_sys_newuname_args),
    new EnvFunction(_simu_linux_x86_sys_ptrace, "sys_ptrace", ABI::X86_LINUX_CUSTOM_SYSCALL, _simu_linux_x86_sys_ptrace_args),
    new EnvFunction(_simu_linux_x86_sys_read, "sys_read", ABI::X86_LINUX_CUSTOM_SYSCALL, _simu_linux_x86_sys_read_args),
    new EnvFunction(_simu_linux_x86_sys_signal, "sys_signal", ABI::X86_LINUX_CUSTOM_SYSCALL, _simu_linux_x86_sys_signal_args),
    new EnvFunction(_simu_linux_x86_sys_time, "sys_time", ABI::X86_LINUX_CUSTOM_SYSCALL, _simu_linux_x86_sys_time_args),
    new EnvFunction(_simu_linux_x86_sys_write, "sys_write", ABI::X86_LINUX_CUSTOM_SYSCALL, _simu_linux_x86_sys_write_args),
    /* Default signal handlers */
    new EnvFunction(_simu_linux_x86_sigtrap_handler, "__simu_default_sigtrap_handler", ABI::X86_CDECL, _simu_linux_x86_signal_handler_args)
    };
};

unordered_map<int, string> default_linux_x86_signal_handlers{
    {X86_LINUX_SIGTRAP, "__simu_default_sigtrap_handler"}
};


/* the traits table for ctypes (from github evanphx/ulysses-libc ) */
unsigned short linux_x86_ctype_b_loc_table[] = {
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* Table starts here for 128 normal ASCII chars */
0x200,0x200,0x200,0x200,0x200,0x200,0x200,0x200,
0x200,0x320,0x220,0x220,0x220,0x220,0x200,0x200,
0x200,0x200,0x200,0x200,0x200,0x200,0x200,0x200,
0x200,0x200,0x200,0x200,0x200,0x200,0x200,0x200,
0x160,0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,
0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,
0x8d8,0x8d8,0x8d8,0x8d8,0x8d8,0x8d8,0x8d8,0x8d8,
0x8d8,0x8d8,0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,
0x4c0,0x8d5,0x8d5,0x8d5,0x8d5,0x8d5,0x8d5,0x8c5,
0x8c5,0x8c5,0x8c5,0x8c5,0x8c5,0x8c5,0x8c5,0x8c5,
0x8c5,0x8c5,0x8c5,0x8c5,0x8c5,0x8c5,0x8c5,0x8c5,
0x8c5,0x8c5,0x8c5,0x4c0,0x4c0,0x4c0,0x4c0,0x4c0,
0x4c0,0x8d6,0x8d6,0x8d6,0x8d6,0x8d6,0x8d6,0x8c6,
0x8c6,0x8c6,0x8c6,0x8c6,0x8c6,0x8c6,0x8c6,0x8c6,
0x8c6,0x8c6,0x8c6,0x8c6,0x8c6,0x8c6,0x8c6,0x8c6,
0x8c6,0x8c6,0x8c6,0x4c0,0x4c0,0x4c0,0x4c0,0x200,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
