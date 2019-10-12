#include "environment.hpp"
#include "exception.hpp"
#include "libc_common.hpp"
#include <vector>
#include <cstdlib>
#include <sstream>
#include <ctime>

using std::string;
using std::vector;
using std::stringstream;

/* ==============================================
 *                  Util functions
 * ============================================= */
/* Read a concrete C string into buffer 
 * addr is the address of the string
 * max_len is the length of the buffer where to put the concrete string
 * len is set to the length of the string
 * is_tainted is set to True if one byte at least was tainted in the string */
bool _mem_read_c_string_and_taint(SymbolicEngine& sym, addr_t addr, char* buffer, int& len, unsigned int max_len, bool& is_tainted){
    Expr e;
    char c = 0xff;
    len = 0;
    is_tainted = false;
    while( c != 0 && len < max_len ){
        e = sym.mem->read(addr+len, 1);
        if( e->is_tainted() )
            is_tainted = true;
        c = (uint8_t)(e->concretize(sym.vars)); // If e is symbolic, this will fail
        buffer[len++] = c;
    }
    if( len == max_len ){
        sym._error_msg = "LinuxX86:_mem_read_c_string_and_taint(): C string is too long to fit into buffer !";
        return false;
    }
    return true;
}

bool _mem_read_c_string(SymbolicEngine& sym, addr_t addr, char* buffer, int& len, unsigned int max_len){
    bool dummy;
    return _mem_read_c_string_and_taint(sym, addr, buffer, len, max_len, dummy);
}

/* Tries to parse a format specifier in string format at index 'index'.
 * If successful, index is modified to the last char of the specifier
 */
int _get_specifier(char* format, int format_len, int& index, char* spec, int spec_max_len ){
    int i = index;
    int res;
    // % marker
    if( format[i] != '%' )
        return SPEC_NONE;
    spec[i-index] = format[i];
    // width
    for( i = i +1; i < format_len; i++){
        if( i > spec_max_len-3 )
            return SPEC_UNSUPPORTED;
        // Check if number
        if( format[i] >= '0' && format[i] <= '9' )
            spec[i-index] = format[i];
        else
            break;
    }
    if( i ==  format_len )
        return false;
        
    // Precision 
    if( format[i] == '.' ){
        spec[i-index] = format[i];
        for( i = i +1; i < format_len; i++){
            if( i > spec_max_len-3 )
                return SPEC_UNSUPPORTED;
            // Check if number
            if( format[i] >= '0' && format[i] <= '9' )
                spec[i-index] = format[i];
            else
                break;
        }
    }
    
    // specifier
    spec[i-index] = format[i];
    if(     format[i] == 'd' || format[i] == 'u' ){
        res = SPEC_INT32; 
    }else if( format[i] == 'x' ){
        res = SPEC_HEX32;
    }else if( format[i] == 's' ){
        res = SPEC_STRING;
    }else if( format[i] == 'c' ){
        res = SPEC_CHAR;
    }else{
        res = SPEC_UNSUPPORTED;
    }
    // Check res
    if( res != SPEC_UNSUPPORTED ){
        spec[i-index+1] = '\0';
        index = i;
    }
    return res;
}

bool _get_format_string(SymbolicEngine& sym, char* format, int len, string& res){
    stringstream ss;
    Expr e;
    int val;
    addr_t addr;
    char buffer[2048], specifier[128], formatted_arg[256];
    int buffer_len;
    int spec;
    addr_t stack = (uint32_t)sym.regs->concretize(sym.arch->sp()) + 4 + 4; // skip ret and format string
    for( int i = 0; i < len; i++ ){
        spec = _get_specifier(format, len, i, specifier, sizeof(specifier));
        if( spec ==  SPEC_INT32 || spec == SPEC_HEX32){
            val = (int) (sym.mem->read(stack, 4)->concretize(sym.vars));
            stack += 4;
            // Use snprintf that does the formatting for us :)
            snprintf(formatted_arg, sizeof(formatted_arg), specifier, val);
            ss << string(formatted_arg);
        }else if( spec == SPEC_STRING ){
            addr = (uint32_t) (sym.mem->read(stack, 4)->concretize(sym.vars));
            stack += 4;
            _mem_read_c_string(sym,  addr, buffer, buffer_len, sizeof(buffer)); // Ignore if we exceed sizeof(buffer)
            ss << string(buffer, buffer_len);
        }else if( spec == SPEC_UNSUPPORTED ){
            stringstream ss_err;
            ss_err << "LinuxX86:_get_format_string(): unsupported format: " << string(specifier) << " in " << string(format);
            sym._error_msg = ss_err.str();
            return false;
        }else{
            ss << format[i];
        }
    }
    res = ss.str();
    return true;
}

/* input: size of expressions must be 8 (a byte) */
bool _is_whitespace(char c){
    return  c == 0x20 ||
            c == 0x9 ||
            c == 0xa ||
            c == 0xb ||
            c == 0xc ||
            c == 0xd ||
            c == 0;
}

bool _is_terminating(char c){
    return  c == 0 ||
            c == '\n';
}

bool _read_format_string(SymbolicEngine& sym, char* format, int len, vector<Expr> input, int& param_parsed){
    addr_t stack = (uint32_t)sym.regs->concretize(X86_ESP) + 4 + 4; // skip ret and format string
    char specifier[128];
    int spec;
    uint64_t int_param;
    addr_t param_addr;
    bool error = false;
    param_parsed = 0;
    int j = 0; // Index in input
    // Get concrete values for input
    string concrete_input;
    for( int i = 0; i < input.size(); i++){
        concrete_input += (char)input[i]->concretize(sym.vars);
    }
    // Skip all whitespaces in input string too
    while( _is_whitespace(concrete_input[j])){
        j++;
    }
    for( int i = 0; i < len; i++ ){
        spec = _get_specifier(format, len, i, specifier, sizeof(specifier));
        if( spec == SPEC_INT32 ){
            int_param = 0;
            if( sscanf(concrete_input.c_str()+j, specifier, &int_param) == 0 ){ // Use sscanf to get the value
                // If scanf failed then the function just returns (the spec says it should return the number
                // of succesfully parsed specifiers so that's what we do here, we don't return false to indicate
                // that the callback failed since it didn't fail according to the spec)
                sym._print_warning("Simulated scanf() failed to parse input according to suppplied format");
                return true;
                //error = true;
                //break;
            }
            param_addr = sym.mem->read(stack, sym.arch->octets)->as_unsigned(sym.vars);
            sym.mem->write(param_addr, exprcst(32, int_param));
            stack += sym.arch->octets;
            // Manually skip to next input byte 
            while( isdigit((uint8_t)input[++j]->concretize(sym.vars)));
            param_parsed++;
        }else if( spec == SPEC_STRING ){
            // Read string
            param_addr = sym.mem->read(stack, sym.arch->octets)->as_unsigned(sym.vars);
            stack += sym.arch->octets;
            do{
                sym.mem->write(param_addr++, input[j]);
            }while( !_is_whitespace(input[j]->as_unsigned(sym.vars)) && (++j < input.size())  );
            param_parsed++;
            j--;
        }else if( spec == SPEC_UNSUPPORTED ){
            return false;
        }else{
            // If simple char check if it matches
            if( _is_whitespace(format[i]) ){
                // Just ignore whitespaces
            }else{
                if( (uint8_t)input[j]->concretize(sym.vars) != format[i] ){
                    error = true;
                    break;
                }
                j++;
            }
            // Skip all whitespaces in input string too
            while( _is_whitespace(concrete_input[j])){
                j++;
            }
        }
    }
    if( error )
        return false;
    else
        return true;
}

// Counter for how many times we read stdin
unsigned int _global_stdin_read_count = 0;

/* non_implemented callback : raise an exception for unimplemented functions */
EnvCallbackReturn _simu_libc_common_not_implemented(SymbolicEngine& sym, vector<Expr> args){
    return ENV_CALLBACK_NOT_IMPLEMENTED;
}

/* ==============================================
 *            Linux X86 libc functions
 * ============================================= */

// ============ abort =============== 
// void abort(void);
EnvCallbackReturn _simu_libc_common_abort(SymbolicEngine& sym, vector<Expr> args){
    // Terminate the program
    sym.info.stop = StopInfo::EXIT;
    return EnvCallbackReturn(ENV_CALLBACK_EXIT);
}

// ============ atoi =============== 
// int atoi (const char * str);
EnvCallbackReturn _simu_libc_common_atoi(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t format = args[0]->as_unsigned(sym.vars);
    char str[256];
    int len;
    int res;
    bool was_tainted;
    
    if( !_mem_read_c_string_and_taint(sym, format, str, len, sizeof(str), was_tainted) ){
        return ENV_CALLBACK_FAIL;
    }
    
    // Transform the string into an int
    res = atoi(str);
    
    // Return the integer :)
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, res); 
} 

// ============ calloc =============== 
// void* calloc (size_t num, size_t size);
EnvCallbackReturn _simu_libc_common_calloc(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    unsigned int num = args[0]->as_unsigned(sym.vars);
    unsigned int size = args[1]->as_unsigned(sym.vars);
    addr_t res;
    
    res = sym.env->alloc(size*num);
    
    // Return value is the address of the allocated block    
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, res); 
}


// ============ exit =============== 
EnvCallbackReturn _simu_libc_common_exit(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    sym.info.stop = StopInfo::EXIT;
    return EnvCallbackReturn(ENV_CALLBACK_EXIT); 
} 

// ============ fflush =============== 
// int fflush ( FILE * stream );
EnvCallbackReturn _simu_libc_common_fflush(SymbolicEngine& sym, vector<Expr> args){
    // Just flush stdout no matter what
    std::cout << std::flush;
    // Return zero for success
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, 0); 
}

// ============ free =============== 
// void free (void* ptr);
EnvCallbackReturn _simu_libc_common_free(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t addr = args[0]->as_unsigned(sym.vars);
    sym.env->free(addr);
    // No return value
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS); 
}

// ============ getenv =============== 
// char* getenv (const char* name);
EnvCallbackReturn _simu_libc_common_getenv(SymbolicEngine& sym, vector<Expr> args){
    /* Find the corresponding env variable */
    addr_t tmp_env = sym.env->env_array;
    addr_t name = args[0]->as_unsigned(sym.vars);
    addr_t env_var = sym.mem->read(tmp_env, 4)->as_unsigned(sym.vars);
    addr_t res = 0;
    char c1, c2;
    bool match;
    while( env_var != 0 ){
        /* Compare env variable with requested name */
        addr_t tmp_name = name;
        addr_t tmp_env_var = env_var;
        match = true;
        do{
            c1 = (char)sym.mem->read(tmp_name, 1)->concretize(sym.vars);
            c2 = (char)sym.mem->read(tmp_env_var, 1)->concretize(sym.vars);
            match = match && ((c1 == c2) || (c1 == '\0' && c2 == '=' ));
            std::cout << "c1 " << c1 << std::endl;
            std::cout << "c2 " << c2 << std::endl;
            std::cout << "match " << match << std::endl;
            tmp_name++;
            tmp_env_var++; 
        }while(match && c1 != '\0' && c2 != '=');
        if( match ){
            res = tmp_env_var;
            break;
        }else{
            tmp_env += 4;
            env_var = sym.mem->read(tmp_env, 4)->as_unsigned(sym.vars);
        }
    }
    /* Return address of the en var value if found and 0 otherwise */
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, res); 
}

// ============ getpagesize =============== 
// int getpagesize(void);
EnvCallbackReturn _simu_libc_common_getpagesize(SymbolicEngine& sym, vector<Expr> args){
    // Return arbitrary page size 0x1000
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, 0x1000); 
}

// ============ malloc =============== 
// void* malloc (size_t size);
EnvCallbackReturn _simu_libc_common_malloc(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    unsigned int size = args[0]->as_unsigned(sym.vars);
    addr_t res;
    
    res = sym.env->alloc(size);
    // Return value is the address of the allocated block
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, res); 
}

// ============ memset =============== 
// void * memset ( void * ptr, int value, size_t num );
EnvCallbackReturn _simu_libc_common_memset(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t ptr = args[0]->as_unsigned(sym.vars);
    Expr value = extract(args[1], 7, 0);
    size_t num = (size_t)(args[2]->as_unsigned(sym.vars));
    
    // Set
    for( ; num > 0; num-- ){
        sym.mem->write(ptr++, value, sym.vars);
    }
    // Return value is 'ptr'
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, args[0]); 
}

// ============ memcpy =============== 
// void *memcpy(void *dest, const void *src, size_t n);
EnvCallbackReturn _simu_libc_common_memcpy(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t dest = args[0]->as_unsigned(sym.vars);
    addr_t src = args[1]->as_unsigned(sym.vars);
    unsigned int n = args[2]->as_unsigned(sym.vars);
    
    // Copy
    for( ; n > 0; n-- ){
        sym.mem->write(dest++, sym.mem->read(src++, 1));
    }
    // Return value is 'dest'
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, args[0]); 
}

// ============ puts =============== 
// int puts ( const char * str );
EnvCallbackReturn _simu_libc_common_puts(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t str = args[0]->as_unsigned(sym.vars);
    char buffer[2048];
    int len;
    string to_print;
    
    // Read first argument (format string) into a buffer
    if( !_mem_read_c_string(sym, str, buffer, len, sizeof(buffer)-1) ){
        return ENV_CALLBACK_FAIL;
    }
    
    // Append a newline 
    buffer[len++] = '\n';
    
    // Simulate write
    std::cout << string(buffer, len) << std::flush;
    
    // Return some non-negative salue
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, 1); 
}

// ============ printf =============== 
// int printf ( const char * format, ... );
EnvCallbackReturn _simu_libc_common_printf(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t format = args[0]->as_unsigned(sym.vars);
    char str[2048];
    int len;
    string to_print;
    
    // Read first argument (format string) into a buffer
    if( !_mem_read_c_string(sym, format, str, len, sizeof(str)) ){
        return ENV_CALLBACK_FAIL;
    }
    
    // Try to interpret the format and get the correct string
    if( !_get_format_string(sym, str, len, to_print) ){
        return ENV_CALLBACK_FAIL;
    }
    std::cout << to_print << std::flush;
    
    // Return value is the number of bytes written
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, to_print.size()); 
}

// ============ rand =============== 
// int rand (void);
EnvCallbackReturn _simu_libc_common_rand(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    int r = rand();
    // Return value in EAX
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, r); 
}

// ============ scanf =============== 
// int scanf ( const char * format, ... );
EnvCallbackReturn _simu_libc_common_scanf(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t format = args[0]->as_unsigned(sym.vars);
    char str[2048];
    int len = 0, input_len=0;
    vector<Expr> input;
    char in_byte = 0xaa;
    int param_parsed;
    
    // Read first argument (format string) into a buffer
    if( !_mem_read_c_string(sym, format, str, len, sizeof(str)) ){
        return ENV_CALLBACK_FAIL;
    }

    // Get input from stdin
    do{
        std::cin.get(in_byte);
        stringstream ss;
        ss << "stdin_" << std::dec << _global_stdin_read_count << "_" << input_len;
        sym.vars->set(ss.str(), in_byte);
        input.push_back(exprvar(8,ss.str(), Taint::TAINTED)); // Taint input
        input_len++;
    }while( in_byte != 0 && in_byte != '\n' );
    
    // Try to interpret the format and get the correct string
    if( !_read_format_string(sym, str, len, input, param_parsed) ){
        sym._error_msg = "scanf() failed to parse input according to supplied format string";
        return ENV_CALLBACK_FAIL;
    }
    
    // Return value is the number of parameters parsed
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, param_parsed); 
}

// ============ sprintf =============== 
// int sprintf ( char * str, const char * format, ... );
// !!! We don't propagate taint with this implementation !
EnvCallbackReturn _simu_libc_common_sprintf(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t str = args[0]->as_unsigned(sym.vars);
    addr_t format = args[1]->as_unsigned(sym.vars);
    char buf[2048];
    int len;
    string to_print;
    
    // Read format string into a buffer
    if( !_mem_read_c_string(sym, format, buf, len, sizeof(str)) ){
        return ENV_CALLBACK_FAIL;
    }
    
    // Try to interpret the format and get the correct string
    if( !_get_format_string(sym, buf, len, to_print) ){
        return ENV_CALLBACK_FAIL;
    }
    
    // Write the string at the requested address :)
    sym.mem->write(str, (uint8_t*)to_print.c_str(), to_print.size()+1);
    
    // Return value is the number of bytes written
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, to_print.size()); 
}

// ============ srand =============== 
// void srand (unsigned int seed);
EnvCallbackReturn _simu_libc_common_srand(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    uint32_t seed = args[0]->as_unsigned(sym.vars);
    srand(seed);
    // No return value
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS); 
}


// ============ strcpy =============== 
// char * strcpy ( char * destination, const char * source );
EnvCallbackReturn _simu_libc_common_strcpy(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t dest = args[0]->as_unsigned(sym.vars);
    addr_t src = args[1]->as_unsigned(sym.vars);
    
    // Copy until zero byte
    while( true ){
        sym.mem->write(dest, sym.mem->read(src, 1));
        if( sym.mem->read(src, 1)->concretize(sym.vars) == 0 )
            break;
        dest++;
        src++;
    }
    // Return value is 'dest'
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, args[0]); 
}

// ============ strlen =============== 
// size_t strlen ( const char * str );
EnvCallbackReturn _simu_libc_common_strlen(SymbolicEngine& sym, vector<Expr> args){
    // With cdecl ABI
    addr_t str = args[0]->as_unsigned(sym.vars);
    int len = 0;
    
    // Copy until zero byte
    while( sym.mem->read(str+len, 1)->concretize(sym.vars) != 0 ){
        len++;
    }
    
    // Return value is the length
    return EnvCallbackReturn(ENV_CALLBACK_SUCCESS_WITH_VALUE, len-1);
}


