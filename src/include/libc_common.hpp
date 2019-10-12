#ifndef ENV_LIBC_COMMON_H
#define ENV_LIBC_COMMON_H

#include "environment.hpp"
#include "exception.hpp"
#include "linux_x86.hpp"
#include <vector>
#include <cstdlib>
#include <sstream>
#include <ctime>

/* ==============================================
 *                  Util functions
 * ============================================= */
/* Read a concrete C string into buffer 
 * addr is the address of the string
 * max_len is the length of the buffer where to put the concrete string
 * len is set to the length of the string
 * is_tainted is set to True if one byte at least was tainted in the string */
bool _mem_read_c_string_and_taint(SymbolicEngine& sym, addr_t addr, char* buffer, int& len, unsigned int max_len, bool& is_tainted);

bool _mem_read_c_string(SymbolicEngine& sym, addr_t addr, char* buffer, int& len, unsigned int max_len);

#define SPEC_NONE 0
#define SPEC_UNSUPPORTED 1
#define SPEC_INT32 2
#define SPEC_STRING 3
#define SPEC_CHAR 4
#define SPEC_HEX32 5 // Int on hex format

/* Tries to parse a format specifier in string format at index 'index'.
 * If successful, index is modified to the last char of the specifier
 */
int _get_specifier(char* format, int format_len, int& index, char* spec, int spec_max_len );
bool _get_format_string(SymbolicEngine& sym, char* format, int len, string& res);

/* input: size of expressions must be 8 (a byte) */
bool _is_whitespace(char c);

bool _is_terminating(char c);

bool _read_format_string(SymbolicEngine& sym, char* format, int len, vector<Expr> input, int& param_parsed);

/* non_implemented callback : raise an exception for unimplemented functions */
EnvCallbackReturn _simu_libc_common_not_implemented(SymbolicEngine& sym, vector<Expr> args);

/* ==============================================
 *            Linux X86 libc functions
 * ============================================= */


EnvCallbackReturn _simu_libc_common_abort(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_atoi(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_calloc(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_exit(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_fflush(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_free(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_getenv(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_getpagesize(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_malloc(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_memset(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_memcpy(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_puts(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_printf(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_rand(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_scanf(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_sprintf(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_srand(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_strcpy(SymbolicEngine& sym, vector<Expr> args);
EnvCallbackReturn _simu_libc_common_strlen(SymbolicEngine& sym, vector<Expr> args);

#endif
