#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

enum class SysType{
    LINUX,
    WINDOWS,
    NONE
};

#include "symbolic.hpp"
#include "expression.hpp"
#include "arch.hpp"

class SymbolicEngine;
class EnvManager;

class EnvCallbackReturn{
public:
    int status;
    cst_t value; // Callback can return a concrete value
    Expr expr; // Or an expression
    EnvCallbackReturn();
    EnvCallbackReturn(int status, cst_t value=0);
    EnvCallbackReturn(int status, Expr expr);
};


typedef EnvCallbackReturn (*env_callback_t)(SymbolicEngine& sym, vector<Expr> args);


/* Diferrent calling conventions
   ============================= 

The usual calling conventions are supported, cdecl, stdcall, thiscall, 
etc... but we also add custom calling conventions, that will be used 
with syscalls (see later for more details)
*/

enum class ABI{
    /* X86 */
    X86_CDECL,
    X86_STDCALL,
    X86_FASTCALL,
    X86_THISCALL_GCC,
    X86_THISCALL_MS,
    X86_LINUX_SYSENTER,
    X86_LINUX_INT80,
    /* X64 */
    X64_MS,
    X64_SYSTEM_V,
    /* Custom */
    X86_LINUX_CUSTOM_SYSCALL
};

// Return values for env callbacks
#define ENV_CALLBACK_SUCCESS 0 // Callback was successfully executed
#define ENV_CALLBACK_FAIL 1 // An error occured while executing the callback
#define ENV_CALLBACK_NOT_IMPLEMENTED 2 // The callback is not implemented
#define ENV_NO_CALLBACK 3 // No callback was executed
#define ENV_CALLBACK_EXIT 4 // Callback exits the simulated program
#define ENV_BREAKPOINT 5 // Callback generated a breakpoint
#define ENV_CALLBACK_SUCCESS_WITH_VALUE 6 // Callback was successful and returned a value

// Generic name for the non_implemented callback
#define ENV_CALLBACK_NOT_IMPLEMENTED_NAME "__callback_not_implemented"

/* ======================================
 *             EnvFunction
 * ====================================== 
   
   Simulated functions can be defined in different ways. 
   - FROM CALLBACK: a callback function will be executed to simulate the function.
     Those functions are intended to be "loaded" at an address in memory. Then, the
     function check_and_simulate() can be used to verify if a jump to a given address
     corresponds to a loaded simulated function. If yes, the arguments of the function
     call are collected according to the ABI of the function, then passed to the callback
     which is executed.
    
   - FROM_IR: an IBlock is directly given that simulates the function. When the function
     is loaded, the IRBlock is transfered to the symbolic engine ir manager that simply maps
     it a the fake address for this functions. Then, the simulated ir block is executed at
     runtime transparently without going through the env manager.
    
  -> The main advantage of FROM_IR on FROM_CALLBACK is that it enables triggering
     breakpoints in imported functions (to trace path constraints, etc).

   A function callback is not responsible to get its arguments and to return the control
   flow. It is the EnvFunction::call() method that does that. Depending on the specfied
   ABI, it will retrieve arguments and call the callback with them. Then, still according to
   the ABI, it will return the control flow. This enables to use the same callback on a
   given architecture with multiple ABIs without rewriting the callback :)
   
   */

enum class EnvFunctionType{
    FROM_CALLBACK,
    FROM_PYTHON_CALLBACK,
    FROM_CODE,
    FROM_IR
};

class EnvFunction{
public:
    EnvFunctionType type;
    env_callback_t callback; // callback, for "FROM_CALLBACK" functions
    string raw_code; // for "code" functions
    IRBlock* irblock; // for "ir" functions, the object takes the ownership of it until it gets loaded, then passes to the IRManager
    vector<size_t> args; // a vector representing the size of the arguments (e.g func(int x, short y) --> args = {4, 2})
    ABI abi; // The ABI that is used by this function 
    string name; // The name of the function

    addr_t load_addr; // Address where the function was loaded (A value of zero = not loaded yet)
    bool is_loaded;
    
    EnvFunction(env_callback_t c, string n, ABI default_abi, vector<size_t> a, addr_t la=0, bool is_loaded=false);
    EnvFunction(string raw_code, string n, addr_t la=0, bool is_loaded=false);
    EnvFunction(IRBlock* irblock, string n, ABI default_abi, vector<size_t> a, addr_t la=0, bool is_loaded=false);
    ~EnvFunction();
    /* The call function handles calling a callback to simulate the effects of a function.
     * It should collect function arguments according to the function's ABI, then call the
     * callback with those arguments.
     * 
     * It returns an int that represents what happened when executing the callback, it is
     * one of the num ENV_CALLBACK_SUCCESS, ENV_CALLBACK_FAIL, etc, described above. */
    int call(SymbolicEngine& sym);
    int call_native_callback(SymbolicEngine& sym);
    int call_python_callback(SymbolicEngine& sym);
    
    /* Python callbacks */
#ifdef PYTHON_BINDINGS
    PyObject* python_callback;
    EnvFunction(PyObject* c, string n, ABI default_abi, vector<size_t> a, addr_t la=0, bool is_loaded=false);
#endif
    
};

/* About syscalls 
 * =================
    
    Simulating syscalls is not trivial. We made the design choice to support
    syscalls the same way we support imported functions: specifying them as
    code, ir code, or high level callbacks, with the expected ABI. However, if
    we use classical ABIs, making a syscall might have side-effects on the 
    stack of the process (like pushing args, etc) that would alter the state
    of the program. So we added custom calling conventions that enable to switch
    the stack and arguments to a "kernel stack" so that all operations are done
    in "kernel land" and then we return to the normal stack. Those ABIs are:

        - X86_LINUX_CUSTOM_SYSCALL: CDECL with the saved stack pointer pushed 
          first, before the arguments 
 
    Basically, syscalls in the IR are handled by the prepare_syscall() function
    of the EnvManager. The first thing it does it look at the syscall type to know
    how the syscall was triggered: we only have one SYSCALL IR instruction but
    in real life a syscall might be triggered by IN80, SYSENTER, SYSCALL, SVC, ...
    Knowing the type gives the native ABI used to invoque the syscall and enables
    to get the syscall number and syscall arguments. 
    Then the EnvManager finds what EnvFunction is associated with this syscall. It
    translates the arguments from the native syscall ABI to the simulated function
    ABI, prepares the call to this function in the symbolic engine, and sets PC
    to the address of the function. 
 
    prepare_syscall() then returns and the symbolic engine will jump to the address
    of the syscall handler and continue execution as it would do for a regular
    function callback
    
 */


/* ======================================
 *              Simulated data 
 * ====================================== */
class EnvData {    
public:
    string name;
    uint8_t* data; // The object takes ownership of the array
    unsigned int size;
    addr_t load_addr;
    bool is_loaded;
    EnvData(string n, unsigned int s, uint8_t* d, addr_t la=0, bool il=false){
        name = n; data = d; size = s;
        load_addr = la; is_loaded = il;
    };
    ~EnvData(){
        delete [] data;
        data = nullptr;
    };
};

/* ======================================
 *          Simulated Memory Allocator
 * ======================================
 
   We simulate memory allocation with a very simple allocator. Basically
   a EnvMemoryAllocator is given a range of addresses that it can use
   to allocate memory. It should be used through the simple interface
    - free(addr) : free block at addr 
    - allocate(size) : allocate new block of size 'size' and return its address
   
   The implementation of the allocator is very simple, it just keeps two lists,
   one of the free blocks, and one of the allocated blocks.
*/
 

typedef struct {
    addr_t start;
    addr_t size;
} MemSlot;

class EnvMemAllocator{
friend class EnvSnapshotManager;
    addr_t min_addr;
    addr_t max_addr; // Last byte of the segment
    vector<MemSlot> free_slots;
    unordered_map<addr_t, unsigned int> allocated_slots;
    void add_allocated_slot(addr_t addr, unsigned int size);
    void add_free_slot(addr_t addr, unsigned int size);
public:
    EnvMemAllocator();
    EnvMemAllocator(addr_t min, addr_t max);
    addr_t alloc(unsigned int size);
    unsigned int free(addr_t addr); // Return size of freed block
};

/* ======================================
 *        Simulated File System
 * ======================================
   
   The EnvFileSystem proposes a very basic simulation of a file system.
   It keeps a list of files that can be identified either by their name
   (a simple string) or their number (which in practice and for now 
   corresponds to the file-descriptor associated with the file at the OS
   level).
   
   An EnvFile is simply a buffer with a position from which you can read
   and write. The functionnality is super basic and in particular lacks:
     - handling different cursors in the same file at the same time
     - locking
    
   Additionnaly, note that there is no notion of directory, file 
   permissions, etc.
*/
   
class EnvFile{
public:
    string name;
    vector<Expr> data;
    unsigned int pos; // Current position in the file

    EnvFile(string name);
    int write_from_buffer(SymbolicEngine& sym, addr_t buf, size_t count);
    int read_to_buffer(SymbolicEngine& sym, addr_t buf, size_t count);
};

class EnvFileSystem{
    vector<EnvFile*> files;
public:
    EnvFileSystem();
    ~EnvFileSystem();
    EnvFile* file_by_name(string name);
    EnvFile* file_by_num(unsigned int num);
    int file_num_by_name(string name);
    EnvFile* create_file(string name);
    EnvFile* create_file_num(string name, unsigned int num);
    void remove_file(string name);
};

/* ============================
 * Snapshoting for environment 
 * =========================== 
   When taking a snapshot, the following elements should be saved
   in the environment to enable succesful semantic state restoration:
     - memory allocation/free (saved as a list of events, like we do for mem writes)
     - list of current signal handlers (they can change dynamically)
     - contents of files (TODO: NOT IMPLEMENTED YET)
*/
#define ENV_MEM_FREE 0
#define ENV_MEM_ALLOC 1
typedef struct mem_alloc_event_t{
    int type; // 0 = free, 1 = alloc
    addr_t addr;
    size_t size; // number of bytes if freed
} mem_alloc_event_t;

typedef unsigned int env_snapshot_id_t;

class EnvSnapshot{
public:
    vector<mem_alloc_event_t> mem_allocs;
    unordered_map<int, addr_t> signal_handlers;
    EnvSnapshot(unordered_map<int, addr_t> signal_handlers);
};

class EnvSnapshotManager{
    vector<EnvSnapshot> _snapshots;
public:
    env_snapshot_id_t take_snapshot(EnvManager& env);
    void record_alloc(addr_t addr);
    void record_free(addr_t addr, size_t size);
    bool rewind(EnvManager& env, bool remove=false);
    bool restore(env_snapshot_id_t snapshot_id, EnvManager& env, bool remove=false);
    bool is_active();
};




/* EnvManager
   ==========
   
   The EnvManager simulates the environment in which the code will run. It aims at handling 
   calls to external functions and various system calls, file system actions, networking, ...
   
*/

// Util functions to create callbacks and simulations
void _abi_return(ABI abi, vector<size_t>& args, SymbolicEngine& sym);
vector<Expr> _abi_get_args(ABI abi, vector<size_t>& args, SymbolicEngine& sym);
void _abi_set_args(ABI abi, vector<Expr>& args, SymbolicEngine& sym);
void _abi_set_return_value(ABI abi, EnvCallbackReturn& ret, SymbolicEngine& sym);
void _abi_set_return_address(ABI abi, addr_t ret, SymbolicEngine& sym);
ucst_t _abi_get_syscall_num(CPUMode mode, SysType sys, SymbolicEngine& sym);
string _get_syscall_func_name(ucst_t num, CPUMode mode, SysType sys);
bool _abi_is_syscall(ABI abi);
ABI _get_default_abi(CPUMode mode, SysType sys);

vector<IROperand> _ir_abi_get_args(ABI abi, vector<size_t>& args, IRBlock& irblock);
void _ir_abi_return(ABI abi, IRBlock& irblock);

// EnvManager class
class EnvManager{
friend class LIEFLoader;
friend class EnvSnapshotManager;
friend class SnapshotManager;
    vector<EnvFunction*> functions; // Simulated functions
    unordered_map<int, string> default_signal_handlers; // Names of default simulated signal handlers functions
    vector<EnvData*> data;  // Simulated data relocations
    EnvMemAllocator mem_allocator; // Custom memory allocator
    env_callback_t not_implemented_callback;
    unsigned short int* ctype_b_loc_table;  // The ctype_loc_b traits table
    EnvSnapshotManager snapshot_manager;
public:
    SysType type; // Operating System 
    addr_t env_array; // Address of the env[] array
    EnvFileSystem filesystem; // Simulated filesystem
    addr_t kernel_stack; // Start address of kernel stack
    addr_t ctype_b_loc_table_ptr; // Pointer to the ctype_loc_b table in symbolic engine's memory 
    unordered_map<int, addr_t> current_signal_handlers; // current <signum, handler> mapping
    
    /* Initialisation */
    EnvManager();
    EnvManager(ArchType arch, SysType sys);
    ~EnvManager();
    void init_mem_allocator(addr_t start, addr_t end);
    
    /* Manage simulated functions */
    vector<string> all_function_names();
    void add_function(EnvFunction* func);
    void loaded_function(string func_name, addr_t addr);
    bool simulates_function(string func_name);
    EnvFunction& get_function(string func_name);
    EnvFunction& get_function(addr_t addr);
    EnvFunction& new_not_implemented_function(string name, ABI abi);
    // Checks if addr is the addr of a simulated function and executes it
    // Returns true if a simulation has been executed
    int check_and_simulate(addr_t addr, SymbolicEngine& sym);
    
    /* Manage simulated data */
    void add_data(EnvData* data);
    void loaded_data(string data_name, addr_t addr);
    bool simulates_data(string data_name);
    EnvData& get_data(string data_name);
    
    /* Handle syscalls, interrupts, signals... */
    void prepare_syscall(cst_t syscall_type, addr_t ret, SymbolicEngine& sym);
    void do_interrupt(cst_t num, addr_t ret, SymbolicEngine& sym);
    void handle_signal(int signum, SymbolicEngine& sym);
    
    /* Memory managment */
    addr_t alloc(unsigned int size);
    unsigned int free(addr_t addr); // Returns the size of the freed block

    /* Snapshoting */
    env_snapshot_id_t take_snapshot();
    void restore_snapshot(env_snapshot_id_t id);
};

#endif
