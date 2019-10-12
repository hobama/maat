#ifndef SYMBOLIC_H
#define SYMBOLIC_H

#include "irmanager.hpp"
#include "block.hpp"
#include "instruction.hpp"
#include "expression.hpp"
#include "simplification.hpp"
#include "memory.hpp"
#include "arch.hpp"
#include "solver.hpp"
#include "environment.hpp"
#include "breakpoint.hpp"
#include "snapshot.hpp"
#include "irstate.hpp"

#ifdef PYTHON_BINDINGS
#include "Python.h"
#endif

using std::tuple;
using std::string;

/* Forward declaration */
class BreakpointRecord;
class BreakpointManager;
class SymbolicEngine;
class PathManager;
class SnapshotManager;
class EnvManager;
class Arch;
class IRManager;

/* Reason why the symbolic engine stopped execution */
enum class StopInfo{
    BREAKPOINT, // Breakpoint hit
    SYMBOLIC_PC, // PC is purely symbolic 
    SYMBOLIC_CODE, // Code to execute is purely symbolic
    MISSING_FUNCTION, // Jump to a function whose code isn't loaded
    EXIT, // Program exited
    INSTR_COUNT, // The number of requested instructions has been executed
    ILLEGAL_INSTRUCTION, // The disassembler encountered an illegal instruction 
    ERROR, // An fatal error was encountered during execution
    NONE 
};

string stopinfo_to_str(StopInfo stop);

/* Describes a branching statement: expression to be evaluated (as null or not) and
 * expressions of the targets for both cases (cond null or not null) */
class MultiBranch{
public:
    Expr cond, if_not_null, if_null;
    MultiBranch(Expr _cond=nullptr, Expr _if_not_null=nullptr, Expr _if_null=nullptr);
    bool is_set();
    void print(ostream& os, string tab="");
};

ostream& operator<<(ostream& os, MultiBranch& multi);

/* Describe a memory access: address, size, and expression that is
 * written/read */
class MemAccess{
public:
    Expr addr;
    exprsize_t size;
    Expr value;
    MemAccess(Expr _addr=nullptr, exprsize_t _size=0, Expr _expr=nullptr);
    bool is_set();
    void print(ostream& os, string tab="");
};

ostream& operator<<(ostream& os, MemAccess& mem);

class SymbolicEngineInfo{
public:
    StopInfo stop; // Reason why the engine stopped
    string breakpoint; // Name of the breakpoint hit
    addr_t addr; // Address of the instruction where the breakpoint hit
    Expr branch; // Expression of the branch to be taken
    MultiBranch multibranch; // Info about the multibranch to be taken
    MemAccess mem_access; // Info about memory access when breakpoint hit
    Constraint path_constraint; // Info about the path constraint to be added
    
    SymbolicEngineInfo();
    void reset();
};

ostream& operator<<(ostream& os, SymbolicEngineInfo& info);

/* SymbolicEngineOption
   ==================== 
Each option should be a bit of a value so that it's easy 
to store them packed in an int or long */

enum class SymbolicEngineOption: int{
    // Symbolic Execution
    OPTIMIZE_IR = 1,        /* Remove unused variables from ir blocks */
    FORCE_CST_FOLDING = 2,   /* Concretize every expression when possible (not tainted & not symbolic) */
    RECORD_PATH_CONSTRAINTS = 4, /* Record the current path constraints in the path manager */
    SYMBOLIC_MEM_READ = 8,   /* Activate symbolic read support */
    SYMBOLIC_MEM_WRITE = 0x10,   /* Activate symbolic write support */
    // Environment simulation
    IGNORE_MISSING_IMPORTS = 0x20, /* Ignore calls to non-supported imported functions */
    IGNORE_MISSING_SYSCALLS = 0x40, /* Ignore non-supported system calls */
    // Constraints
    SIMPLIFY_CONSTRAINTS = 0x80, /* Apply simplifications on path constraints */
    // I/O
    PRINT_WARNINGS = 0x1000000, /* Print warnings by the symbolic engine */
    PRINT_INSTRUCTIONS = 0x2000000, /* Print executed instructions */
    PRINT_ERRORS = 0x4000000 /* Print executed instructions */
};


/* PathManager
   ============ */
class PathManager{
    vector<Constraint> _constraints;
public:
    void add(Constraint constr);
    void constraints_to_solver(Solver* s);
    unsigned int take_snapshot();
    void restore_snapshot(unsigned int snap_id);
    vector<Constraint>& constraints();
};


/* SymbolicEngine
   ============== */

class SymbolicEngine{
friend class BreakpointManager;
friend class LIEFLoader;
friend class SnapshotManager;
friend class EnvFunction;
    ExprSimplifier _cst_folding_simplifier;
    unordered_map<string, addr_t> _symbols;
    BreakpointRecord breakpoint_record;
    int options;
#ifdef PYTHON_BINDINGS
    PyObject* self_python_wrapper_object; // Not owned of course
#endif
public:
    
    IRState irstate;
    IRManager* irmanager;
    SymbolicEngineInfo info;
    VarContext* vars;
    IRContext* regs;
    MemEngine* mem;
    Arch* arch;
    PathManager* path;
    SnapshotManager* snapshot_manager;
    BreakpointManager breakpoint;
    ExprSimplifier* simplifier;
    EnvManager * env;
    
    string _error_msg; // To set error messages
    
    SymbolicEngine();
    SymbolicEngine(ArchType arch, SysType sys=SysType::NONE);
    SymbolicEngine(Arch* arch, IRManager* irm=nullptr, VarContext* varctx=nullptr, IRContext* irctx=nullptr, MemEngine* mem=nullptr, PathManager* pathm=nullptr);
    ~SymbolicEngine();
    /* Symbolic execution */
    StopInfo execute(unsigned int max_instr=0);
    StopInfo execute_from(addr_t addr, unsigned int max_instr=0);
    /* Snapshots */
    snapshot_id_t take_snapshot();
    bool restore_snapshot(snapshot_id_t id, bool remove=false);
    bool restore_snapshot(bool remove=false);
    /* Option managment */
    void enable(SymbolicEngineOption opt);
    void disable(SymbolicEngineOption opt);
    bool is_enabled(SymbolicEngineOption opt);
    /* Symbols info */
    void set_symbol_address(string name, addr_t addr);
    addr_t get_symbol_address(string name);
    /* Printing infos */
    void _print_info(string msg);
    void _print_warning(string msg);
    void _print_error(string msg);
    /* Breakpoints */
    bool handle_breakpoint();
    /* Other */
#ifdef PYTHON_BINDINGS
    void set_self_python_wrapper_object(PyObject* obj);
#endif
};

#endif
