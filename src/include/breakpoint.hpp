#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include "expression.hpp"
#include "typedefs.hpp"

#ifdef PYTHON_BINDINGS
#include "Python.h"
#endif

using std::vector;
using std::string;

/* Forward declarations */
class SymbolicEngine;
class MemEngine;
class IROperand;
class IRContext;
class IRInstruction;
class BreakpointManager;

// Functions used by SymbolicEngine internals
Expr _expand_lvalue(Expr current, Expr e, exprsize_t high, exprsize_t low); 
Expr _get_operand(IROperand& arg, IRContext* irctx, vector<Expr>& tmp_vars); 

/* Breakpoints
   ===========

A breakpoint manager is used by a symbolic engine to check if breakpoints
must be triggered. It holds a list of active breakpoints and checks them
against IR instructions.

A breakpoint consists in a name (e.g "my_breakpoint_1"), a type (e.g 
REGISTER_R, MEMORY_RW, ...), and one or two values whose meaning depends on the type.
For REGISTER_* breakpoints, it's the number representing the register, for MEMORY_* breakpoints
it'll be an address, etc.

When a breakpoint is triggered, the breakpoint manager updates the information
contained in the SymbolicEngineInfo field of its corresponding SymbolicEngine.

There are two kinds of breakpoints. The ones that are checked at the IR level
(irlvl) and the ones that are checked at the assembly level (asmlvl). Irlvl 
breakpoints are checked at every IR instruction executed. Asmlvl breakpoints
are checked only when we change the ASM instruction (instruction address changes
in the IRInstruction class). 

*/

enum class CallbackType{
    NATIVE,
    PYTHON,
    NONE
};

enum class BreakpointType{
    /* Executing an instruction at address... */
    ADDR,
    /* Accessing registers */
    REGISTER_R,
    REGISTER_W,
    REGISTER_RW,
    /* Accessing memory */
    MEMORY_R,
    MEMORY_W,
    MEMORY_RW,
    /* Branchement instructions */
    BRANCH,
    MULTIBRANCH,
    /* Tainted control flow or code */
    TAINTED_PC,
    TAINTED_CODE,
    /* Tainted path constraints */
    PATH_CONSTRAINT,
    /* Invalid (for empty constructor) */
    NONE
};

/* Breakpoint
   ==========
   A breakpoint instance is fairly simple. It has a name that uniquely identifies it, 
   and a type (see BreakpointType).
   
   The two 'value' fields how data that specify when to break. For example for an
   BREAK.ADDR breakpoint, it will be triggered if the instruction tested has an address
   in the range [value, value2].
   
   The optional field 'callback' can be used to specify a callback that's be automatically 
   execute when the breakpoint is triggered.
   
   The optional field 'resume' enables to continue execution automatically after the breakpoint
   has been hit.
*/

class Breakpoint{
public:
    BreakpointType type;
    string name;
    addr_t value;
    addr_t value2;
    void (*callback)(SymbolicEngine& sym);
    CallbackType callback_type;
    bool resume; // Resume auto if callback is called
    Breakpoint();
    ~Breakpoint();
    Breakpoint(BreakpointType type, string name, addr_t value, addr_t value2 = 0, 
        void (*callback)(SymbolicEngine& sym) = nullptr, bool resume=true);
#ifdef PYTHON_BINDINGS
    PyObject* python_callback;
    Breakpoint(BreakpointType type, string name, addr_t value, addr_t value2 = 0, 
        PyObject* python_callback = nullptr, bool resume=true);
#endif
};

/* BreakpointRecord
   ================
   The purpose of this class is to hold information about what breakpoints have been triggered
   for the currently executed instruction/IRInstruction. This is needed because of breakpoints
   are tested in Maat, to avoid re-breaking forever on the same breakpoint on the same instruction
*/

class BreakpointRecord{
public:
    vector<string> irlvl_names;
    vector<string> asmlvl_names;
    void add_irlvl(string name);
    void add_asmlvl(string name);
    void clear_asmlvl();
    void clear_irlvl();
    bool contains(string& val);
};



typedef void (*callback_t)(SymbolicEngine& sym);
#ifdef PYTHON_BINDINGS
typedef PyObject* (*python_env_callback_t)(PyObject* args); 
#endif

class BreakpointManager{
friend class SymbolicEngine;
friend class EnvManager;
    Breakpoint _hit; // Last breakpoint hit
    unsigned int _nb;
    vector<Breakpoint> _breakpoints;
    Breakpoint _tainted_pc;
    Breakpoint _path_constraint;
    Breakpoint _tainted_code;
    // Check standard breakpoints like REGISTER_*, MEMORY_*
    bool check(SymbolicEngine& sym, IRInstruction& instr, vector<Expr>& tmp_vars ); 
    // Check ADDR breakpoint
    bool check_addr(SymbolicEngine& sym, addr_t addr);
    // Check TAINTED_PC breakpoint
    bool check_pc(SymbolicEngine& sym, Expr pc);
    // Check PATH_CONSTRAINT breakpoint
    bool check_path(SymbolicEngine& sym, IRInstruction& instr, vector<Expr>& tmp_vars );
    // Check TAINTED_CODE breakpoint
    bool check_tainted_code(SymbolicEngine& sym, addr_t addr);
    
public:
    BreakpointManager();
    BreakpointManager(MemEngine* mem, IRContext* ctx);
    void add(BreakpointType type, string name, addr_t value=0, void (*callback)(SymbolicEngine& sym)=nullptr, bool resume=true);
    void add(BreakpointType type, string name, addr_t value, addr_t value2, void (*callback)(SymbolicEngine& sym)=nullptr, bool resume=true);
    void remove(string name);
    void remove_all();
#ifdef PYTHON_BINDINGS
    void add_from_python(BreakpointType type, string name, addr_t value, addr_t value2, PyObject* python_callback, bool resume);
#endif 
};

#endif
