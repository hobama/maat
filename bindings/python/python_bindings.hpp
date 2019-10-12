#ifndef PYTHON_BINDINGS_INCLUDE_H
#define PYTHON_BINDINGS_INCLUDE_H

#include "Python.h"
#include "structmember.h"
#include "exception.hpp"
#include "expression.hpp"
#include "instruction.hpp"
#include "memory.hpp"
#include "symbolic.hpp"
#include "solver.hpp"
#include "loader.hpp"

/* -------------------------------------------------
 *                     Utils
 * ------------------------------------------------- */

PyObject* create_class(PyObject* name, PyObject* bases, PyObject* dict);

/* --------------------------------------------------
 *                   Arch
 *  -------------------------------------------------- */

void init_arch(PyObject* module);

/* --------------------------------------------------
 *                   Expr
 *  -------------------------------------------------- */
void init_expression(PyObject* module);

typedef struct {
    PyObject_HEAD
    Expr* expr;
    int size;
} Expr_Object;

PyObject* maat_Cst(PyObject* self, PyObject* args, PyObject* keywords);
PyObject* maat_Var(PyObject* self, PyObject* args, PyObject* keywords);
PyObject* maat_Concat(PyObject* upper, PyObject* lower);
PyObject* maat_Extract(PyObject* self, PyObject* args);
PyObject* PyExpr_FromExpr(Expr e);
PyObject* get_Expr_Type();
#define as_expr_object(x) (*((Expr_Object*)x))

typedef struct {
    PyObject_HEAD
    VarContext* ctx;
    bool is_ref; // Tells if it is owned or just a reference
} VarContext_Object;
PyObject* maat_VarContext(PyObject* self, PyObject* args);
PyObject* PyVarContext_FromVarContext(VarContext* ctx, bool is_ref);
PyObject* get_VarContext_Type();
#define as_varctx_object(x) (*((VarContext_Object*)x))

/* --------------------------------------------------
 *                   Constraint
 *  -------------------------------------------------- */
void init_constraint(PyObject* module);

typedef struct {
    PyObject_HEAD
    Constraint* constr;
} Constraint_Object;
PyObject* PyConstraint_FromConstraint(Constraint c);
PyObject* get_Constraint_Type();
#define as_constraint_object(x) (*((Constraint_Object*)x))

/* --------------------------------------------------
 *                   IR
 *  -------------------------------------------------- */
typedef struct {
    PyObject_HEAD
    IRContext* ctx;
    bool is_ref; // Tells if it is owned or just a reference
} IRContext_Object;
PyObject* PyIRContext_FromIRContext(IRContext* ctx, bool is_ref);
#define as_irctx_object(x) (*((IRContext_Object*)x))


/* --------------------------------------------------
 *                   Memory
 *  -------------------------------------------------- */
void init_memory(PyObject* module);
typedef struct{
    PyObject_HEAD
    MemEngine* mem;
    bool is_ref;
} MemEngine_Object;
PyObject* PyMemEngine_FromMemEngine(MemEngine* mem, bool is_ref);
#define as_mem_object(x) (*((MemEngine_Object*)x))

/* --------------------------------------------------
 *                   Breakpoint
 *  -------------------------------------------------- */
void init_breakpoint(PyObject* module);
 
typedef struct{
    PyObject_HEAD
    BreakpointManager* breakpoint;
    bool is_ref;
} BreakpointManager_Object;
PyObject* PyBreakpointManager_FromBreakpointManager(BreakpointManager* b, bool is_ref);
#define as_break_object(x) (*((BreakpointManager_Object*)x))


/* --------------------------------------------------
 *                   SymbolicEngine
 *  -------------------------------------------------- */
void init_symbolic(PyObject* module);

typedef struct{
    PyObject_HEAD
    PathManager* path;
    bool is_ref;
} PathManager_Object;
PyObject* PyPathManager_FromPathManager(PathManager* path, bool is_ref);
#define as_path_object(x) (*((PathManager_Object*)x))

typedef struct{
    PyObject_HEAD
    MultiBranch* multi;
    bool is_ref;
} MultiBranch_Object;
PyObject* PyMultiBranch_FromMultiBranch(MultiBranch* access, bool is_ref);
#define as_multibranch_object(x)  (*((MultiBranch_Object*)x))

typedef struct{
    PyObject_HEAD
    MemAccess* access;
    bool is_ref;
} MemAccess_Object;
PyObject* PyMemAccess_FromMemAccess(MemAccess* access, bool is_ref);
#define as_memaccess_object(x)  (*((MemAccess_Object*)x))

typedef struct{
    PyObject_HEAD
    SymbolicEngineInfo* info;
    bool is_ref;
} Info_Object;
PyObject* PyInfo_FromInfo(SymbolicEngineInfo* info, bool is_ref);
#define as_info_object(x)  (*((Info_Object*)x))


typedef struct{
    PyObject_HEAD
    SymbolicEngine* sym;
    /* Wrappers to members */
    PyObject* vars;
    PyObject* regs; 
    PyObject* mem; 
    PyObject* breakpoint;
    PyObject* info;
    PyObject* path;
    PyObject* env;
} SymbolicEngine_Object;
PyObject* get_SymbolicEngine_Type();
PyObject* maat_SymbolicEngine(PyObject* self, PyObject* args);
#define as_sym_object(x)  (*((SymbolicEngine_Object*)x))

/* --------------------------------------------------
 *                      Solver
 *  -------------------------------------------------- */

#ifdef HAS_SOLVER_BACKEND
typedef struct{
    PyObject_HEAD
    Solver* solver;
    bool is_ref;
} Solver_Object;
PyObject* get_Solver_Type();
PyObject* maat_Solver(PyObject* module, PyObject* args);
PyObject* PySolver_FromSolver(Solver* solver, bool is_ref);
#define as_solver_object(x)  (*((Solver_Object*)x))
#endif

/* --------------------------------------------------
 *                      Loader
 *  -------------------------------------------------- */
#ifdef HAS_LOADER_BACKEND
void init_loader(PyObject* module);

typedef struct{
    PyObject_HEAD
    CmdlineArg* arg;
} CmdlineArg_Object;
PyObject* get_CmdlineArg_Type();
PyObject* maat_Arg(PyObject* module, PyObject* args, PyObject* keywords);
PyObject* maat_SymArg(PyObject* module, PyObject* args, PyObject* keywords);
#define as_arg_object(x)  (*((CmdlineArg_Object*)x))


typedef struct{
    PyObject_HEAD
    Loader* loader;
    bool is_ref;
} Loader_Object;
PyObject* get_Loader_Type();
PyObject* maat_Loader(PyObject* module, PyObject* args);
PyObject* PyLoader_FromLoader(Loader* solver, bool is_ref);
#define as_loader_object(x)  (*((Loader_Object*)x))
#endif
/* --------------------------------------------------
 *                      Env
 *  -------------------------------------------------- */
void init_env(PyObject* module);

typedef struct{
    PyObject_HEAD
    EnvCallbackReturn* ret;
} EnvCallbackReturn_Object;

PyObject* get_EnvCallbackReturn_Type();
PyObject* maat_EnvCallbackReturn(PyObject* module, PyObject* args);

typedef struct{
    PyObject_HEAD
    EnvManager* env;
    bool is_ref;
} EnvManager_Object;
PyObject* PyEnvManager_FromEnvManager(EnvManager* e, bool is_ref);
#define as_env_object(x) (*((EnvManager_Object*)x))

#endif
