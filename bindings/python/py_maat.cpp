#include "Python.h"
#include "python_bindings.hpp"

/* Module methods */
PyMethodDef module_methods[] = {
    /* Expr */
    {"Cst", (PyCFunction)maat_Cst, METH_VARARGS | METH_KEYWORDS, "Create a constant expression"},
    {"Var", (PyCFunction)maat_Var, METH_VARARGS | METH_KEYWORDS, "Create a symbolic variable"},
    {"Concat", (PyCFunction)maat_Concat, METH_VARARGS, "Concatenate two expressions"},
    {"Extract", (PyCFunction)maat_Extract, METH_VARARGS, "Bitfield extract from an expression"},
    /* VarContext */
    {"VarContext", (PyCFunction)maat_VarContext, METH_VARARGS, "Create an empty VarContext"},
    /* SymbolicEngine */
    {"SymbolicEngine", (PyCFunction)maat_SymbolicEngine, METH_VARARGS, "Create a new DSE engine"},
#ifdef HAS_SOLVER_BACKEND
    /* Solver */
    {"Solver", (PyCFunction)maat_Solver, METH_VARARGS, "Create a constraint solver for the given symbolic engine"},
#endif
#ifdef HAS_LOADER_BACKEND
    /* Loader */
    {"Arg", (PyCFunction)maat_Arg, METH_VARARGS | METH_KEYWORDS, "Command line argument"},
    {"SymArg", (PyCFunction)maat_SymArg, METH_VARARGS | METH_KEYWORDS, "Fully-symbolic command line arguument"},
    {"Loader", (PyCFunction)maat_Loader, METH_VARARGS, "Create a binary loader for the given symbolic engine"},
    /* Env */
    {"EnvCallbackReturn", (PyCFunction)maat_EnvCallbackReturn, METH_VARARGS, "Return status for simulated function"},
#endif
    {NULL}
    
};


/* Module information */
PyModuleDef maat_module_def = {
    PyModuleDef_HEAD_INIT,
    "maat",
    nullptr,
    -1,      // m_size
    module_methods, // m_methods
    nullptr, // m_slots
    nullptr, // m_traverse
    nullptr, // m_clear
    nullptr  // m_free    
};

PyMODINIT_FUNC PyInit_maat(){
    Py_Initialize();
    PyObject* module = PyModule_Create(&maat_module_def);
    
    init_arch(module);
    init_expression(module);
    init_memory(module);
    init_symbolic(module);
    init_breakpoint(module);
    init_constraint(module);
#ifdef HAS_LOADER_BACKEND
    init_loader(module);
#endif
    init_env(module);
    return module;
}

