#include "python_bindings.hpp"

/* -------------------------------------
 *        MultiBranch object
 * ------------------------------------ */ 
static void MultiBranch_dealloc(PyObject* self){
    if( ! as_multibranch_object(self).is_ref){
        delete ((MultiBranch_Object*)self)->multi;
    }
    as_multibranch_object(self).multi = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int MultiBranch_print(PyObject* self, void * io, int s){
    std::cout << std::endl << *((MultiBranch_Object*)self)->multi << std::flush;
    return 0;
}

static PyObject* MultiBranch_str(PyObject* self) {
    std::stringstream res;
    res << *((MultiBranch_Object*) self)->multi;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* MultiBranch_repr(PyObject* self) {
    return MultiBranch_str(self);
}

/* Getters for the members */
static PyObject* MultiBranch_get_cond(PyObject* self, void* closure){
    if( as_multibranch_object(self).multi->cond == nullptr ){
        return PyErr_Format(PyExc_AttributeError, "'cond' property is not set currently");
    }
    return PyExpr_FromExpr(as_multibranch_object(self).multi->cond);
}

static PyObject* MultiBranch_get_if_null(PyObject* self, void* closure){
    if( as_multibranch_object(self).multi->if_null == nullptr ){
        return PyErr_Format(PyExc_AttributeError, "'if_null' property is not set currently");
    }
    return PyExpr_FromExpr(as_multibranch_object(self).multi->if_null);
}

static PyObject* MultiBranch_get_if_not_null(PyObject* self, void* closure){
    if( as_multibranch_object(self).multi->if_not_null == nullptr ){
        return PyErr_Format(PyExc_AttributeError, "'if_not_null' property is not set currently");
    }
    return PyExpr_FromExpr(as_multibranch_object(self).multi->if_not_null);
}

static PyGetSetDef MultiBranch_getset[] = {
    {"cond", MultiBranch_get_cond, NULL, "Expression corresponding to the branch condition", NULL},
    {"if_null", MultiBranch_get_if_null, NULL, "Expression corresponding to the target address to jump to if the condition expression is null", NULL},
    {"if_not_null", MultiBranch_get_if_not_null, NULL, "Expression corresponding to the target address to jump to if the condition expression is not null", NULL},
    {NULL}
};

/* Type description for python Expr objects */
PyTypeObject MultiBranch_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "MultiBranch",                                   /* tp_name */
    sizeof(MultiBranch_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)MultiBranch_dealloc,          /* tp_dealloc */
    (printfunc)MultiBranch_print,             /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    MultiBranch_repr,                         /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    MultiBranch_str,                          /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Multiple Branch Info",                   /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    MultiBranch_getset,                       /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

/* Constructors */
PyObject* PyMultiBranch_FromMultiBranch(MultiBranch* multi, bool is_ref){
    MultiBranch_Object* object;
    
    // Create object
    PyType_Ready(&MultiBranch_Type);
    object = PyObject_New(MultiBranch_Object, &MultiBranch_Type);
    if( object != nullptr ){
        object->multi = multi;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}



/* -------------------------------------
 *        MemAccess object
 * ------------------------------------ */ 
static void MemAccess_dealloc(PyObject* self){
    if( ! as_memaccess_object(self).is_ref){
        delete ((MemAccess_Object*)self)->access;
    }
    as_memaccess_object(self).access = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int MemAccess_print(PyObject* self, void * io, int s){
    std::cout << std::endl << *((MultiBranch_Object*)self)->multi << std::flush;
    return 0;
}

static PyObject* MemAccess_str(PyObject* self) {
    std::stringstream res;
    res << *((MemAccess_Object*) self)->access;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* MemAccess_repr(PyObject* self) {
    return MemAccess_str(self);
}

/* Getters for the members */
static PyObject* MemAccess_get_addr(PyObject* self, void* closure){
    if( as_memaccess_object(self).access->addr == nullptr ){
        return PyErr_Format(PyExc_AttributeError, "'addr' property is not set currently");
    }
    return PyExpr_FromExpr(as_memaccess_object(self).access->addr);
}

static PyObject* MemAccess_get_size(PyObject* self, void* closure){
    return PyLong_FromLong(as_memaccess_object(self).access->size);
}

static PyObject* MemAccess_get_value(PyObject* self, void* closure){
    if( as_memaccess_object(self).access->value == nullptr ){
        return PyErr_Format(PyExc_AttributeError, "'value' property is not set currently");
    }
    return PyExpr_FromExpr(as_memaccess_object(self).access->value);
}

static PyGetSetDef MemAccess_getset[] = {
    {"addr", MemAccess_get_addr, NULL, "Expression of the address where the memory is accessed", NULL},
    {"size", MemAccess_get_size, NULL, "Number of bytes accessed", NULL},
    {"value", MemAccess_get_value, NULL, "Expression of the value that is read/written in memory", NULL},
    {NULL}
};

/* Type description for python Expr objects */
PyTypeObject MemAccess_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "MemAccess",                                   /* tp_name */
    sizeof(MemAccess_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)MemAccess_dealloc,            /* tp_dealloc */
    (printfunc)MemAccess_print,               /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    MemAccess_repr,                           /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    MemAccess_str,                            /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Memory Access Info",                     /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    MemAccess_getset,                              /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

/* Constructors */
PyObject* PyMemAccess_FromMemAccess(MemAccess* access, bool is_ref){
    MemAccess_Object* object;
    
    // Create object
    PyType_Ready(&MemAccess_Type);
    object = PyObject_New(MemAccess_Object, &MemAccess_Type);
    if( object != nullptr ){
        object->access = access;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}


/* -------------------------------------
 *       SymbolicEngineInfo object
 * ------------------------------------ */
static void Info_dealloc(PyObject* self){
    if( ! as_info_object(self).is_ref){
        delete ((Info_Object*)self)->info;
    }
    as_info_object(self).info = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* Info_str(PyObject* self) {
    std::stringstream res;
    res << *((Info_Object*) self)->info;
    return PyUnicode_FromString(res.str().c_str());
}

static int Info_print(PyObject* self, void * io, int s){
    std::cout << *((Info_Object*)self)->info << std::flush;
    return 0;
}

static PyObject* Info_repr(PyObject* self) {
    return Info_str(self);
}

/* Getters for the members */
static PyObject* Info_get_stop(PyObject* self, void* closure){
    return PyLong_FromLong((int)as_info_object(self).info->stop);
}

static PyObject* Info_get_breakpoint(PyObject* self, void* closure){
    return PyUnicode_FromString(as_info_object(self).info->breakpoint.c_str());
}

static PyObject* Info_get_addr(PyObject* self, void* closure){
    return PyLong_FromUnsignedLongLong(as_info_object(self).info->addr);
}

static PyObject* Info_get_branch(PyObject* self, void* closure){
    if( as_info_object(self).info->branch == nullptr ){
        return PyErr_Format(PyExc_AttributeError, "'branch' property is not set currently");
    }
    return PyExpr_FromExpr(as_info_object(self).info->branch);
}

static PyObject* Info_get_mem_access(PyObject* self, void* closure){
    return PyMemAccess_FromMemAccess(&(as_info_object(self).info->mem_access), true);
}

static PyObject* Info_get_multibranch(PyObject* self, void* closure){
    return PyMultiBranch_FromMultiBranch(&(as_info_object(self).info->multibranch), true);
}

static PyObject* Info_get_path_constraint(PyObject* self, void* closure){
    if( as_info_object(self).info->path_constraint == nullptr ){
        return PyErr_Format(PyExc_AttributeError, "'path_constraint' property is not set currently");
    }
    return PyConstraint_FromConstraint(as_info_object(self).info->path_constraint);
}

static PyGetSetDef Info_getset[] = {
    {"stop", Info_get_stop, NULL, "Latest reason why the symbolic engine stopped", NULL},
    {"addr", Info_get_addr, NULL, "Address of the instruction where the symbolic engine stopped", NULL},
    {"breakpoint", Info_get_breakpoint, NULL, "Name of the breakpoint that was hit (if any)", NULL},
    {"branch", Info_get_branch, NULL, "Expression representing the execution address to be jumped to", NULL},
    {"mem_access", Info_get_mem_access, NULL, "Information about the memory access corresponding to the breakpoint that was raised (if any)", NULL},
    {"multibranch", Info_get_multibranch, NULL, "Information about the multiple branchment to be taken (if any)", NULL},
    {"path_constraint", Info_get_path_constraint, NULL, "Information about the path constraint about to be added (if any)", NULL},
    {NULL}
};

/* Type description for python Info objects */
PyTypeObject Info_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Info",                                   /* tp_name */
    sizeof(Info_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Info_dealloc,                 /* tp_dealloc */
    (printfunc)Info_print,                    /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    Info_repr,                                /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    Info_str,                                 /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Symbolic Engine Info",                   /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    Info_getset,                              /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

/* Constructors */
PyObject* PyInfo_FromInfo(SymbolicEngineInfo* info, bool is_ref){
    Info_Object* object;
    
    // Create object
    PyType_Ready(&Info_Type);
    object = PyObject_New(Info_Object, &Info_Type);
    if( object != nullptr ){
        object->info = info;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}




/* -------------------------------------
 *          SymbolicEngine object
 * ------------------------------------ */

static void SymbolicEngine_dealloc(PyObject* self){
    delete ((SymbolicEngine_Object*)self)->sym;  ((SymbolicEngine_Object*)self)->sym = nullptr;
    Py_DECREF(as_sym_object(self).vars);
    Py_DECREF(as_sym_object(self).regs);
    Py_DECREF(as_sym_object(self).mem);
    Py_DECREF(as_sym_object(self).breakpoint);
    Py_DECREF(as_sym_object(self).info);
    Py_DECREF(as_sym_object(self).path);
    Py_DECREF(as_sym_object(self).env);
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* SymbolicEngine_execute(PyObject* self, PyObject* args){
    unsigned int max_instr = 0;
    StopInfo res;
    
    if( ! PyArg_ParseTuple(args, "|I", &max_instr) ){
        return NULL;
    }
    try{
        res = as_sym_object(self).sym->execute(max_instr);
    }catch(symbolic_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, " -- Fatal error -- : %s\n Objects may have been left be in an unstable state. ", e.what());
    }
    return PyLong_FromLong((int)res);
};

static PyObject* SymbolicEngine_execute_from(PyObject* self, PyObject* args){
    unsigned long long addr;
    unsigned int max_instr = 0;
    StopInfo res;
    
    if( ! PyArg_ParseTuple(args, "K|I", &addr, &max_instr) ){
        return NULL;
    }
    try{ 
        res = as_sym_object(self).sym->execute_from(addr, max_instr);
    }catch(symbolic_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(runtime_exception& e){
        return PyErr_Format(PyExc_RuntimeError, " -- Fatal error -- : %s\n Objects may have been left be in an unstable state. ", e.what());
    }
    return PyLong_FromLong((int)res);
};

static PyObject* SymbolicEngine_enable(PyObject* self, PyObject* args){
    unsigned int option;
    
    if( ! PyArg_ParseTuple(args, "I", &option) ){
        return NULL;
    }
    
    as_sym_object(self).sym->enable((SymbolicEngineOption)option);
    Py_RETURN_NONE;
};

static PyObject* SymbolicEngine_disable(PyObject* self, PyObject* args){
    unsigned int option;
    
    if( ! PyArg_ParseTuple(args, "I", &option) ){
        return NULL;
    }
    
    as_sym_object(self).sym->disable((SymbolicEngineOption)option);
    Py_RETURN_NONE;
};

static PyObject* SymbolicEngine_is_enabled(PyObject* self, PyObject* args){
    unsigned int option;
    
    if( ! PyArg_ParseTuple(args, "I", &option) ){
        return NULL;
    }
    
    if( as_sym_object(self).sym->is_enabled((SymbolicEngineOption)option))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
};

static PyObject* SymbolicEngine_take_snapshot(PyObject* self){
    unsigned int snap_id;
    
    snap_id = as_sym_object(self).sym->take_snapshot();
    return PyLong_FromLong(snap_id);
};

static PyObject* SymbolicEngine_restore_snapshot(PyObject* self, PyObject* args, PyObject* keywords){
    unsigned int id = -1;
    int remove = 0;
    static char *kwlist[] = {"", "remove", NULL};
    bool res;

    if( ! PyArg_ParseTupleAndKeywords(args, keywords, "|Ip", kwlist, &id, &remove) ){
        return NULL;
    }
    
    try{
        if( id == -1 ){
            res = as_sym_object(self).sym->restore_snapshot((bool)remove);
        }else{
            res = as_sym_object(self).sym->restore_snapshot(id, (bool)remove);
        }
    }catch(snapshot_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    
    if( res )
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
};

static PyObject* SymbolicEngine_get_symbol_address(PyObject* self, PyObject* args){
    char * name;
    int len; 
    addr_t res;
    
    if( ! PyArg_ParseTuple(args, "s#", &name, &len) ){
        return NULL;
    }
    
    try{
        res = as_sym_object(self).sym->get_symbol_address(string(name, len));
    }catch(symbolic_exception& e){
        return PyErr_Format(PyExc_KeyError, "%s", e.what());
    }
    return PyLong_FromUnsignedLongLong(res);
};

static PyMethodDef SymbolicEngine_methods[] = {
    {"execute", (PyCFunction)SymbolicEngine_execute, METH_VARARGS, "Continue to execute code from current location"},
    {"execute_from", (PyCFunction)SymbolicEngine_execute_from, METH_VARARGS, "Execute code from a given address"},
    {"take_snapshot", (PyCFunction)SymbolicEngine_take_snapshot, METH_NOARGS, "Take a snapshot of the symbolic engine"},
    {"restore_snapshot", (PyCFunction)SymbolicEngine_restore_snapshot, METH_VARARGS | METH_KEYWORDS, "Restore a snapshot of the symbolic engine"},
    {"enable", (PyCFunction)SymbolicEngine_enable, METH_VARARGS, "Enable an option for the symbolic engine"},
    {"disable", (PyCFunction)SymbolicEngine_disable, METH_VARARGS, "Disable an option for the symbolic engine"},
    {"is_enabled", (PyCFunction)SymbolicEngine_is_enabled, METH_VARARGS, "Check whether an option is enabled for the symbolic engine"},
    {"get_symbol_address", (PyCFunction)SymbolicEngine_get_symbol_address, METH_VARARGS, "Get the absolute virtual address of the given symbol"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef SymbolicEngine_members[] = {
    {"vars", T_OBJECT_EX, offsetof(SymbolicEngine_Object, vars), READONLY, "Symbolic Variables Context"},
    {"regs", T_OBJECT_EX, offsetof(SymbolicEngine_Object, regs), READONLY, "Registers Context"},
    {"mem", T_OBJECT_EX, offsetof(SymbolicEngine_Object, mem), READONLY, "Memory Engine"},
    {"breakpoint", T_OBJECT_EX, offsetof(SymbolicEngine_Object, breakpoint), READONLY, "Breakpoint Manager"},
    {"info", T_OBJECT_EX, offsetof(SymbolicEngine_Object, info), READONLY, "Symbolic Engine Info"},
    {"path", T_OBJECT_EX, offsetof(SymbolicEngine_Object, path), READONLY, "Path Manager"},
    {"env", T_OBJECT_EX, offsetof(SymbolicEngine_Object, env), READONLY, "Environment Manager"},
    {NULL}
};

/* Type description for python Expr objects */
PyTypeObject SymbolicEngine_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "SymbolicEngine",                         /* tp_name */
    sizeof(SymbolicEngine_Object),            /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)SymbolicEngine_dealloc,       /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Dynamic Symbolic Execution Engine",      /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    SymbolicEngine_methods,                   /* tp_methods */
    SymbolicEngine_members,                   /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

PyObject* get_SymbolicEngine_Type(){
    return (PyObject*)&SymbolicEngine_Type;
};

/* Constructor */
PyObject* maat_SymbolicEngine(PyObject* self, PyObject* args){
    SymbolicEngine_Object* object;
    int arch;
    int sys = (int)SysType::NONE;
    
    // Parse arguments
    if( ! PyArg_ParseTuple(args, "i|i", &arch, &sys) ){
        return NULL;
    }
    
    // Create object
    try{
        PyType_Ready(&SymbolicEngine_Type);
        object = PyObject_New(SymbolicEngine_Object, &SymbolicEngine_Type);
        if( object != nullptr ){
            object->sym = new SymbolicEngine((ArchType)arch, (SysType)sys);
            object->sym->set_self_python_wrapper_object((PyObject*)object);
            /* Create wrappers with references to members */
            object->vars = PyVarContext_FromVarContext(object->sym->vars, true);
            object->regs = PyIRContext_FromIRContext(object->sym->regs, true);
            object->mem = PyMemEngine_FromMemEngine(object->sym->mem, true);
            object->breakpoint = PyBreakpointManager_FromBreakpointManager(&(object->sym->breakpoint), true);
            object->info = PyInfo_FromInfo(&(object->sym->info), true);
            object->path = PyPathManager_FromPathManager(object->sym->path, true);
            object->env = PyEnvManager_FromEnvManager(object->sym->env, true);
        }
    }catch(symbolic_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    return (PyObject*)object;
}


/* -------------------------------------
 *          Init function
 * ------------------------------------ */
void init_symbolic(PyObject* module){
    /* STOP enum */
    PyObject* stop_enum = PyDict_New();
    PyDict_SetItemString(stop_enum, "BREAKPOINT", PyLong_FromLong((int)StopInfo::BREAKPOINT));
    PyDict_SetItemString(stop_enum, "SYMBOLIC_PC", PyLong_FromLong((int)StopInfo::SYMBOLIC_PC));
    PyDict_SetItemString(stop_enum, "SYMBOLIC_CODE", PyLong_FromLong((int)StopInfo::SYMBOLIC_CODE));
    PyDict_SetItemString(stop_enum, "MISSING_FUNCTION", PyLong_FromLong((int)StopInfo::MISSING_FUNCTION));
    PyDict_SetItemString(stop_enum, "EXIT", PyLong_FromLong((int)StopInfo::EXIT));
    PyDict_SetItemString(stop_enum, "INSTR_COUNT", PyLong_FromLong((int)StopInfo::INSTR_COUNT));
    PyDict_SetItemString(stop_enum, "ILLEGAL_INSTRUCTION", PyLong_FromLong((int)StopInfo::ILLEGAL_INSTRUCTION));
    PyDict_SetItemString(stop_enum, "ERROR", PyLong_FromLong((int)StopInfo::ERROR));
    PyDict_SetItemString(stop_enum, "NONE", PyLong_FromLong((int)StopInfo::NONE));
    PyObject* stop_class = create_class(PyUnicode_FromString("STOP"), PyTuple_New(0), stop_enum);
    PyModule_AddObject(module, "STOP", stop_class);
    
    /* OPTION enum */
    PyObject* option_enum = PyDict_New();
    PyDict_SetItemString(option_enum, "FORCE_CST_FOLDING", PyLong_FromLong((int)SymbolicEngineOption::FORCE_CST_FOLDING));
    PyDict_SetItemString(option_enum, "OPTIMIZE_IR", PyLong_FromLong((int)SymbolicEngineOption::OPTIMIZE_IR));
    PyDict_SetItemString(option_enum, "RECORD_PATH_CONSTRAINTS", PyLong_FromLong((int)SymbolicEngineOption::RECORD_PATH_CONSTRAINTS));
    PyDict_SetItemString(option_enum, "SIMPLIFY_CONSTRAINTS", PyLong_FromLong((int)SymbolicEngineOption::SIMPLIFY_CONSTRAINTS));
    PyDict_SetItemString(option_enum, "IGNORE_MISSING_IMPORTS", PyLong_FromLong((int)SymbolicEngineOption::IGNORE_MISSING_IMPORTS));
    PyDict_SetItemString(option_enum, "IGNORE_MISSING_SYSCALLS", PyLong_FromLong((int)SymbolicEngineOption::IGNORE_MISSING_SYSCALLS));
    PyDict_SetItemString(option_enum, "PRINT_INSTRUCTIONS", PyLong_FromLong((int)SymbolicEngineOption::PRINT_INSTRUCTIONS));
    PyDict_SetItemString(option_enum, "PRINT_WARNINGS", PyLong_FromLong((int)SymbolicEngineOption::PRINT_WARNINGS));
    PyDict_SetItemString(option_enum, "PRINT_ERRORS", PyLong_FromLong((int)SymbolicEngineOption::PRINT_ERRORS));
    PyObject* option_class = create_class(PyUnicode_FromString("OPTION"), PyTuple_New(0), option_enum);
    PyModule_AddObject(module, "OPTION", option_class);
};
