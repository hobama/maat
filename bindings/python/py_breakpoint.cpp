#include "python_bindings.hpp"

/* -------------------------------------
 *        BreakpointManager object
 * ------------------------------------ */

static void BreakpointManager_dealloc(PyObject* self){
    if( ! as_break_object(self).is_ref){
        delete as_break_object(self).breakpoint;
    }
    as_break_object(self).breakpoint = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* BreakpointManager_add(PyObject* self, PyObject*args, PyObject* keywords ){
    int type;
    const char* name;
    long long value1=0, value2=0;
    PyObject* callback = NULL;
    bool resume = false;
    
    char* keywd[] = {"", "", "", "", "callback", "resume", NULL};
    
    if( !PyArg_ParseTupleAndKeywords(args, keywords, "is|LLOp", keywd, &type, &name, &value1, &value2, &callback, &resume) ){
        return NULL;
    }
    // Check if callback is valid
    if( callback != NULL && !PyCallable_Check(callback)){
        return PyErr_Format(PyExc_ValueError, "%s", "'callback' argument must a function with one argument: callable(SymbolicEngine: sym)");
    }
    
    /* Handle the case where optional parameter was not specified, then it must be equal to the 
     * first value parameter */
    if( PyTuple_Size(args) == 3 ){
        value2 = value1;
    }
    
    try{
        as_break_object(self).breakpoint->add_from_python((BreakpointType)type, string(name), value1, value2, callback, resume);
    }catch(breakpoint_exception e){
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    Py_RETURN_NONE;
};

static PyObject* BreakpointManager_remove(PyObject* self, PyObject*args ){
    const char* name;
    
    if( !PyArg_ParseTuple(args, "s", &name) ){
        return NULL;
    }
    as_break_object(self).breakpoint->remove(string(name));
    Py_RETURN_NONE;
};

static PyObject* BreakpointManager_remove_all(PyObject* self ){
    as_break_object(self).breakpoint->remove_all();
    Py_RETURN_NONE;
};

static PyMethodDef BreakpointManager_methods[] = {
    {"add", (PyCFunction)BreakpointManager_add, METH_VARARGS | METH_KEYWORDS, "Add a breakpoint"},
    {"remove", (PyCFunction)BreakpointManager_remove, METH_VARARGS, "Remove a given breakpoint"},
    {"remove_all", (PyCFunction)BreakpointManager_remove_all, METH_NOARGS, "Remove all breakpoints"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef BreakpointManager_members[] = {
    {NULL}
};

/* Type description for python BreakopintManager objects */
static PyTypeObject BreakpointManager_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "BreakpointManager",                             /* tp_name */
    sizeof(BreakpointManager_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)BreakpointManager_dealloc,           /* tp_dealloc */
    0,                                       /* tp_print */
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
    "Breakpoint manager",                  /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    BreakpointManager_methods,                /* tp_methods */
    BreakpointManager_members,                /* tp_members */
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

/* Constructors */
PyObject* PyBreakpointManager_FromBreakpointManager(BreakpointManager* b, bool is_ref){
    BreakpointManager_Object* object;
    
    // Create object
    PyType_Ready(&BreakpointManager_Type);
    object = PyObject_New(BreakpointManager_Object, &BreakpointManager_Type);
    if( object != nullptr ){
        object->breakpoint = b;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}


/* -------------------------------------
 *           Init function
 * ------------------------------------ */
void init_breakpoint(PyObject* module){
    /* BREAK enum */
    PyObject* break_enum = PyDict_New();
    PyDict_SetItemString(break_enum, "ADDR", PyLong_FromLong((int)BreakpointType::ADDR));
    PyDict_SetItemString(break_enum, "REGISTER_R", PyLong_FromLong((int)BreakpointType::REGISTER_R));
    PyDict_SetItemString(break_enum, "REGISTER_W", PyLong_FromLong((int)BreakpointType::REGISTER_W));
    PyDict_SetItemString(break_enum, "REGISTER_RW", PyLong_FromLong((int)BreakpointType::REGISTER_RW));
    PyDict_SetItemString(break_enum, "MEMORY_R", PyLong_FromLong((int)BreakpointType::MEMORY_R));
    PyDict_SetItemString(break_enum, "MEMORY_W", PyLong_FromLong((int)BreakpointType::MEMORY_W));
    PyDict_SetItemString(break_enum, "MEMORY_RW", PyLong_FromLong((int)BreakpointType::MEMORY_RW));
    PyDict_SetItemString(break_enum, "BRANCH", PyLong_FromLong((int)BreakpointType::BRANCH));
    PyDict_SetItemString(break_enum, "MULTIBRANCH", PyLong_FromLong((int)BreakpointType::MULTIBRANCH));
    PyDict_SetItemString(break_enum, "PATH_CONSTRAINT", PyLong_FromLong((int)BreakpointType::PATH_CONSTRAINT));
    PyDict_SetItemString(break_enum, "TAINTED_PC", PyLong_FromLong((int)BreakpointType::TAINTED_PC));
    PyDict_SetItemString(break_enum, "TAINTED_CODE", PyLong_FromLong((int)BreakpointType::TAINTED_CODE));
    PyObject* break_class = create_class(PyUnicode_FromString("BREAK"), PyTuple_New(0), break_enum);
    PyModule_AddObject(module, "BREAK", break_class);
    
}
