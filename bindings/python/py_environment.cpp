#include "python_bindings.hpp"

/* -------------------------------------
 *           EnvCallbackReturn
 * ------------------------------------ */

/* Methods */

static void EnvCallbackReturn_dealloc(PyObject* self){
    delete ((EnvCallbackReturn_Object*)self)->ret;  ((EnvCallbackReturn_Object*)self)->ret = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyMethodDef EnvCallbackReturn_methods[] = {
    {NULL, NULL, 0, NULL}
};

static PyMemberDef EnvCallbackReturn_members[] = {
    {NULL}
};


/* Type description for python Expr objects */
PyTypeObject EnvCallbackReturn_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "EnvCallbackReturn",                                   /* tp_name */
    sizeof(EnvCallbackReturn_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)EnvCallbackReturn_dealloc,                 /* tp_dealloc */
    0,                    /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    0,                                /* tp_repr */
    0,                          /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    0,                                 /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Return status for simualted functions",     /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    EnvCallbackReturn_methods,                       /* tp_methods */
    EnvCallbackReturn_members,                       /* tp_members */
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

PyObject* get_EnvCallbackReturn_Type(){
    return (PyObject*)&EnvCallbackReturn_Type;
};

/* Constructors */
PyObject* PyEnvCallbackReturn_FromEnvCallbackReturn(EnvCallbackReturn* ret){
    EnvCallbackReturn_Object* object;
    
    // Create object
    PyType_Ready(&EnvCallbackReturn_Type);
    object = PyObject_New(EnvCallbackReturn_Object, &EnvCallbackReturn_Type);
    if( object != nullptr ){
        object->ret = ret;
    }
    return (PyObject*)object;
}

PyObject* maat_EnvCallbackReturn(PyObject* module, PyObject* args){
    unsigned int status;
    PyObject* value = nullptr;
    EnvCallbackReturn* ret = nullptr;
    cst_t val;
    Expr e;
    
    if( ! PyArg_ParseTuple(args, "L|O", &status, &value)){
        return NULL;
    }
    
    if( value == nullptr ){
        ret = new EnvCallbackReturn(status);
    }else{
        if( PyLong_Check(value)){
            val = PyLong_AsLongLong(value);
            ret = new EnvCallbackReturn(status, val);
        }else if( PyObject_TypeCheck(value, (PyTypeObject*)get_Expr_Type())){
            e = *(as_expr_object(value).expr);
            ret = new EnvCallbackReturn(status, e);
        }else{
            return PyErr_Format(PyExc_TypeError, "EnvCallbackReturn()'s second argument must be int or Expr");
        }
    }
    return PyEnvCallbackReturn_FromEnvCallbackReturn(ret);
}

/* -------------------------------------
 *          EnvManager object
 * ------------------------------------ */

static void EnvManager_dealloc(PyObject* self){
    if( ! as_env_object(self).is_ref){
        delete as_env_object(self).env;
    }
    as_env_object(self).env = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* EnvManager_add_function(PyObject* self, PyObject* args){
    char* name;
    int abi;
    PyObject* callback = NULL, *callback_args = NULL;
    Py_ssize_t i;
    
    vector<size_t> native_args;
    // Constructor in native for EnvFunction is : 
    //    EnvFunction(PyObject* c, string n, ABI default_abi, vector<size_t> a
    
    if( !PyArg_ParseTuple(args, "Osi|O", &callback, &name, &abi, &callback_args) ){
        return NULL;
    }
    
    // Check that callback is callable
    if( !PyCallable_Check(callback)){
        return PyErr_Format(PyExc_ValueError, "add_function(): first argument must be a callable function");
    }
    // Check that arguments is a list (if any)
    if( callback_args != NULL ){
        
        if( !PyList_Check(callback_args)){
            return PyErr_Format(PyExc_ValueError, "add_function(): 4th argument must be a list of arguments sizes");
        }

        for( i = 0; i < PyList_Size(callback_args); i++){
            native_args.push_back(PyLong_AsLong(PyList_GetItem(callback_args, i)));
        }
    }

    try{
        as_env_object(self).env->add_function(new EnvFunction(callback, string(name), (ABI)abi, native_args));
    }catch(env_exception e){
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
    
    Py_RETURN_NONE;
};


static PyMethodDef EnvManager_methods[] = {
    {"add_function", (PyCFunction)EnvManager_add_function, METH_VARARGS , "Add a simulated function"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef EnvManager_members[] = {
    {NULL}
};


/* Type description for python BreakopintManager objects */
static PyTypeObject EnvManager_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "EnvManager",                             /* tp_name */
    sizeof(EnvManager_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)EnvManager_dealloc,           /* tp_dealloc */
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
    "Env manager",                            /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    EnvManager_methods,                       /* tp_methods */
    EnvManager_members,                       /* tp_members */
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
PyObject* PyEnvManager_FromEnvManager(EnvManager* e, bool is_ref){
    EnvManager_Object* object;
    
    // Create object
    PyType_Ready(&EnvManager_Type);
    object = PyObject_New(EnvManager_Object, &EnvManager_Type);
    if( object != nullptr ){
        object->env = e;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}


/* -------------------------------------
 *    Initialisation function for enums
 * ------------------------------------ */

void init_env(PyObject* module){
    
    /* SYS enum */
    PyObject* sys_enum = PyDict_New();
    PyDict_SetItemString(sys_enum, "LINUX", PyLong_FromLong((int)SysType::LINUX));
    PyDict_SetItemString(sys_enum, "WINDOWS", PyLong_FromLong((int)SysType::WINDOWS));
    PyDict_SetItemString(sys_enum, "NONE", PyLong_FromLong((int)SysType::NONE));
    PyObject* sys_class = create_class(PyUnicode_FromString("SYS"), PyTuple_New(0), sys_enum);
    PyModule_AddObject(module, "SYS", sys_class);
    
    /* CALLBACK enum */
    PyObject* callback_enum = PyDict_New();
    PyDict_SetItemString(callback_enum, "SUCCESS", PyLong_FromLong(ENV_CALLBACK_SUCCESS));
    PyDict_SetItemString(callback_enum, "SUCCESS_WITH_VALUE", PyLong_FromLong(ENV_CALLBACK_SUCCESS_WITH_VALUE));
    PyDict_SetItemString(callback_enum, "FAIL", PyLong_FromLong(ENV_CALLBACK_FAIL));
    PyDict_SetItemString(callback_enum, "EXIT", PyLong_FromLong(ENV_CALLBACK_EXIT));
    PyObject* callback_class = create_class(PyUnicode_FromString("CALLBACK"), PyTuple_New(0), callback_enum);
    PyModule_AddObject(module, "CALLBACK", callback_class);
    
    /* ABI enum */
    PyObject* abi_enum = PyDict_New();
    PyDict_SetItemString(abi_enum, "X86_CDECL", PyLong_FromLong((int)ABI::X86_CDECL));
    PyDict_SetItemString(abi_enum, "X86_STDCALL", PyLong_FromLong((int)ABI::X86_STDCALL));
    PyDict_SetItemString(abi_enum, "X86_FASTCALL", PyLong_FromLong((int)ABI::X86_FASTCALL));
    PyDict_SetItemString(abi_enum, "X86_THISCALL_GCC", PyLong_FromLong((int)ABI::X86_THISCALL_GCC));
    PyDict_SetItemString(abi_enum, "X86_THISCALL_MS", PyLong_FromLong((int)ABI::X86_THISCALL_MS));
    PyDict_SetItemString(abi_enum, "X86_LINUX_SYSENTER", PyLong_FromLong((int)ABI::X86_LINUX_SYSENTER));
    PyDict_SetItemString(abi_enum, "X86_LINUX_INT80", PyLong_FromLong((int)ABI::X86_LINUX_INT80));
    PyDict_SetItemString(abi_enum, "X64_MS", PyLong_FromLong((int)ABI::X64_MS));
    PyDict_SetItemString(abi_enum, "X64_SYSTEM_V", PyLong_FromLong((int)ABI::X64_SYSTEM_V));
    PyDict_SetItemString(abi_enum, "X86_LINUX_CUSTOM_SYSCALL", PyLong_FromLong((int)ABI::X86_LINUX_CUSTOM_SYSCALL));
    PyObject* abi_class = create_class(PyUnicode_FromString("ABI"), PyTuple_New(0), abi_enum);
    PyModule_AddObject(module, "ABI", abi_class);
};

