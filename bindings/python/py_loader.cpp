#ifdef HAS_LOADER_BACKEND

#include "python_bindings.hpp"

/* -------------------------------------
 *           CmdlineArg object
 * ------------------------------------ */

static void CmdlineArg_dealloc(PyObject* self){
    delete ((CmdlineArg_Object*)self)->arg;
    as_arg_object(self).arg = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyMethodDef CmdlineArg_methods[] = {
    {NULL, NULL, 0, NULL}
};

static PyMemberDef CmdlineArg_members[] = {
    {NULL}
};

/* Type description for python CmdlineArg objects */
static PyTypeObject CmdlineArg_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "CmdlineArg",                             /* tp_name */
    sizeof(CmdlineArg_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)CmdlineArg_dealloc,           /* tp_dealloc */
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
    "Binary loader",                          /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    CmdlineArg_methods,                       /* tp_methods */
    CmdlineArg_members,                       /* tp_members */
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

PyObject* get_CmdlineArg_Type(){
    return (PyObject*) &CmdlineArg_Type;
}

PyObject* PyCmdlineArg(string str, bool is_tainted){
    CmdlineArg_Object* object;
    
    // Create object
    PyType_Ready(&CmdlineArg_Type);
    object = PyObject_New(CmdlineArg_Object, &CmdlineArg_Type);
    if( object != nullptr ){
        object->arg = new CmdlineArg(str, is_tainted);
    }
    return (PyObject*)object;
}

PyObject* PyCmdlineArg(string str, unsigned int len, bool is_tainted){
    CmdlineArg_Object* object;
    
    // Create object
    PyType_Ready(&CmdlineArg_Type);
    object = PyObject_New(CmdlineArg_Object, &CmdlineArg_Type);
    if( object != nullptr ){
        object->arg = new CmdlineArg(str, len, is_tainted);
    }
    return (PyObject*)object;
}

PyObject* maat_Arg(PyObject* module, PyObject* args, PyObject* keywords){
    int is_tainted = 0;
    char * str;
    int str_len;
    
    char * kwds[] = {"", "tainted", NULL};
    
    if( ! PyArg_ParseTupleAndKeywords(args, keywords, "s#|p", kwds, &str, &str_len, &is_tainted)){
        return NULL;
    }
    
    return PyCmdlineArg(string(str, str_len), (bool)is_tainted); 
}

PyObject* maat_SymArg(PyObject* module, PyObject* args, PyObject* keywords){
    int is_tainted = 0;
    char * str;
    int str_len;
    unsigned int len;
    
    char * kwds[] = {"", "", "tainted", NULL};
    
    if( ! PyArg_ParseTupleAndKeywords(args, keywords, "s#I|p", kwds, &str, &str_len, &len, &is_tainted)){
        return NULL;
    }
    
    return PyCmdlineArg(string(str, str_len), len, (bool)is_tainted); 
}


/* -------------------------------------
 *           Loader object
 * ------------------------------------ */

static void Loader_dealloc(PyObject* self){
    if( ! as_loader_object(self).is_ref){
        delete ((Loader_Object*)self)->loader;
    }
    as_loader_object(self).loader = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* Loader_load(PyObject* self, PyObject* args, PyObject* keywords){
    char * name;
    int bin_type;
    unsigned long long base = 0;
    PyObject* py_cmdline_args = nullptr, *arg = nullptr;
    PyObject* py_env_variables = nullptr, *env_var = nullptr;
    vector<CmdlineArg> cmdline_args;
    vector<string> env_variables;
    Py_ssize_t i;
    
    char* keywd[] = {"", "", "base", "args", "env", NULL};
    
    if( !PyArg_ParseTupleAndKeywords(args, keywords, "si|KOO", keywd, &name, &bin_type, &base, &py_cmdline_args, &py_env_variables)){
        return NULL;
    }
    
    /* Build args vector */
    if( py_cmdline_args != nullptr ){
        // Check if it's a list
        if( !PyList_Check(py_cmdline_args) ){
            return PyErr_Format(PyExc_TypeError, "Loader::load(): 'args' parameter must be a list");
        }
        for( i = 0; i < PyList_Size(py_cmdline_args); i++){
            arg = PyList_GetItem(py_cmdline_args, i);
            if( !PyObject_TypeCheck(arg, (PyTypeObject*)get_CmdlineArg_Type()) ){
                return PyErr_Format(PyExc_TypeError, "Loader::load(): wrong argument type for argument %d", i);
            }
            cmdline_args.push_back(*(as_arg_object(arg).arg));
        }
    }
    /* Build env variables vector */
    if( py_env_variables != nullptr ){
        // Check if it's a list
        if( !PyList_Check(py_env_variables) ){
            return PyErr_Format(PyExc_TypeError, "Loader::load(): 'env' parameter must be a list");
        }
        for( i = 0; i < PyList_Size(py_env_variables); i++){
            env_var = PyList_GetItem(py_env_variables, i);
            if( !PyBytes_Check(env_var) ){
                return PyErr_Format(PyExc_TypeError, "Loader::load(): env variables must be bytes");
            }
            env_variables.push_back(string(PyBytes_AsString(env_var)));
        }
    }
    
    try{
        as_loader_object(self).loader->load(name, (BinType)bin_type, (addr_t)base, cmdline_args, env_variables);
    }catch(std::exception& e){
        return PyErr_Format(PyExc_RuntimeError, e.what());
    }
    
    Py_RETURN_NONE;
};

static PyMethodDef Loader_methods[] = {
    {"load", (PyCFunction)Loader_load, METH_VARARGS | METH_KEYWORDS, "Load a binary into the associated symbolic engine"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef Loader_members[] = {
    {NULL}
};


/* Type description for python Loader objects */
static PyTypeObject Loader_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Loader",                             /* tp_name */
    sizeof(Loader_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Loader_dealloc,           /* tp_dealloc */
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
    "Binary loader",                          /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Loader_methods,                       /* tp_methods */
    Loader_members,                       /* tp_members */
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

PyObject* get_Loader_Type(){
    return (PyObject*)&Loader_Type;
}

/* Constructors */
PyObject* PyLoader_FromLoader(Loader* loader, bool is_ref){
    Loader_Object* object;
    
    // Create object
    PyType_Ready(&Loader_Type);
    object = PyObject_New(Loader_Object, &Loader_Type);
    if( object != nullptr ){
        object->loader = loader;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

PyObject* maat_Loader(PyObject* module, PyObject* args){
    PyObject* sym = nullptr;
    
    if( ! PyArg_ParseTuple(args, "O!", get_SymbolicEngine_Type(), &sym)){
        return NULL;
    }
    Loader* res = NewLoader(*(as_sym_object(sym).sym));
    return PyLoader_FromLoader(res, false); // Not a ref ! 
}


void init_loader(PyObject* module){
    /* BIN enum */
    PyObject* bin_enum = PyDict_New();
    PyDict_SetItemString(bin_enum, "ELF32", PyLong_FromLong((int)BinType::ELF32));
    PyDict_SetItemString(bin_enum, "ELF64", PyLong_FromLong((int)BinType::ELF64));
    PyDict_SetItemString(bin_enum, "PE32", PyLong_FromLong((int)BinType::PE32));
    PyDict_SetItemString(bin_enum, "PE64", PyLong_FromLong((int)BinType::PE64));
    PyObject* bin_class = create_class(PyUnicode_FromString("BIN"), PyTuple_New(0), bin_enum);
    PyModule_AddObject(module, "BIN", bin_class);
    
};

#endif
