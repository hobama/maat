#include "python_bindings.hpp"

/* -------------------------------------
 *           MemEngine object
 * ------------------------------------ */

static void MemEngine_dealloc(PyObject* self){
    if( ! as_mem_object(self).is_ref){
        delete ((MemEngine_Object*)self)->mem;
    }
    as_mem_object(self).mem = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* MemEngine_str(PyObject* self){
    std::stringstream res;
    res << *((MemEngine_Object*) self)->mem;
    return PyUnicode_FromString(res.str().c_str());
}

static int MemEngine_print(PyObject* self, void * io, int s){
    std::cout << *((MemEngine_Object*) self)->mem << std::flush;
    return 0;
}

static PyObject* MemEngine_repr(PyObject* self) {
    return MemEngine_str(self);
}

static PyObject* MemEngine_new_segment(PyObject* self, PyObject* args, PyObject* keywords) {
    unsigned long long start, end;
    unsigned short flags = MEM_FLAG_RWX;
    char* name = NULL;
    string name_str;
    
    char* keywds[] = {"", "", "flags", "name", NULL};
    
    if( !PyArg_ParseTupleAndKeywords(args, keywords, "KK|Hs", keywds, &start, &end, &flags, &name)){
        return NULL;
    }
    if( name != NULL){
        name_str = string(name);
    }
    
    try{
        as_mem_object(self).mem->new_segment(start, end, flags, name_str);
    }catch(mem_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    Py_RETURN_NONE;
}

static PyObject* MemEngine_read(PyObject* self, PyObject* args) {
    unsigned long long addr;
    unsigned int nb_bytes;
    Expr res;
    
    if( !PyArg_ParseTuple(args, "KI", &addr, &nb_bytes)){
        return NULL;
    }
    try{
        res = as_mem_object(self).mem->read(addr, nb_bytes);
    }catch(mem_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    return PyExpr_FromExpr(res);
}

static PyObject* MemEngine_write(PyObject* self, PyObject* args) {
    unsigned long long addr;
    Expr e;
    char * data;
    Py_ssize_t data_len;
    PyObject* arg2 = nullptr;
    PyObject* arg3 = nullptr;
    VarContext * ctx;


    if( !PyArg_ParseTuple(args, "KO|O", &addr, &arg2, &arg3)){
        return NULL;
    }
    
    try{
        /* Check arguments types, several possibilities */
        // (addr, expr, varctx)
        if( PyObject_TypeCheck(arg2, (PyTypeObject*)get_Expr_Type()) ){
            if( arg3 == nullptr ) // If no arg3 specified, default argument is nullptr for varctx
                ctx = nullptr;
            else if( PyObject_TypeCheck(arg3, (PyTypeObject*)get_VarContext_Type()) ) // Else check if argument is a varctx
                ctx = as_varctx_object(arg3).ctx;
            else // If wrong throw error
                return PyErr_Format(PyExc_TypeError, "MemEngine.write(): got wrong types for arguments");
            // DO the write
            as_mem_object(self).mem->write(addr, *(as_expr_object(arg2).expr), ctx);
        // (addr, cst, nb_bytes)
        }else if(arg3 != nullptr && PyLong_Check(arg2) && PyLong_Check(arg3)){
            as_mem_object(self).mem->write(addr, PyLong_AsLongLong(arg2), PyLong_AsUnsignedLong(arg3));
        // (addr, buffer, nb_bytes)
        }else if( arg3 != nullptr && PyBytes_Check(arg2) && PyLong_Check(arg3)){
            PyBytes_AsStringAndSize(arg2, &data, &data_len);
            if(PyLong_AsSsize_t(arg3) < data_len){
                data_len = PyLong_AsSsize_t(arg3);
            }
            as_mem_object(self).mem->write(addr, (uint8_t*)data, (unsigned int)data_len);
        }else{
            return PyErr_Format(PyExc_TypeError, "MemEngine.write(): got wrong types for arguments");
        }
    }catch(mem_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    
    Py_RETURN_NONE;
}
 
PyObject* MemEngine_make_symbolic(PyObject* self, PyObject* args){
    unsigned long long addr;
    unsigned int nb_elems, elem_size;
    char * name = "";
    string res_name;
    
    if( ! PyArg_ParseTuple(args, "KIIs", &addr, &nb_elems, &elem_size, &name)){
        return NULL;
    }

    try{
        res_name = as_mem_object(self).mem->make_symbolic(addr, nb_elems, elem_size, string(name));
    }catch(mem_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(var_context_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    return PyUnicode_FromString(res_name.c_str());
}

PyObject* MemEngine_make_tainted(PyObject* self, PyObject* args, PyObject* keywords){
    unsigned long long addr;
    unsigned int nb_elems, elem_size;
    char * name = "";
    string res_name;
    
    char* keywd[] = {"", "", "", "name", NULL};
    
    if( ! PyArg_ParseTupleAndKeywords(args, keywords, "KII|s", keywd, &addr, &nb_elems, &elem_size, &name)){
        return NULL;
    }

    try{
        res_name = as_mem_object(self).mem->make_tainted(addr, nb_elems, elem_size, string(name));
    }catch(mem_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(var_context_exception e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }

    return PyUnicode_FromString(res_name.c_str());
}

static PyMethodDef MemEngine_methods[] = {
    {"new_segment", (PyCFunction)MemEngine_new_segment, METH_VARARGS | METH_KEYWORDS, "Allocate a new segment in memory"},
    {"read", (PyCFunction)MemEngine_read, METH_VARARGS, "Reads memory into an expression"},
    {"write", (PyCFunction)MemEngine_write, METH_VARARGS, "Write a value/expression/buffer into memory"},
    {"make_symbolic", (PyCFunction)MemEngine_make_symbolic, METH_VARARGS, "Make a memory area purely symbolic"},
    {"make_tainted", (PyCFunction)MemEngine_make_tainted, METH_VARARGS | METH_KEYWORDS, "Make a memory area tainted, and optionnaly replace expressions by symbolic variables"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef MemEngine_members[] = {
    {NULL}
};

/* Type description for python MemEngine objects */
static PyTypeObject MemEngine_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "MemEngine",                             /* tp_name */
    sizeof(MemEngine_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)MemEngine_dealloc,           /* tp_dealloc */
    (printfunc)MemEngine_print,              /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    MemEngine_repr,                           /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    MemEngine_str,                            /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Memory engine",                          /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    MemEngine_methods,                       /* tp_methods */
    MemEngine_members,                       /* tp_members */
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
PyObject* PyMemEngine_FromMemEngine(MemEngine* mem, bool is_ref){
    MemEngine_Object* object;
    
    // Create object
    PyType_Ready(&MemEngine_Type);
    object = PyObject_New(MemEngine_Object, &MemEngine_Type);
    if( object != nullptr ){
        object->mem = mem;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

void init_memory(PyObject* module){
    /* MEM enum */
    PyObject* mem_enum = PyDict_New();
    PyDict_SetItemString(mem_enum, "FLAG_R", PyLong_FromLong(MEM_FLAG_R));
    PyDict_SetItemString(mem_enum, "FLAG_W", PyLong_FromLong(MEM_FLAG_W));
    PyDict_SetItemString(mem_enum, "FLAG_X", PyLong_FromLong(MEM_FLAG_X));
    PyDict_SetItemString(mem_enum, "FLAG_RW", PyLong_FromLong(MEM_FLAG_RW));
    PyDict_SetItemString(mem_enum, "FLAG_WX", PyLong_FromLong(MEM_FLAG_WX));
    PyDict_SetItemString(mem_enum, "FLAG_RWX", PyLong_FromLong(MEM_FLAG_RWX));
    PyObject* mem_class = create_class(PyUnicode_FromString("MEM"), PyTuple_New(0), mem_enum);
    PyModule_AddObject(module, "MEM", mem_class);
    
};
