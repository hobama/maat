#include "python_bindings.hpp"
#include <iostream>
#include <sstream>

/* -------------------------------------
 *           IRContext object
 * ------------------------------------ */

static void IRContext_dealloc(PyObject* self){
    if( ! as_irctx_object(self).is_ref){
        delete ((IRContext_Object*)self)->ctx;
    }
    as_irctx_object(self).ctx = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};


static PyObject* IRContext_set(PyObject* self, PyObject* args) {
    int reg;
    PyObject* e;
    
    if( !PyArg_ParseTuple(args, "iO!", &reg, get_Expr_Type(), &e)){
        return NULL;
    }
    try{
        as_irctx_object(self).ctx->set(reg, *(as_expr_object(e).expr));
    }catch(ir_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    Py_RETURN_NONE;
}

static PyObject* IRContext_get(PyObject* self, PyObject* args) {
    unsigned int reg;
    Expr res;
    
    if( !PyArg_ParseTuple(args, "I", &reg)){
        return NULL;
    }
    
    try{
        res = as_irctx_object(self).ctx->get(reg);
    }catch(ir_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    return PyExpr_FromExpr(res);
}


static PyObject* IRContext_as_unsigned(PyObject* self, PyObject* args) {
    unsigned int reg;
    ucst_t res;
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "I|O!", &reg, get_VarContext_Type(), &varctx)){
        return NULL;
    }
    
    try{
        if( varctx != nullptr )
            res = as_irctx_object(self).ctx->concretize(reg, as_varctx_object(varctx).ctx);
        else
            res = as_irctx_object(self).ctx->concretize(reg, nullptr);
    }catch(ir_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    res = cst_sign_trunc( as_irctx_object(self).ctx->get(reg)->size, res);
    return PyLong_FromUnsignedLongLong(res);
}

static PyObject* IRContext_as_signed(PyObject* self, PyObject* args) {
    unsigned int reg;
    cst_t res;
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "I|O!", &reg, get_VarContext_Type(), &varctx)){
        return NULL;
    }
    
    try{
        if( varctx != nullptr )
            res = as_irctx_object(self).ctx->concretize(reg, as_varctx_object(varctx).ctx);
        else
            res = as_irctx_object(self).ctx->concretize(reg, nullptr);
    }catch(ir_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    return PyLong_FromLongLong(res);
}

static PyObject* IRContext_make_symbolic(PyObject* self, PyObject* args) {
    char* name;
    unsigned int reg;
    string res_name;
    
    if( !PyArg_ParseTuple(args, "Is", &reg, &name)){
        return NULL;
    }
    
    try{
        res_name = as_irctx_object(self).ctx->make_symbolic(reg, name);
    }catch(ir_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(var_context_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    
    return PyUnicode_FromString(res_name.c_str());
}

static PyObject* IRContext_make_var(PyObject* self, PyObject* args) {
    char* name;
    unsigned int reg;
    string res_name;
    
    if( !PyArg_ParseTuple(args, "Is", &reg, &name)){
        return NULL;
    }
    
    try{
        res_name = as_irctx_object(self).ctx->make_var(reg, name);
    }catch(ir_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(var_context_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    
    return PyUnicode_FromString(res_name.c_str());
}

static PyObject* IRContext_make_tainted(PyObject* self, PyObject* args) {
    unsigned int reg;
    
    if( !PyArg_ParseTuple(args, "I", &reg)){
        return NULL;
    }
    
    try{
        as_irctx_object(self).ctx->make_tainted(reg);
    }catch(ir_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }catch(var_context_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    
    Py_RETURN_NONE;
}

static PyMethodDef IRContext_methods[] = {
    {"set", (PyCFunction)IRContext_set, METH_VARARGS, "Assign an expression to a register"},
    {"get", (PyCFunction)IRContext_get, METH_VARARGS, "Get the expression of a register"},
    {"as_signed", (PyCFunction)IRContext_as_signed, METH_VARARGS, "Get the concrete value (interpreted as signed) of the expression of a register"},
    {"as_unsigned", (PyCFunction)IRContext_as_unsigned, METH_VARARGS, "Get the concrete value (interpreted as unsigned) of the expression of a register"},
    {"make_symbolic", (PyCFunction)IRContext_make_symbolic, METH_VARARGS, "Make a register purely symbolic"},
    {"make_tainted", (PyCFunction)IRContext_make_tainted, METH_VARARGS, "Taint a register's current expression"},
    {"make_var", (PyCFunction)IRContext_make_var, METH_VARARGS, "Replace a register expression by a variable"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef IRContext_members[] = {
    {NULL}
};

/* Type description for python IRContext objects */
static PyTypeObject IRContext_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "IRContext",                             /* tp_name */
    sizeof(IRContext_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)IRContext_dealloc,           /* tp_dealloc */
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
    "Context for registers",                  /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    IRContext_methods,                       /* tp_methods */
    IRContext_members,                       /* tp_members */
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
PyObject* PyIRContext_FromIRContext(IRContext* ctx, bool is_ref){
    IRContext_Object* object;
    
    // Create object
    PyType_Ready(&IRContext_Type);
    object = PyObject_New(IRContext_Object, &IRContext_Type);
    if( object != nullptr ){
        object->ctx = ctx;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}
