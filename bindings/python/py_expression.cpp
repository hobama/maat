#include "python_bindings.hpp"
#include <iostream>
#include <sstream>


/* -------------------------------------
 *              Expr object
 * ------------------------------------ */

/* Methods */

static void Expr_dealloc(PyObject* self){
    delete ((Expr_Object*)self)->expr;  ((Expr_Object*)self)->expr = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int Expr_print(PyObject* self, void * io, int s){
    std::cout << *((Expr_Object*)self)->expr << std::flush;
    return 0;
}

static PyObject* Expr_str(PyObject* self) {
    std::stringstream res;
    res << *((Expr_Object*) self)->expr;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* Expr_repr(PyObject* self) {
    return Expr_str(self);
}

static PyObject* Expr_is_tainted(PyObject* self){
    return PyBool_FromLong( (*(as_expr_object(self).expr))->is_tainted());
}

static PyObject* Expr_make_tainted(PyObject* self){
    (*(as_expr_object(self).expr))->make_tainted();
    Py_RETURN_NONE;
}

static PyObject* Expr_as_unsigned(PyObject* self, PyObject* args) {
    ucst_t res;
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "|O!", get_VarContext_Type(), &varctx)){
        return NULL;
    }
    
    try{
        if( varctx != nullptr )
            res = (*(as_expr_object(self).expr))->concretize(as_varctx_object(varctx).ctx);
        else
            res = (*(as_expr_object(self).expr))->concretize(nullptr);
    }catch(var_context_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    res = cst_sign_trunc( (*(as_expr_object(self).expr))->size, res);
    return PyLong_FromUnsignedLongLong(res);
}

static PyObject* Expr_as_signed(PyObject* self, PyObject* args) {
    cst_t res;
    PyObject* varctx = nullptr;
    
    if( !PyArg_ParseTuple(args, "|O!", get_VarContext_Type(), &varctx)){
        return NULL;
    }
    
    try{
        if( varctx != nullptr )
            res = (*(as_expr_object(self).expr))->concretize(as_varctx_object(varctx).ctx);
        else
            res = (*(as_expr_object(self).expr))->concretize(nullptr);
    }catch(var_context_exception& e){
        return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
    }
    return PyLong_FromLongLong(res);
}

static PyMethodDef Expr_methods[] = {
    {"is_tainted", (PyCFunction)Expr_is_tainted, METH_NOARGS, "Check whether the expression is tainted"},
    {"make_tainted", (PyCFunction)Expr_make_tainted, METH_NOARGS, "Make the expression tainted"},
    {"as_signed", (PyCFunction)Expr_as_signed, METH_VARARGS, "Concretizes the expression interpreted as a signed value"},
    {"as_unsigned", (PyCFunction)Expr_as_unsigned, METH_VARARGS, "Concretizes the expression interpreted as an unsigned value"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef Expr_members[] = {
    {"size", T_UINT, offsetof(Expr_Object, size), 0, "Expression size in bits"},
    {NULL}
};

/* Compare function */
static PyObject* Expr_richcompare(PyObject* self, PyObject* other, int op){
    Constraint res;
    Expr e1, e2;
    if( ! PyObject_IsInstance(other, get_Expr_Type())){
        return PyErr_Format(PyExc_TypeError, "Comparison operator expected another 'Expr' as second argument");
    }
    e1 = *as_expr_object(self).expr;
    e2 = *as_expr_object(other).expr;
    try{
        switch(op){
            case Py_LT: res = e1 < e2; break;
            case Py_LE: res = e1 <= e2; break;
            case Py_EQ: res = e1 == e2; break;
            case Py_NE: res = e1 != e2; break;
            case Py_GT: res = e1 > e2; break;
            case Py_GE: res = e1 >= e2; break;
            default: return Py_NotImplemented;
        }
        return PyConstraint_FromConstraint(res);
    }catch(constraint_exception e){
        return PyErr_Format(PyExc_ValueError, "%s", e.what());
    }
}

static PyNumberMethods Expr_operators; // Empty PyNumberMethods, will be filled in the init_expression() function

/* Type description for python Expr objects */
PyTypeObject Expr_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Expr",                                   /* tp_name */
    sizeof(Expr_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Expr_dealloc,                 /* tp_dealloc */
    (printfunc)Expr_print,                    /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    Expr_repr,                                /* tp_repr */
    &Expr_operators,                          /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    Expr_str,                                 /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Symbolic expression",                    /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    Expr_richcompare,                         /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Expr_methods,                             /* tp_methods */
    Expr_members,                             /* tp_members */
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

PyObject* get_Expr_Type(){
    return (PyObject*)&Expr_Type;
};

#define CATCH_EXPRESSION_EXCEPTION(x) try{x}catch(expression_exception e){ \
    return PyErr_Format(PyExc_ValueError, "%s", e.what()); \
}

/* Number methods & Various Constructors */
static PyObject* Expr_nb_add(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '+'");
    }
    CATCH_EXPRESSION_EXCEPTION (return PyExpr_FromExpr(*(as_expr_object(self).expr) + *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_sub(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '-'");
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(*(as_expr_object(self).expr) - *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_mul(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '*'");
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(*(as_expr_object(self).expr) * *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_div(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '/'");
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(*(as_expr_object(self).expr) / *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_and(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '&'");
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(*(as_expr_object(self).expr) & *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_or(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '|'");
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(*(as_expr_object(self).expr) | *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_xor(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '^'");
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(*(as_expr_object(self).expr) ^ *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_rem(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '%'");
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(*(as_expr_object(self).expr) % *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_lshift(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '<<'");
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(*(as_expr_object(self).expr) << *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_rshift(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Expr_Type))){
        return PyErr_Format(PyExc_TypeError, "Mismatching types for operator '>>'");
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(*(as_expr_object(self).expr) >> *(as_expr_object(other).expr)); )
}

static PyObject* Expr_nb_neg(PyObject* self){
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(- *(as_expr_object(self).expr)); )
}

static PyObject* Expr_nb_not(PyObject* self){
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr(~ *(as_expr_object(self).expr)); )
}

PyObject* maat_Cst(PyObject* self, PyObject* args, PyObject* keywords){
    Expr_Object* object;
    cst_t val = 0;
    int size = 0;
    int tainted = 0;
    Taint taint = Taint::NOT_TAINTED;
    static char* kwlist[] = {"", "", "tainted", NULL};
    // Parse arguments
    if( ! PyArg_ParseTupleAndKeywords(args, keywords, "il|p", kwlist, &size, &val, &tainted)){
        return NULL;
    }
    if( tainted )
        taint = Taint::TAINTED;
    
    // Create object
    PyType_Ready(&Expr_Type);
    object = PyObject_New(Expr_Object, &Expr_Type);
    PyObject_Init((PyObject*)object, &Expr_Type);
    if( object != nullptr ){
        object->size = size;
        object->expr = new Expr();
        try{
            *object->expr = exprcst(size,val, taint);
        }catch(expression_exception& e){
            return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
        }
    }
    return (PyObject*)object;
}

PyObject* maat_Var(PyObject* self, PyObject* args, PyObject* keywords){
    Expr_Object* object;
    const char * name;
    int name_length;
    int size = 0;
    static char* kwlist[] = {"", "", "tainted", NULL};
    int tainted = 0;
    Taint taint = Taint::NOT_TAINTED;
    
    // Parse arguments
    if( !PyArg_ParseTupleAndKeywords(args, keywords, "is#|p", kwlist, &size, &name, &name_length, &tainted)){
        return NULL;
    }
    
    if( name_length > 255 ){
        return PyErr_Format(PyExc_TypeError, "Var: name cannot be longer than 255 characters");
    }
    
    if( tainted )
        taint = Taint::TAINTED;
    
    // Create object
    PyType_Ready(&Expr_Type);
    object = PyObject_New(Expr_Object, &Expr_Type);
    PyObject_Init((PyObject*)object, &Expr_Type);
    if( object != nullptr ){
        object->size = size;
        object->expr = new Expr();
        try{
            *object->expr = exprvar(size, name, taint);
        }catch(expression_exception& e){
            return PyErr_Format(PyExc_RuntimeError, "%s", e.what());
        }
    }
    return (PyObject*)object;
}

PyObject* maat_Concat(PyObject* self, PyObject* args){
    Expr_Object* upper, *lower;
    if( ! PyArg_ParseTuple(args, "O!O!", (PyObject*)&Expr_Type, &upper, (PyObject*)&Expr_Type, &lower)){
        return NULL;
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr( concat(*(as_expr_object(upper).expr), *(as_expr_object(lower).expr))); )
}

PyObject* maat_Extract(PyObject* self, PyObject* args){
    Expr_Object* expr;
    long lower, higher;
    if( ! PyArg_ParseTuple(args, "O!ll", (PyObject*)&Expr_Type, &expr, &higher, &lower)){
        return NULL;
    }
    CATCH_EXPRESSION_EXCEPTION ( return PyExpr_FromExpr( extract(*(as_expr_object(expr).expr), higher, lower)); )
}

PyObject* PyExpr_FromExpr(Expr e){
    Expr_Object* object;
    
    // Create object
    PyType_Ready(&Expr_Type);
    object = PyObject_New(Expr_Object, &Expr_Type);
    PyObject_Init((PyObject*)object, &Expr_Type);
    if( object != nullptr ){
        object->size = e->size;
        object->expr = new Expr();
        *object->expr = e;
    }
    return (PyObject*)object;
}


/* -------------------------------------
 *          VarContext object
 * ------------------------------------ */

static void VarContext_dealloc(PyObject* self){
    if( ! as_varctx_object(self).is_ref){
        delete ((VarContext_Object*)self)->ctx;
    }
    as_varctx_object(self).ctx = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int VarContext_print(PyObject* self, void * io, int s){
    std::cout << *((VarContext_Object*)self)->ctx << std::flush;
    return 0;
}

static PyObject* VarContext_str(PyObject* self) {
    std::stringstream res;
    res << *((VarContext_Object*) self)->ctx;
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* VarContext_repr(PyObject* self) {
    return VarContext_str(self);
}

static PyObject* VarContext_set(PyObject* self, PyObject* args) {
    const char * name;
    cst_t value;
    
    if( !PyArg_ParseTuple(args, "sl", &name, &value)){
        return NULL;
    }
    
    as_varctx_object(self).ctx->set(string(name), value);
    Py_RETURN_NONE;
}

static PyObject* VarContext_get(PyObject* self, PyObject* args) {
    const char * name;
    
    if( !PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }
    if( !as_varctx_object(self).ctx->contains(string(name))){
        return PyErr_Format(PyExc_KeyError, "Variable %s unknown in this context");
    }
    return PyLong_FromLong(as_varctx_object(self).ctx->get(string(name)));
}

static PyObject* VarContext_get_as_buffer(PyObject* self, PyObject* args) {
    const char * name;
    vector<uint8_t> buffer;
    char str[4096];
    PyObject* res;
    
    if( !PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }
    
    buffer = as_varctx_object(self).ctx->get_as_buffer(string(name));
    if( buffer.size() > sizeof(str) ){
        return PyErr_Format(PyExc_RuntimeError, "Buffer is too big!");
    }else{
        for( int i = 0; i < buffer.size(); i++ ){
            str[i] = (char)buffer[i];
        }
    }
    
    res = PyBytes_FromStringAndSize(str, buffer.size());
    if( res == nullptr ){
        return PyErr_Format(PyExc_RuntimeError, "Internal error: couldn't build bytes from string!");
    }
    
    return res;
}

static PyObject* VarContext_remove(PyObject* self, PyObject* args) {
    const char * name;
    
    if( !PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }
    
    as_varctx_object(self).ctx->remove(string(name));
    Py_RETURN_NONE;
}

static PyObject* VarContext_contains(PyObject* self, PyObject* args) {
    const char * name;
    
    if( !PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }
    
    if( as_varctx_object(self).ctx->contains(string(name)))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static PyObject* VarContext_update_from(PyObject* self, PyObject* args) {
    PyObject* other;
    
    if( !PyArg_ParseTuple(args, "O!", PyObject_Type(self), &other)){
        return NULL;
    }
    as_varctx_object(self).ctx->update_from(*(as_varctx_object(other).ctx));
    Py_RETURN_NONE;
}



static PyMethodDef VarContext_methods[] = {
    {"set", (PyCFunction)VarContext_set, METH_VARARGS, "Give a concrete value to a symbolic variable"},
    {"get", (PyCFunction)VarContext_get, METH_VARARGS, "Give the concrete value associated with a symbolic variable"},
    {"get_as_buffer", (PyCFunction)VarContext_get_as_buffer, METH_VARARGS, "Give the buffer associate with a certain symbolic variable prefix"},
    {"remove", (PyCFunction)VarContext_remove, METH_VARARGS, "Remove the concrete value associated with a symbolic variable"},
    {"contains", (PyCFunction)VarContext_contains, METH_VARARGS, "Check if a given symbolic variable has an associated concrete value"},
    {"update_from", (PyCFunction)VarContext_update_from, METH_VARARGS, "Update concrete values associated with symbolic variables according to another VarContext"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef VarContext_members[] = {
    {NULL}
};

/* Type description for python VarContext objects */
static PyTypeObject VarContext_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "VarContext",                             /* tp_name */
    sizeof(VarContext_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)VarContext_dealloc,           /* tp_dealloc */
    (printfunc)VarContext_print,              /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    VarContext_repr,                          /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    VarContext_str,                           /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Context for symbolic variables",         /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    VarContext_methods,                       /* tp_methods */
    VarContext_members,                       /* tp_members */
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

PyObject* get_VarContext_Type(){
    return (PyObject*)&VarContext_Type;
};

/* Constructors */
PyObject* PyVarContext_FromVarContext(VarContext* ctx, bool is_ref){
    VarContext_Object* object;
    
    // Create object
    PyType_Ready(&VarContext_Type);
    object = PyObject_New(VarContext_Object, &VarContext_Type);
    if( object != nullptr ){
        object->ctx = ctx;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

PyObject* maat_VarContext(PyObject* self, PyObject* args){
    if( !PyArg_ParseTuple(args, "") ){
        return NULL;
    }
    VarContext * ctx = new VarContext(0x1337);
    return PyVarContext_FromVarContext(ctx, false);
}

/* -------------------------------------
 *          Init function
 * ------------------------------------ */
void init_expression(PyObject* module){
    /* Add number operators to Expr */
    Expr_operators.nb_add = Expr_nb_add;
    Expr_operators.nb_subtract = Expr_nb_sub;
    Expr_operators.nb_multiply = Expr_nb_mul;
    Expr_operators.nb_floor_divide = Expr_nb_div;
    Expr_operators.nb_true_divide = Expr_nb_div;
    Expr_operators.nb_and = Expr_nb_and;
    Expr_operators.nb_or = Expr_nb_or;
    Expr_operators.nb_xor = Expr_nb_xor;
    Expr_operators.nb_remainder = Expr_nb_rem;
    Expr_operators.nb_lshift = Expr_nb_lshift;
    Expr_operators.nb_rshift = Expr_nb_rshift;
    Expr_operators.nb_negative = Expr_nb_neg;
    Expr_operators.nb_invert = Expr_nb_not;
}
