#ifdef HAS_SOLVER_BACKEND

#include "python_bindings.hpp"

/* -------------------------------------
 *           Solver object
 * ------------------------------------ */

static void Solver_dealloc(PyObject* self){
    if( ! as_solver_object(self).is_ref){
        delete ((Solver_Object*)self)->solver;
    }
    as_solver_object(self).solver = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* Solver_reset(PyObject* self){
    as_solver_object(self).solver->reset();
    Py_RETURN_NONE;
};

static PyObject* Solver_add(PyObject* self, PyObject* args){
    PyObject* constr;
    
    if( !PyArg_ParseTuple(args, "O!", get_Constraint_Type(), &constr)){
        return NULL;
    }
    
    as_solver_object(self).solver->add(*(as_constraint_object(constr).constr));
    Py_RETURN_NONE;
};

static PyObject* Solver_check(PyObject* self, PyObject* args){
    PyObject* varctx = nullptr;
    bool res;
    
    if( !PyArg_ParseTuple(args, "|O!", get_VarContext_Type(), &varctx)){
        return NULL;
    }
    if( varctx == nullptr ){
        res = as_solver_object(self).solver->check();
    }else{
        res = as_solver_object(self).solver->check(as_varctx_object(varctx).ctx);
    }
    
    if( res )
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
};

static PyObject* Solver_get_model(PyObject* self){
    VarContext * res;
    res = as_solver_object(self).solver->get_model();
    if( res == nullptr )
        Py_RETURN_NONE;
    return PyVarContext_FromVarContext(res, false);
};

static PyMethodDef Solver_methods[] = {
    {"reset", (PyCFunction)Solver_reset, METH_NOARGS, "Remove all constraints from the solver"},
    {"add", (PyCFunction)Solver_add, METH_VARARGS, "Add a constraint to the solver"},
    {"check", (PyCFunction)Solver_check, METH_VARARGS, "Check if a model exists for the current constraints"},
    {"get_model", (PyCFunction)Solver_get_model, METH_NOARGS, "If a model exists, return the model as a 'VarContext' instance"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef Solver_members[] = {
    {NULL}
};

/* Type description for python Solver objects */
static PyTypeObject Solver_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Solver",                             /* tp_name */
    sizeof(Solver_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Solver_dealloc,           /* tp_dealloc */
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
    "Constraint solver",                          /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Solver_methods,                       /* tp_methods */
    Solver_members,                       /* tp_members */
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

PyObject* get_Solver_Type(){
    return (PyObject*)&Solver_Type;
}

/* Constructors */
PyObject* PySolver_FromSolver(Solver* solver, bool is_ref){
    Solver_Object* object;
    
    // Create object
    PyType_Ready(&Solver_Type);
    object = PyObject_New(Solver_Object, &Solver_Type);
    if( object != nullptr ){
        object->solver = solver;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}

PyObject* maat_Solver(PyObject* module, PyObject* args){
    PyObject* sym = nullptr;
    
    if( ! PyArg_ParseTuple(args, "O!", get_SymbolicEngine_Type(), &sym)){
        return NULL;
    }
    Solver* res = NewSolver(as_sym_object(sym).sym->vars);
    return PySolver_FromSolver(res, false); // Not a ref !
}
#endif
