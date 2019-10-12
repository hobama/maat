#include "python_bindings.hpp"
#include <iostream>
#include <sstream>


/* -------------------------------------
 *            Constraint object
 * ------------------------------------ */

/* Methods */

static void Constraint_dealloc(PyObject* self){
    delete ((Constraint_Object*)self)->constr;  ((Constraint_Object*)self)->constr = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static int Constraint_print(PyObject* self, void * io, int s){
    std::cout << *(as_constraint_object(self).constr) << std::flush;
    return 0;
}

static PyObject* Constraint_str(PyObject* self) {
    std::stringstream res;
    res << *(as_constraint_object(self).constr);
    return PyUnicode_FromString(res.str().c_str());
}

static PyObject* Constraint_repr(PyObject* self) {
    return Constraint_str(self);
}

static PyObject* Constraint_invert(PyObject* self){
    return PyConstraint_FromConstraint((*(as_constraint_object(self).constr))->invert());
}

static PyMethodDef Constraint_methods[] = {
    {"invert", (PyCFunction)Constraint_invert, METH_NOARGS, "Returns the invert of the condition"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef Constraint_members[] = {
    {NULL}
};

static PyNumberMethods Constraint_operators; // Empty PyNumberMethods, will be filled in the init_constraint() function

/* Type description for python Expr objects */
PyTypeObject Constraint_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "Constraint",                                   /* tp_name */
    sizeof(Constraint_Object),                      /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)Constraint_dealloc,                 /* tp_dealloc */
    (printfunc)Constraint_print,                    /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_reserved */
    Constraint_repr,                                /* tp_repr */
    &Constraint_operators,                          /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash  */
    0,                                        /* tp_call */
    Constraint_str,                                 /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                       /* tp_flags */
    "Constraint on symbolic expressions",     /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    Constraint_methods,                       /* tp_methods */
    Constraint_members,                       /* tp_members */
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

PyObject* get_Constraint_Type(){
    return (PyObject*)&Constraint_Type;
};

PyObject* PyConstraint_FromConstraint(Constraint c){
    Constraint_Object* object;
    
    // Create object
    PyType_Ready(&Constraint_Type);
    object = PyObject_New(Constraint_Object, &Constraint_Type);
    if( object != nullptr ){
        object->constr = new Constraint();
        *object->constr = c;
    }
    return (PyObject*)object;
}

/* Number methods */
static PyObject* Constraint_nb_and(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Constraint_Type))){
        return PyErr_Format(PyExc_TypeError, "Operator '&' expected a Constraint instance as second argument");
    }
    return PyConstraint_FromConstraint(*(as_constraint_object(self).constr) && *(as_constraint_object(other).constr));
}

static PyObject* Constraint_nb_or(PyObject* self, PyObject *other){
    if( ! PyObject_IsInstance(other, (PyObject*)&(Constraint_Type))){
        return PyErr_Format(PyExc_TypeError, "Operator '|' expected a Constraint instance as second argument");
    }
    return PyConstraint_FromConstraint(*(as_constraint_object(self).constr) || *(as_constraint_object(other).constr));
}

/* -------------------------------------
 *          Init function
 * ------------------------------------ */
void init_constraint(PyObject* module){
    /* Add number operators to Constraint */
    Constraint_operators.nb_and = Constraint_nb_and;
    Constraint_operators.nb_or = Constraint_nb_or;
}
