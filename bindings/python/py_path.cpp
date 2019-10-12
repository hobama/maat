#include "python_bindings.hpp"

/* --------------------------------------------------
 *                   PathManager object
 *  -------------------------------------------------- */

static void PathManager_dealloc(PyObject* self){
    if( ! as_path_object(self).is_ref){
        delete ((PathManager_Object*)self)->path;
    }
    as_path_object(self).path = nullptr;
    Py_TYPE(self)->tp_free((PyObject *)self);
};

static PyObject* PathManager_constraints_to_solver(PyObject* self, PyObject* args){
#ifdef HAS_SOLVER_BACKEND
    PyObject* solver;
    if( ! PyArg_ParseTuple(args, "O!", get_Solver_Type(), &solver)){
        return NULL;
    }
    
    as_path_object(self).path->constraints_to_solver(as_solver_object(solver).solver);
#endif
    Py_RETURN_NONE;
};

static PyMethodDef PathManager_methods[] = {
    {"constraints_to_solver", (PyCFunction)PathManager_constraints_to_solver, METH_VARARGS, "Add all constraints corresponding to the current path to a solver"},
    {NULL, NULL, 0, NULL}
};

static PyMemberDef PathManager_members[] = {
    {NULL}
};

/* Type description for python MemEngine objects */
static PyTypeObject PathManager_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "PathManager",                             /* tp_name */
    sizeof(PathManager_Object),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)PathManager_dealloc,           /* tp_dealloc */
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
    "Path Manager",                          /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    PathManager_methods,                       /* tp_methods */
    PathManager_members,                       /* tp_members */
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
PyObject* PyPathManager_FromPathManager(PathManager* path, bool is_ref){
    PathManager_Object* object;
    
    // Create object
    PyType_Ready(&PathManager_Type);
    object = PyObject_New(PathManager_Object, &PathManager_Type);
    if( object != nullptr ){
        object->path = path;
        object->is_ref = is_ref;
    }
    return (PyObject*)object;
}
