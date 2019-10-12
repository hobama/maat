#include "python_bindings.hpp"
#include "arch.hpp"

void init_arch(PyObject* module){
    /* ARCH enum */
    PyObject* arch_enum = PyDict_New();
    PyDict_SetItemString(arch_enum, "X86", PyLong_FromLong((int)ArchType::X86));
    PyDict_SetItemString(arch_enum, "X64", PyLong_FromLong((int)ArchType::X64));
    PyDict_SetItemString(arch_enum, "ARM32", PyLong_FromLong((int)ArchType::ARM32));
    PyDict_SetItemString(arch_enum, "ARM64", PyLong_FromLong((int)ArchType::ARM64));
    PyObject* arch_class = create_class(PyUnicode_FromString("ARCH"), PyTuple_New(0), arch_enum);
    PyModule_AddObject(module, "ARCH", arch_class);
    
    /* X86 registers enum */
    PyObject* x86_enum = PyDict_New();
    PyDict_SetItemString(x86_enum, "EAX", PyLong_FromLong(X86_EAX));
    PyDict_SetItemString(x86_enum, "EBX", PyLong_FromLong(X86_EBX));
    PyDict_SetItemString(x86_enum, "ECX", PyLong_FromLong(X86_ECX));
    PyDict_SetItemString(x86_enum, "EDX", PyLong_FromLong(X86_EDX));
    PyDict_SetItemString(x86_enum, "EDI", PyLong_FromLong(X86_EDI));
    PyDict_SetItemString(x86_enum, "ESI", PyLong_FromLong(X86_ESI));
    PyDict_SetItemString(x86_enum, "EBP", PyLong_FromLong(X86_EBP));
    PyDict_SetItemString(x86_enum, "ESP", PyLong_FromLong(X86_ESP));
    PyDict_SetItemString(x86_enum, "EIP", PyLong_FromLong(X86_EIP));
    PyDict_SetItemString(x86_enum, "CS", PyLong_FromLong(X86_CS));
    PyDict_SetItemString(x86_enum, "DS", PyLong_FromLong(X86_DS));
    PyDict_SetItemString(x86_enum, "ES", PyLong_FromLong(X86_ES));
    PyDict_SetItemString(x86_enum, "FS", PyLong_FromLong(X86_FS));
    PyDict_SetItemString(x86_enum, "GS", PyLong_FromLong(X86_GS));
    PyDict_SetItemString(x86_enum, "SS", PyLong_FromLong(X86_SS));
    PyDict_SetItemString(x86_enum, "CF", PyLong_FromLong(X86_CF));
    PyDict_SetItemString(x86_enum, "PF", PyLong_FromLong(X86_PF));
    PyDict_SetItemString(x86_enum, "AF", PyLong_FromLong(X86_AF));
    PyDict_SetItemString(x86_enum, "ZF", PyLong_FromLong(X86_ZF));
    PyDict_SetItemString(x86_enum, "SF", PyLong_FromLong(X86_SF));
    PyDict_SetItemString(x86_enum, "TF", PyLong_FromLong(X86_TF));
    PyDict_SetItemString(x86_enum, "IF", PyLong_FromLong(X86_IF));
    PyDict_SetItemString(x86_enum, "DF", PyLong_FromLong(X86_DF));
    PyDict_SetItemString(x86_enum, "OF", PyLong_FromLong(X86_OF));
    PyDict_SetItemString(x86_enum, "IOPL", PyLong_FromLong(X86_IOPL));
    PyDict_SetItemString(x86_enum, "NT", PyLong_FromLong(X86_NT));
    PyDict_SetItemString(x86_enum, "RF", PyLong_FromLong(X86_RF));
    PyDict_SetItemString(x86_enum, "VM", PyLong_FromLong(X86_VM));
    PyDict_SetItemString(x86_enum, "AC", PyLong_FromLong(X86_AC));
    PyDict_SetItemString(x86_enum, "VIF", PyLong_FromLong(X86_VIF));
    PyDict_SetItemString(x86_enum, "VIP", PyLong_FromLong(X86_VIP));
    PyDict_SetItemString(x86_enum, "ID", PyLong_FromLong(X86_ID));
    PyDict_SetItemString(x86_enum, "NB_REGS", PyLong_FromLong(X86_NB_REGS));
    PyObject* x86_class = create_class(PyUnicode_FromString("X86"), PyTuple_New(0), arch_enum);
    PyModule_AddObject(module, "X86", x86_class);
};
