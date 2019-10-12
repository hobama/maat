#include "environment.hpp"
#include "exception.hpp"
#include "io.hpp"
#include "linux_x86.hpp"
#include "libc_common.hpp"
#include <sstream>

#ifdef PYTHON_BINDINGS
#include "python_bindings.hpp"
#include "Python.h"
#endif

using std::stringstream;

/* ==========================================
 *            EnvCallbackReturn
 * ========================================= */
EnvCallbackReturn::EnvCallbackReturn(): status(ENV_CALLBACK_FAIL), value(0), expr(nullptr){}
EnvCallbackReturn::EnvCallbackReturn(int s, cst_t v): status(s), value(v), expr(nullptr){}
EnvCallbackReturn::EnvCallbackReturn(int s, Expr e): status(s), value(0), expr(e){}

/* =========================================
 *                EnvFunction 
 * ========================================= */
 
EnvFunction::EnvFunction(env_callback_t c, string n, ABI default_abi, vector<size_t> a, addr_t la, bool il): type(EnvFunctionType::FROM_CALLBACK), callback(c), name(n), 
        abi(default_abi), args(a), irblock(nullptr), load_addr(la), is_loaded(il){
    // Verify arg sizes
    for( auto size : args ){
        if( size != 1 && size != 2 && size != 4 && size != 8 ){
            throw env_exception(ExceptionFormatter() << "EnvFunction: cannot accept argument of size " << size >> ExceptionFormatter::to_str);
        }
    }
#ifdef PYTHON_CALLBACK
    python_callback = nullptr;
#endif
}

EnvFunction::EnvFunction(IRBlock* ir, string n, ABI default_abi, vector<size_t> a, addr_t la, bool il): type(EnvFunctionType::FROM_IR), callback(nullptr), name(n), 
        abi(default_abi), args(a), irblock(ir), load_addr(la), is_loaded(il){
    // Verify arg sizes
    for( auto size : args ){
        if( size != 1 && size != 2 && size != 4 && size != 8 ){
            throw env_exception(ExceptionFormatter() << "EnvFunction: cannot accept argument of size " << size >> ExceptionFormatter::to_str);
        }
    }
#ifdef PYTHON_CALLBACK
    python_callback = nullptr;
#endif
}

#ifdef PYTHON_BINDINGS
EnvFunction::EnvFunction(PyObject* c, string n, ABI default_abi, vector<size_t> a, addr_t la, bool il): type(EnvFunctionType::FROM_PYTHON_CALLBACK), 
        callback(nullptr), name(n), abi(default_abi), args(a), irblock(nullptr), load_addr(la), is_loaded(il), python_callback(c){
    // Verify arg sizes
    for( auto size : args ){
        if( size != 1 && size != 2 && size != 4 && size != 8 ){
            throw env_exception(ExceptionFormatter() << "EnvFunction: cannot accept argument of size " << size >> ExceptionFormatter::to_str);
        }
    }
    Py_INCREF(python_callback);
}
#endif

EnvFunction::~EnvFunction(){
    if( !is_loaded ){
        delete irblock; irblock = nullptr;
    }
    // If loaded then ownership of the IRBlock has been transfered to the ir manager,
    // so we don't delete it! :)
#ifdef PYTHON_BINDINGS
    if( python_callback != nullptr && type == EnvFunctionType::FROM_PYTHON_CALLBACK){
        Py_DECREF(python_callback);
        python_callback = nullptr;
    }
#endif
}


int EnvFunction::call(SymbolicEngine& sym){
    if( type == EnvFunctionType::FROM_CALLBACK ){
        return call_native_callback(sym);
    }else if( type == EnvFunctionType::FROM_PYTHON_CALLBACK ){
        return call_python_callback(sym);
    }else{
        throw runtime_exception("EnvFunction::call(): got unsupported EnvFunctionType!");
    }
}

int EnvFunction::call_native_callback(SymbolicEngine& sym){
    if( type == EnvFunctionType::FROM_CALLBACK ){
        vector<Expr> cb_args = _abi_get_args(abi, args, sym);
        EnvCallbackReturn res = callback(sym, cb_args);
        if( res.status == ENV_CALLBACK_FAIL ){
            return res.status;
        }else{
            if( res.status == ENV_CALLBACK_SUCCESS_WITH_VALUE ){
                _abi_set_return_value(abi, res, sym);
            }
            _abi_return(abi, args, sym);
            return res.status;
        }
    }else{
        throw runtime_exception("EnvFunction::call_native_callback() not supported for this type of env function");
    }
}

int EnvFunction::call_python_callback(SymbolicEngine& sym){
    int res_status = ENV_CALLBACK_FAIL;
#ifdef PYTHON_BINDINGS
    if( type == EnvFunctionType::FROM_PYTHON_CALLBACK ){
        // Get arguments
        vector<Expr> cb_args = _abi_get_args(abi, args, sym);
        // Get symbolic engine wrapper
        PyObject* py_sym = sym.self_python_wrapper_object;
        // BUild args tuple to call python callback
        PyObject* argslist = PyList_New(0);
        
        if( argslist == NULL ){
            throw runtime_exception("EnvFunction::call_python_callback() failed to create new python list");
        }

        for (Expr arg : cb_args){
            if( PyList_Append(argslist, PyExpr_FromExpr(arg)) == -1){
                throw runtime_exception("EnvFunction::call_python_callback() failed to add argument to callback args");
            }
        }
        PyObject* args_tuple = Py_BuildValue("(OO)", py_sym, argslist);
        if( args_tuple == NULL ){
            throw runtime_exception("EnvFunction::call_python_callback() failed to build args tuple");
        }
        
        // Get the python callback name
        PyObject* repr = PyObject_GetAttrString(python_callback, "__name__");
        PyObject* str = PyUnicode_AsEncodedString(repr, "utf-8", "~E~");
        string callback_name = string(PyBytes_AS_STRING(str));
        Py_XDECREF(str);
        Py_XDECREF(repr);
        
        // Call the python callback
        Py_INCREF(args_tuple);
        PyObject* res = PyObject_CallObject(python_callback, args_tuple);
        Py_DECREF(args_tuple);
        
        // Test if CallObject failed
        if( res == NULL ){
            PyErr_Print();
            throw runtime_exception(ExceptionFormatter() << "Python Callback " << callback_name << "() failed and returned a NULL object" >> ExceptionFormatter::to_str);
        }
        
        if( ! PyObject_TypeCheck(res, (PyTypeObject*)get_EnvCallbackReturn_Type())){
            throw runtime_exception(ExceptionFormatter() << "Python Callback " << callback_name << "() returned wrong object ! Expected an 'EnvCallbackReturn' instance " >> ExceptionFormatter::to_str);
        }
        
        if( ((EnvCallbackReturn_Object*)res)->ret->status == ENV_CALLBACK_FAIL ){
            res_status = ((EnvCallbackReturn_Object*)res)->ret->status;
        }else{
            if( ((EnvCallbackReturn_Object*)res)->ret->status == ENV_CALLBACK_SUCCESS_WITH_VALUE ){
                _abi_set_return_value(abi, *(((EnvCallbackReturn_Object*)res)->ret), sym);
            }
            _abi_return(abi, args, sym);
            res_status =  ((EnvCallbackReturn_Object*)res)->ret->status;
        }
        Py_XDECREF(res); // We don't keep the result
        
    }else{
        throw runtime_exception("EnvFunction::call_python_callback() not supported for this type of env function");
    }
#endif
    return res_status;
}

/* ======================================
 *          Simulated Memory Allocator
 * ====================================== */
EnvMemAllocator::EnvMemAllocator(): min_addr(0), max_addr(0){}

EnvMemAllocator::EnvMemAllocator(addr_t min, addr_t max): min_addr(min), max_addr(max){
    add_free_slot(min_addr, max_addr-min_addr+1);
}

addr_t EnvMemAllocator::alloc(unsigned int size){
    MemSlot slot;
    for( int i = 0; i < free_slots.size(); i++ ){
        slot = free_slots[i];
        if( slot.size >= size ){
            add_allocated_slot(slot.start, size);
            // Remove the free block if needed
            if( slot.size == size )
                free_slots.erase(free_slots.begin()+i);
            return slot.start;
        }
    }
    throw env_exception("Failed to allocate new block");
}

unsigned int EnvMemAllocator::free(addr_t addr){
    unsigned int size;
    unordered_map<addr_t, unsigned int>::iterator it;
    if( (it = allocated_slots.find(addr)) == allocated_slots.end()){
        throw env_exception(ExceptionFormatter() << "Trying to free block that is not allocated at: " << std::hex << addr >> ExceptionFormatter::to_str);
    }
    size = it->second;
    add_free_slot(it->first, it->second);
    allocated_slots.erase(it);
    return size;
}

void EnvMemAllocator::add_allocated_slot(addr_t addr, unsigned int size){
    allocated_slots[addr] = size;
}

void EnvMemAllocator::add_free_slot(addr_t addr, unsigned int size){
    MemSlot slot;
    for( int i = 0; i < free_slots.size(); i++ ){
        slot = free_slots[i];
        // Just after a free slot, extend it
        if( slot.start + slot.size == addr){
            slot.size += size;
            return;
        // Just before a free slot, extend it
        }else if( addr + size == slot.start ){
            slot.start -= size;
            return;
        // Before a slot, insert before it
        }else if( addr + size < slot.start ){
            free_slots.insert(free_slots.begin()+i, MemSlot{addr, size});
            return;
        }
    }
    // Insert as last free slot
    free_slots.insert(free_slots.end(), MemSlot{addr, size});
    return;
}

/* ======================================
 *        Simulated File System
 * ====================================== */
EnvFile::EnvFile(string n):name(n), pos(0){}
int EnvFile::write_from_buffer(SymbolicEngine& sym, addr_t buf, size_t count){
    int i;
    for( i = 0; i < count; i ++ ){
        data.push_back(sym.mem->read(buf+i, 1));
    }
    pos += i;
    return i;
}

int EnvFile::read_to_buffer(SymbolicEngine& sym, addr_t buf, size_t count){
    int i;
    for( i = 0; i < count; i ++ ){
        sym.mem->write(buf+i, data[pos+i], sym.vars);
    }
    pos += i;
    return i;
}

EnvFileSystem::EnvFileSystem(){}

EnvFileSystem::~EnvFileSystem(){
    for( EnvFile* file : files )
        delete file;
}

EnvFile* EnvFileSystem::file_by_name(string name){
    for( EnvFile* file : files ){
        if( file->name == name )
            return file;
    }
    return nullptr;
}

EnvFile* EnvFileSystem::file_by_num(unsigned int num){
    if( num >= files.size() )
        throw env_exception("EnvFileSystem::file_by_num() got invalid num");
    return files[num];
}

int EnvFileSystem::file_num_by_name(string name){
    int i = 0;
    for( i = 0; i < files.size(); i++ ){
        if( files[i]->name == name )
            return i;
    }
    return -1;
}

EnvFile* EnvFileSystem::create_file(string name){
    int i = 0;
    EnvFile* new_file = new EnvFile(name);
    for( i = 0; i < files.size(); i++ ){
        if( files[i] == nullptr ){
            files[i] = new_file;
            return new_file;
        }
    }
    files.push_back(new_file);
    return new_file;
}

EnvFile* EnvFileSystem::create_file_num(string name, unsigned int num){
    EnvFile* new_file = new EnvFile(name);
    if( num >= files.size() ){
        for( int i = 0; i < files.size()-num; i++){
            files.push_back(nullptr);
        }
        files.push_back(new_file);
    }else{
        if( files[num] != nullptr ){
            throw env_exception("EnvFileSystem::create_file_num(): this num is already taken by a file!");
        }
        files[num] = new_file;
    }
    return new_file;
}

void EnvFileSystem::remove_file(string name){
    for( int i = 0; i < files.size(); i++ ){
        if( files[i]->name == name ){
            delete files[i]; files[i] = nullptr;
            return;
        }
    }
}


/* =========================================
 *                EnvManager 
 * ========================================= */

extern vector<EnvFunction*> default_linux_x86_simulated_functions();
extern env_callback_t _simu_linux_x86_not_implemented(SymbolicEngine& sym, vector<Expr> args);
extern unsigned short int linux_x86_ctype_b_loc_table[];
extern unordered_map<int, string> default_linux_x86_signal_handlers;

EnvManager::EnvManager(): type(SysType::NONE), env_array(-1), kernel_stack(-1), ctype_b_loc_table_ptr(-1){}

uint8_t myglobal[4] = {1, 2, 3, 4};
EnvManager::EnvManager(ArchType arch, SysType sys):env_array(-1), kernel_stack(-1), ctype_b_loc_table_ptr(-1){
    type = sys;
    if( sys == SysType::LINUX ){
        if( arch == ArchType::X86 ){
            // Linux X86 default environment
            functions = default_linux_x86_simulated_functions();
            ctype_b_loc_table = linux_x86_ctype_b_loc_table;
            not_implemented_callback = (env_callback_t)_simu_libc_common_not_implemented;
            default_signal_handlers = default_linux_x86_signal_handlers;
        }
    }
}

EnvManager::~EnvManager(){
    for( EnvFunction* func : functions ){
        delete func;
    }
}

void EnvManager::init_mem_allocator(addr_t start, addr_t end){
    mem_allocator = EnvMemAllocator(start, end);
}

addr_t EnvManager::alloc(unsigned int size){
    addr_t addr = mem_allocator.alloc(size);
    snapshot_manager.record_alloc(addr);
    return addr;
}

unsigned int EnvManager::free(addr_t addr){
    unsigned int size = mem_allocator.free(addr);
    snapshot_manager.record_free(addr, size);
    return size;
}

void EnvManager::add_function(EnvFunction* func){
    // Replace function if already present in vector 
    for( vector<EnvFunction*>::iterator func_it = functions.begin(); func_it != functions.end(); func_it++ ){
        if( func->name == (*(func_it))->name){
            // Keep load information if any
            func->is_loaded = (*func_it)->is_loaded;
            func->load_addr = (*func_it)->load_addr;
            // Replace previous function
            delete *func_it; // Delete previous function
            *func_it = func;
            return;
        }
    }
    // If the name doesn't exist yet, create new function :) 
    functions.push_back(func);
}

env_snapshot_id_t EnvManager::take_snapshot(){
    return snapshot_manager.take_snapshot(*this);
}

void EnvManager::restore_snapshot(env_snapshot_id_t id){
    snapshot_manager.restore(id, *this);
}

bool EnvManager::simulates_function(string func_name){
    for( EnvFunction* func : functions ){
        if( func->name == func_name){
            return true;
        }
    }
    return false;
}

EnvFunction& EnvManager::new_not_implemented_function(string name, ABI abi){
    add_function(new EnvFunction(not_implemented_callback, name, abi, vector<size_t>{}));
    return get_function(name);
}

void EnvManager::loaded_function(string func_name, addr_t addr){
    for( EnvFunction* func : functions ){
        if( func->name == func_name){
            if( func->is_loaded ){
                throw env_exception(ExceptionFormatter() << "EnvManager::loaded_function(), function " << func_name << " is already loaded" >> ExceptionFormatter::to_str);
            }
            func->load_addr = addr;
            func->is_loaded = true;
            return;
        }
    }
    throw env_exception(ExceptionFormatter() << "EnvManager::loaded_function(), function " << func_name << " is unknown" >> ExceptionFormatter::to_str);
}

EnvFunction& EnvManager::get_function(string func_name){
    for( EnvFunction* func : functions ){
        if( func->name == func_name)
            return *func;
    }
    throw env_exception(ExceptionFormatter() << "EnvManager:get_function(): unknown function " << func_name >> ExceptionFormatter::to_str);
}

EnvFunction& EnvManager::get_function(addr_t addr){
    for( EnvFunction* func : functions ){
        if( func->load_addr == addr )
            return *func;
    }
    throw env_exception(ExceptionFormatter() << "EnvManager:get_function(): unknown function at addr " << std::hex << addr >> ExceptionFormatter::to_str);
}

int EnvManager::check_and_simulate(addr_t addr, SymbolicEngine& sym){
    for( EnvFunction* func : functions ){
        if( (func->type == EnvFunctionType::FROM_CALLBACK || func->type == EnvFunctionType::FROM_PYTHON_CALLBACK) && 
            func->is_loaded && func->load_addr == addr){
            if( sym.breakpoint.check_addr(sym, addr)){
                return ENV_BREAKPOINT;
            }
            if( sym.is_enabled(SymbolicEngineOption::PRINT_INSTRUCTIONS)){
                stringstream ss;
                ss << "Simulating function: " << func->name << " (0x" << std::hex << addr << ")";
                sym._print_info(ss.str());
            }
            return func->call(sym);
        }
    }
    return ENV_NO_CALLBACK;
}

void EnvManager::add_data(EnvData* d){
    data.push_back(d);
}

void EnvManager::loaded_data(string data_name, addr_t addr){
    for( EnvData* d : data ){
        if( d->name == data_name ){
           if( d->is_loaded ){
                throw env_exception(ExceptionFormatter() << "EnvManager::loaded_data(), data " << data_name << " is already loaded" >> ExceptionFormatter::to_str);
            }
            d->load_addr = addr;
            d->is_loaded = true;
            return;
        }
    }
    throw env_exception(ExceptionFormatter() << "EnvManager::loaded_data(), data " << data_name << " is unknown" >> ExceptionFormatter::to_str);
}

bool EnvManager::simulates_data(string data_name){
    for( EnvData* d : data ){
        if( d->name == data_name ){
           return true;
        }
    }
    return false;
}
EnvData& EnvManager::get_data(string data_name){
    for( EnvData* d : data ){
        if( d->name == data_name ){
           return *d;
        }
    }
    throw env_exception(ExceptionFormatter() << "EnvManager:get_data(): unknown data " << data_name >> ExceptionFormatter::to_str);
}

void EnvManager::prepare_syscall(cst_t syscall_type, addr_t ret, SymbolicEngine& sym){
    vector<Expr> args;
    /* Get syscall abi */
    ABI syscall_abi;
    if( sym.arch->mode == CPUMode::X86 && sym.env->type == SysType::LINUX && syscall_type == SYSCALL_X86_INT80 ){
        syscall_abi = ABI::X86_LINUX_INT80;
    }else if( sym.arch->mode == CPUMode::X86 && sym.env->type == SysType::LINUX && syscall_type == SYSCALL_X86_SYSENTER){
        syscall_abi = ABI::X86_LINUX_SYSENTER;
    }else{
        throw runtime_exception("Got unsupported syscall ABI");
    }
    /* Get syscall number */
    ucst_t syscall_num = _abi_get_syscall_num(sym.arch->mode, this->type, sym);
    /* Get associated function name */
    string func_name = _get_syscall_func_name(syscall_num, sym.arch->mode, this->type);
    if( func_name  == "" ){
        if( sym.is_enabled(SymbolicEngineOption::IGNORE_MISSING_SYSCALLS)){
            if( sym.is_enabled(SymbolicEngineOption::PRINT_WARNINGS )){
                stringstream ss;
                ss << "Ignoring unsupported syscall: 0x" << std::hex << syscall_num;
                print_warning(ss.str());
            }
            // Just set PC to the return address and continue
            sym.regs->set(sym.arch->pc(), exprcst(sym.arch->bits, ret));
            return;
        }else{
            throw runtime_exception(ExceptionFormatter() << "Unsupported syscall number: 0x" << std::hex
                            << syscall_num >> ExceptionFormatter::to_str);
        }
    }
    EnvFunction& func = get_function(func_name);
    if( ! func.is_loaded ){
        throw runtime_exception("Calling syscall that redirects to function that is not loaded!");
    }
    /* Get args */
    args = _abi_get_args(syscall_abi, func.args, sym);
    /* Translate them to the syscall function's abi */
    _abi_set_args(func.abi, args, sym);
    /* Push return address */
    _abi_set_return_address(func.abi, ret, sym);
    /* Set EIP to the function's address */
    sym.regs->set(sym.arch->pc(), exprcst(sym.arch->bits, func.load_addr));
    return;
}

string _get_syscall_func_name(ucst_t num, CPUMode mode, SysType sys){
    if( mode == CPUMode::X86 ){
        if( sys == SysType::LINUX ){
            switch(num){
                case 1: return "exit";
                case 3: return "sys_read";
                case 4: return "sys_write";
                case 0xd: return "sys_time";
                case 0x14: return "sys_getpid";
                case 0x1a: return "sys_ptrace";
                case 0x2d: return "sys_brk";
                case 0x30: return "sys_signal";
                case 0x7a: return "sys_newuname";
                default: return "";
            }
        }else{
            throw runtime_exception("_get_syscall_func_name(): not implemented for this system");
        }
    }else{
        throw runtime_exception("_get_syscall_func_name(): not implemented for this architecture");
    }
}

void EnvManager::do_interrupt(cst_t num, addr_t ret, SymbolicEngine& sym){
    if( sym.arch->mode == CPUMode::X86 && this->type == SysType::LINUX ){
        switch(num){
            case 0x3:   sym.regs->set(X86_EIP, exprcst(32, ret)); // Set eip to next value after sigtrap
                        handle_signal(X86_LINUX_SIGTRAP, sym); // Int3 sigtrap !
                        return;
            case 0x80: prepare_syscall(SYSCALL_X86_INT80, ret, sym); return; // Do syscall
            default: throw runtime_exception(ExceptionFormatter() << "Interruption  0x" << std::hex << num << 
                        "not supported by environment" >> ExceptionFormatter::to_str);
        }
    }else{
        throw runtime_exception("do_interrupt(): not implemented for this architecture/system");
    }
}

void EnvManager::handle_signal(int signum, SymbolicEngine& sym){
    auto it = current_signal_handlers.find(signum);
    if( it == current_signal_handlers.end() ){
        throw runtime_exception(ExceptionFormatter() << "No handler defined for signal: " << std::dec << signum >> ExceptionFormatter::to_str);
    }
    // Get the current ABI
    ABI abi = _get_default_abi(sym.arch->mode, sym.env->type);
    vector<Expr> args{exprcst(sym.arch->bits, signum)};
    // Call the handler with the signal number :)
    _abi_set_args(abi, args, sym);
    _abi_set_return_address(abi, cst_sign_trunc(sym.regs->get(sym.arch->pc())->size, sym.regs->concretize(sym.arch->pc())), sym);
    sym.regs->set(sym.arch->pc(), exprcst(sym.arch->bits, it->second)); 
}


vector<string> EnvManager::all_function_names(){
    vector<string> res;
    for( EnvFunction* func : functions ){
        res.push_back(func->name);
    }
    return res;
}

/* =========================================
 *           Snapshoting for env
 * ========================================= */
 
EnvSnapshot::EnvSnapshot(unordered_map<int, addr_t> sig):signal_handlers(sig){};

snapshot_id_t EnvSnapshotManager::take_snapshot(EnvManager& env){
    if( _snapshots.size() == MAX_SNAPSHOTS )
        throw runtime_exception("Fatal error: maximum number of snapshots reached");
    _snapshots.push_back(EnvSnapshot(env.current_signal_handlers));
    return _snapshots.size()-1;
}

void EnvSnapshotManager::record_alloc(addr_t addr){
    if( !is_active() )
        return;
    _snapshots.back().mem_allocs.push_back(mem_alloc_event_t{ENV_MEM_ALLOC, addr, 0});
}

void EnvSnapshotManager::record_free(addr_t addr, size_t size){
    if( !is_active() )
        return;
    _snapshots.back().mem_allocs.push_back(mem_alloc_event_t{ENV_MEM_FREE, addr, size});
}

bool EnvSnapshotManager::rewind(EnvManager& env, bool remove){
    vector<mem_alloc_event_t>::reverse_iterator it;
    if( _snapshots.empty() ){
        return false;
    }
    // Restore memory allocations
    for( it = _snapshots.back().mem_allocs.rbegin(); it != _snapshots.back().mem_allocs.rend(); it++ ){
        if( it->type == ENV_MEM_ALLOC ){
            // If it was allocated then free it
            env.mem_allocator.free(it->addr);
        }else{
            // If it was a free then reallocate the chunk with same size
            env.mem_allocator.add_allocated_slot(it->addr, it->size);
        }
    }
    _snapshots.back().mem_allocs.clear();
    // Restore signal handlers
    env.current_signal_handlers = _snapshots.back().signal_handlers;
    if( remove ){
        // Remove last snapshot
        _snapshots.pop_back();
    }
    return true;
}

bool EnvSnapshotManager::restore(snapshot_id_t id, EnvManager& env, bool remove){
    if( id >= _snapshots.size() ){
        throw runtime_exception("EnvSnapshotManager::restore() got invalid snapshot id");
    }
    while( _snapshots.size() > id +1 ){
        rewind(env, true);
    }
    rewind(env, remove);
    return true;
}

bool EnvSnapshotManager::is_active(){
    return _snapshots.size() > 0;
}


/* =========================================
 *          ABIs & Arguments parsing 
 * ========================================= */

bool _abi_is_syscall(ABI abi){
    return  abi == ABI::X86_LINUX_INT80 || 
            abi == ABI::X86_LINUX_SYSENTER;
}

ABI _get_default_abi(CPUMode mode, SysType sys){
    if( mode == CPUMode::X86 && sys == SysType::LINUX ){
        return ABI::X86_CDECL;
    }else{
        throw runtime_exception("_get_default_abi(): Unsupported arch/sys");
    }
}

/* ============= X86 CDECL ============ */
vector<Expr> _x86_cdecl_get_args(vector<size_t>& args, SymbolicEngine& sym){
    vector<Expr> res;
    /* Arguments are on the stack, pushed right to left */
    addr_t stack = (uint32_t)(sym.regs->concretize(X86_ESP)) + 4;
    for( size_t arg_size : args ){
        res.push_back(sym.mem->read(stack, arg_size));
        stack += arg_size;
    }
    return res;
}

void _x86_cdecl_set_args(vector<Expr>& args, SymbolicEngine& sym){
    vector<Expr> res;
    /* Arguments are on the stack, pushed right to left */
    addr_t stack = (uint32_t)(sym.regs->concretize(X86_ESP));
    for( vector<Expr>::reverse_iterator it = args.rbegin(); it != args.rend(); it++ ){
        stack -= (*it)->size/8;
        sym.mem->write(stack, *it);
    }
    sym.regs->set(X86_ESP, exprcst(32, stack));
}

void _x86_cdecl_set_return_address(addr_t ret, SymbolicEngine& sym){
    vector<Expr> res;
    // Push the return address, simply
    sym.regs->set(X86_ESP, sym.regs->get(X86_ESP) - 4 );
    sym.mem->write((uint32_t)sym.regs->concretize(X86_ESP), ret, (unsigned int)4);
}

void _x86_cdecl_set_return_value(EnvCallbackReturn& ret, SymbolicEngine& sym){
    // Return value in EAX
    if( ret.expr == nullptr )
        sym.regs->set(X86_EAX, exprcst(32, ret.value));
    else{
        if( ret.expr->size != 32 ){
            throw runtime_exception("x86_cdecl_set_return_value(): fatal error, callback returned an expression with size != 32 ");
        }
        sym.regs->set(X86_EAX, ret.expr);
    }
}

void _x86_cdecl_return(vector<size_t>& args, SymbolicEngine& sym){
    /* Caller clean-up, we just simulate a 'ret' instruction */
    sym.regs->set(X86_EIP, sym.mem->read((uint32_t)(sym.regs->concretize(X86_ESP)), 4));
    sym.regs->set(X86_ESP, sym.regs->get(X86_ESP) + 4);
    return;
}

vector<IROperand> _ir_x86_cdecl_get_args(vector<size_t>& args, IRBlock& irblock){
    unsigned int tmp_vars_count = 0;
    IRBasicBlockId bblkid = irblock.new_bblock();
    IROperand stack = ir_tmp(tmp_vars_count++, 31, 0), arg;
    vector<IROperand> res;
    if( bblkid != 0 ){
        throw runtime_exception("_ir_x86_cdecl_get_args(): got new basic block with id != 0, error");
    }
    irblock.add_instr(bblkid, ir_add(stack, ir_var(X86_ESP, 31, 0), ir_cst(4, 31, 0), 0x0));
    for( size_t arg_size : args ){
        arg = ir_tmp(tmp_vars_count++, (arg_size*8)-1, 0);
        res.push_back(arg);
        irblock.add_instr(bblkid, ir_ldm(arg, stack, 0x0));
        irblock.add_instr(bblkid, ir_add(stack, stack, ir_cst(arg_size, 31, 0), 0x0));
    }
    irblock.add_instr(bblkid, ir_bcc(ir_cst(1,31,0), ir_cst(bblkid+1, 31, 0), ir_none(), 0x0)); // Jump to next bblock
    irblock._nb_tmp_vars = tmp_vars_count;
    return res;
}

void _ir_x86_cdecl_return(IRBlock& irblock){
    /* Caller clean-up, we just simulate a 'ret' instruction */
    IRBasicBlockId bblkid = irblock.nb_bblocks()-1;
    irblock.add_instr(bblkid, ir_ldm(ir_var(X86_EIP, 31, 0), ir_var(X86_ESP, 31, 0), 0x0));
    irblock.add_instr(bblkid, ir_add(ir_var(X86_ESP, 31, 0), ir_var(X86_ESP, 31, 0), ir_cst(4, 31, 0), 0x0));
    irblock.add_instr(bblkid, ir_jcc(ir_cst(1, 31, 0), ir_var(X86_EIP, 31, 0), ir_none(), 0x0));
    return;
}

/* ============= X86 STDCALL ============ */
vector<Expr> _x86_stdcall_get_args(vector<size_t>& args, SymbolicEngine& sym){
    vector<Expr> res;
    /* Arguments are on the stack, pushed right to left */
    addr_t stack = (uint32_t)(sym.regs->concretize(X86_ESP)) + 4;
    for( size_t arg_size : args ){
        res.push_back(sym.mem->read(stack, arg_size));
        stack += arg_size;
    }
    return res;
}

void _x86_stdcall_set_args(vector<Expr>& args, SymbolicEngine& sym){
    vector<Expr> res;
    /* Arguments are on the stack, pushed right to left */
    addr_t stack = (uint32_t)(sym.regs->concretize(X86_ESP));
    for( vector<Expr>::reverse_iterator it = args.rbegin(); it != args.rend(); it++ ){
        stack -= (*it)->size/8;
        sym.mem->write(stack, *it);
    }
    sym.regs->set(X86_ESP, exprcst(32, stack));
}

void _x86_stdcall_set_return_address(addr_t ret, SymbolicEngine& sym){
    vector<Expr> res;
    // Push the return address, simply
    sym.regs->set(X86_ESP, sym.regs->get(X86_ESP) - 4 );
    sym.mem->write((uint32_t)sym.regs->concretize(X86_ESP), ret, (unsigned int)4);
}

void _x86_stdcall_return(vector<size_t>& args, SymbolicEngine& sym){
    /* Callee clean-up, we readjust stack pointer then jump to return address */
    sym.regs->set(X86_EIP, sym.mem->read((uint32_t)(sym.regs->concretize(X86_ESP)), 4));
    size_t total_args_size = 0;
    for( size_t size : args ){
        total_args_size += size;
    }
    sym.regs->set(X86_ESP, sym.regs->get(X86_ESP) + 4 + total_args_size);
    return;
}

/* ============= X86 LINUX INT80 ============ */
vector<Expr> _x86_linux_int80_get_args(vector<size_t>& args, SymbolicEngine& sym){
    vector<Expr> res;
    reg_t args_regs[6] = {X86_EBX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBP}; 
    /* Arguments are in ebx, ecx, edx, esi, edi, ebp */
    if( args.size() > 6 ){
        throw env_exception("X86 Linux INT80 ABI doesn't support more than 6 arguments");
    }
    for( int i = 0; i < args.size(); i++ ){
        res.push_back(extract(sym.regs->get(args_regs[i]), (args[i]*8)-1, 0));
    }
    return res;
}

/* ============= X86 LINUX SYSENTER ============ */
vector<Expr> _x86_linux_sysenter_get_args(vector<size_t>& args, SymbolicEngine& sym){
    vector<Expr> res;
    reg_t args_regs[5] = {X86_EBX, X86_ECX, X86_EDX, X86_ESI, X86_EDI}; 
    /* Arguments are in ebx, ecx, edx, esi, edi, [ebp] */
    if( args.size() > 6 ){
        throw env_exception("X86 Linux SYSENTER ABI doesn't support more than 6 arguments");
    }
    // Read reg args
    for( int i = 0; i < args.size(); i++ ){
        res.push_back(extract(sym.regs->get(args_regs[i]), (args[i]*8)-1, 0));
    }
    // Get last arg if any
    if( args.size() == 6 ){
        res.push_back(sym.mem->read((uint32_t)sym.regs->concretize(X86_EBP), args[5]));
    }
    return res;
}

/* ============= X86 LINUX CUSTOM SYSCALL ============ */
vector<Expr> _x86_linux_custom_syscall_get_args(vector<size_t>& args, SymbolicEngine& sym){
    return _x86_cdecl_get_args(args, sym);
}

void _x86_linux_custom_syscall_set_args(vector<Expr>& args, SymbolicEngine& sym){
    vector<Expr> res;
    Expr saved_sp = sym.regs->get(X86_ESP);
    /* First switch stack and push saved stack pointer */
    sym.regs->set(X86_ESP, exprcst(32, sym.env->kernel_stack-4));
    sym.mem->write((uint32_t)sym.regs->concretize(X86_ESP), saved_sp, sym.vars); 
    
    /* Then, as cdecl, arguments are on the stack, pushed right to left */
    addr_t stack = (uint32_t)(sym.regs->concretize(X86_ESP));
    for( vector<Expr>::reverse_iterator it = args.rbegin(); it != args.rend(); it++ ){
        stack -= (*it)->size/8;
        sym.mem->write(stack, *it);
    }
    sym.regs->set(X86_ESP, exprcst(32, stack));
}

void _x86_linux_custom_syscall_set_return_address(addr_t ret, SymbolicEngine& sym){
    vector<Expr> res;
    // Push the return address, simply
    sym.regs->set(X86_ESP, sym.regs->get(X86_ESP) - 4 );
    sym.mem->write((uint32_t)sym.regs->concretize(X86_ESP), ret, (unsigned int)4);
}

void _x86_linux_custom_syscall_set_return_value(EnvCallbackReturn& ret, SymbolicEngine& sym){
    // Return value in EAX
    if( ret.expr == nullptr )
        sym.regs->set(X86_EAX, exprcst(32, ret.value));
    else{
        if( ret.expr->size != 32 ){
            throw runtime_exception("x86_cdecl_set_return_value(): fatal error, callback returned an expression with size != 32 ");
        }
        sym.regs->set(X86_EAX, ret.expr);
    }
}

void _x86_linux_custom_syscall_return(vector<size_t>& args, SymbolicEngine& sym){
    /* Get total size of args */
    size_t total_args_size = 0;
    for( auto& a : args )
        total_args_size += a;
    /* Same as cdecl but we also have to restore ESP */
    sym.regs->set(X86_EIP, sym.mem->read((uint32_t)(sym.regs->concretize(X86_ESP)), 4));
    sym.regs->set(X86_ESP, sym.mem->read((uint32_t)sym.regs->concretize(X86_ESP)+total_args_size+4, 4));
    return;
}

/* ============ Wrappers ============== */
vector<Expr> _abi_get_args(ABI abi, vector<size_t>& args, SymbolicEngine& sym){
    switch(abi){
        case ABI::X86_CDECL: return _x86_cdecl_get_args(args, sym);
        case ABI::X86_STDCALL: return _x86_stdcall_get_args(args, sym);
        case ABI::X86_LINUX_INT80: return _x86_linux_int80_get_args(args, sym);
        case ABI::X86_LINUX_SYSENTER: return _x86_linux_sysenter_get_args(args, sym);
        case ABI::X86_LINUX_CUSTOM_SYSCALL: return _x86_linux_custom_syscall_get_args(args, sym);
        default: throw runtime_exception("EnvManager::_abi_get_args(): got unsupported ABI");
    }
}

void _abi_set_args(ABI abi, vector<Expr>& args, SymbolicEngine& sym){
    switch(abi){
        case ABI::X86_CDECL: return _x86_cdecl_set_args(args, sym);
        case ABI::X86_STDCALL: return _x86_stdcall_set_args(args, sym);
        case ABI::X86_LINUX_CUSTOM_SYSCALL: return _x86_linux_custom_syscall_set_args(args, sym);
        default: throw runtime_exception("EnvManager::_abi_set_args(): got unsupported ABI");
    }
}

void _abi_set_return_address(ABI abi, addr_t ret, SymbolicEngine& sym){
    switch(abi){
        case ABI::X86_CDECL: return _x86_cdecl_set_return_address(ret, sym);
        case ABI::X86_STDCALL: return _x86_stdcall_set_return_address(ret, sym);
        case ABI::X86_LINUX_CUSTOM_SYSCALL: return _x86_linux_custom_syscall_set_return_address(ret, sym);
        default: throw runtime_exception("EnvManager::_abi_set_return_address(): got unsupported ABI");
    }
}

void _abi_set_return_value(ABI abi, EnvCallbackReturn& ret, SymbolicEngine& sym){
    switch(abi){
        case ABI::X86_CDECL: return _x86_cdecl_set_return_value(ret, sym);
        case ABI::X86_LINUX_CUSTOM_SYSCALL: return _x86_linux_custom_syscall_set_return_value(ret, sym);
        default: throw runtime_exception("EnvManager::_abi_set_return_value(): got unsupported ABI");
    }
}

vector<IROperand> _ir_abi_get_args(ABI abi, vector<size_t>& args, IRBlock& irblock){
    switch(abi){
        case ABI::X86_CDECL: return _ir_x86_cdecl_get_args(args, irblock);
        default: throw env_exception("EnvManager::_ir_abi_get_args(): got unsupported ABI");
    }
}

void _abi_return(ABI abi, vector<size_t>& args, SymbolicEngine& sym){
    switch(abi){
        case ABI::X86_CDECL: return _x86_cdecl_return(args, sym);
        case ABI::X86_STDCALL: return _x86_stdcall_return(args, sym);
        case ABI::X86_LINUX_CUSTOM_SYSCALL: return _x86_linux_custom_syscall_return(args, sym);
        default: throw runtime_exception("EnvManager::_abi_return(): got unsupported ABI");
    }
}

void _ir_abi_return(ABI abi, IRBlock& irblock){
    switch(abi){
        case ABI::X86_CDECL: return _ir_x86_cdecl_return(irblock);
        default: throw env_exception("EnvManager::_ir_abi_return(): got unsupported ABI");
    }
}

ucst_t _abi_get_syscall_num(CPUMode mode, SysType sys, SymbolicEngine& sym){
    ucst_t res;
    if( mode == CPUMode::X86 ){
        if( sys == SysType::LINUX ){
            /* Linux X86, syscall num in eax */
            res = (uint32_t)sym.regs->concretize(X86_EAX);
        }else{
            throw runtime_exception("_abi_get_syscall_num(): not implemented for this system");
        }
    }else{
        throw runtime_exception("_abi_get_syscall_num(): not implemented for this architecture/system");
    }
    return res;
}
