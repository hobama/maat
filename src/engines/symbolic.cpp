#include "symbolic.hpp"
#include "exception.hpp"
#include "simplification.hpp"
#include "io.hpp"
#include <cassert>
#include <vector>
#include <iostream>
#include <algorithm>
#include <sstream>

using std::get;
using std::vector;
using std::stringstream;

/* ======================================== */
Snapshot::Snapshot(IRContext* c, IRState& irs, snapshot_id_t path_id, env_snapshot_id_t env_id): ctx(c), 
            path_snapshot_id(path_id), env_snapshot_id(env_id){
    irstate.copy_from(irs);
}
/* ======================================== */
snapshot_id_t SnapshotManager::take_snapshot(SymbolicEngine& sym){
    if( _snapshots.size() == MAX_SNAPSHOTS )
        throw runtime_exception("Fatal error: maximum number of snapshots reached");
    _snapshots.push_back(Snapshot(sym.regs->copy(),sym.irstate, sym.path->take_snapshot(), sym.env->take_snapshot()));
    return _snapshots.size()-1;
}

void SnapshotManager::record_write(addr_t addr, int nb_bytes, MemEngine& mem){
    if( !is_active() )
        return;
    while( nb_bytes >= 8 ){
        _snapshots.back().mem_writes.push_back(make_tuple(addr,
                                                    mem.concrete_snapshot(addr, 8), 
                                                    mem.symbolic_snapshot(addr, 8)));
        nb_bytes -= 8;
        addr += 8;
    }
    if( nb_bytes >= 4 ){
        _snapshots.back().mem_writes.push_back(make_tuple(addr,
                                                    mem.concrete_snapshot(addr, 4), 
                                                    mem.symbolic_snapshot(addr, 4)));
        nb_bytes -= 4;
        addr += 4;
    }
    if( nb_bytes >= 2 ){
        _snapshots.back().mem_writes.push_back(make_tuple(addr,
                                                    mem.concrete_snapshot(addr, 2), 
                                                    mem.symbolic_snapshot(addr, 2)));
        nb_bytes -= 2;
        addr += 2;
    }
    if( nb_bytes == 1 ){
        _snapshots.back().mem_writes.push_back(make_tuple(addr,
                                                    mem.concrete_snapshot(addr, 1), 
                                                    mem.symbolic_snapshot(addr, 1)));
        nb_bytes -= 1;
        addr += 1;
    }
}

bool SnapshotManager::rewind(SymbolicEngine& sym, bool remove){
    vector<mem_write_event_t>::reverse_iterator it;
    mem_alert_t alert;
    vector<IRBlock*> block_list;
    if( _snapshots.empty() ){
        return false;
    }
    // Rewrite memory 
    for( it = _snapshots.back().mem_writes.rbegin(); it != _snapshots.back().mem_writes.rend(); it++ ){
        sym.mem->write_from_concrete_snapshot(get<0>(*it), get<1>(*it), get<2>(*it)->size(), alert); // Concrete
        sym.mem->write_from_symbolic_snapshot(get<0>(*it), get<2>(*it), alert); // Symbolic
        // If auto modifying code, remove IR blocks
        if( alert & MEM_ALERT_X_OVERWRITE ){
            /* Check if it is inside a block already disassembled */
            block_list = sym.irmanager->contains_addr(get<0>(*it));
            for( auto block : block_list ){
                sym.irmanager->remove(block->start_addr);
            }
        }
        delete get<2>(*it); get<2>(*it) = nullptr; // Delete the symbolic snaposhot
    }
    _snapshots.back().mem_writes.clear();
    // Restore path manager state
    sym.path->restore_snapshot(_snapshots.back().path_snapshot_id);
    // Restore env state
    sym.env->restore_snapshot(_snapshots.back().env_snapshot_id);
    // Restore IR state
    sym.irstate.copy_from(_snapshots.back().irstate);
    // Restore context
    sym.regs->copy_from(*_snapshots.back().ctx);
    if( remove ){
        // Remove last snapshot
        delete _snapshots.back().ctx; // Delete saved ir context
        _snapshots.pop_back();
    }
    return true;
}

bool SnapshotManager::restore(snapshot_id_t id, SymbolicEngine& sym, bool remove){
    if( id >= _snapshots.size() ){
        throw snapshot_exception("SnapshotManager::restore() got invalid snapshot id");
    }
    while( _snapshots.size() > id +1 ){
        rewind(sym, true);
    }
    rewind(sym, remove);
    return true;
}

bool SnapshotManager::is_active(){
    return _snapshots.size() > 0;
}

/* ========================================== */
MultiBranch::MultiBranch(Expr _cond, Expr _if_not_null, Expr _if_null): 
    cond(_cond), if_not_null(_if_not_null), if_null(_if_null){}
    
bool MultiBranch::is_set(){
    return cond != nullptr;
}

void MultiBranch::print(ostream& os, string tab){
    if( !is_set() ){
        os << "Multibranch: not set" << std::endl;
        return;
    }
    string  name("Multibranch | ");
    string space("            | ");
    os << tab << space << "Condition:   " << cond << std::endl;
    os << tab << name <<  "If null:     " << if_null << std::endl;
    os << tab << space << "If not null: " << if_not_null << std::endl;
}

ostream& operator<<(ostream& os, MultiBranch& multi){
    multi.print(os);
    return os;
}

MemAccess::MemAccess(Expr _addr, exprsize_t _size, Expr _expr):
    addr(_addr), size(_size), value(_expr){}
bool MemAccess::is_set(){
    return addr != nullptr;
}
void MemAccess::print(ostream& os, string tab){
    if( !is_set() ){
        os << "Mem Access: not set" << std::endl;
        return;
    }
    string  name("Mem Access | ");
    string space("           | ");
    os << tab << space << "Addr:   " << addr << std::endl;
    os << tab << name <<  "Size:   " << size << " bytes" << std::endl;
    os << tab << space << "Value:  " << value << std::endl;
}

ostream& operator<<(ostream& os, MemAccess& mem){
    mem.print(os);
    return os;
}

string stopinfo_to_str(StopInfo stop){
    switch(stop){
        case StopInfo::BREAKPOINT: return "BREAKPOINT";
        case StopInfo::SYMBOLIC_PC: return "SYMBOLIC_PC";
        case StopInfo::SYMBOLIC_CODE: return "SYMBOLIC_CODE";
        case StopInfo::MISSING_FUNCTION: return "MISSING FUNCTION";
        case StopInfo::EXIT: return "EXIT";
        case StopInfo::NONE: return "NONE";
        default: throw symbolic_exception("stopinfo_to_str(): Got unsupported StopInfo ! ");
    }
}

SymbolicEngineInfo::SymbolicEngineInfo(){
    reset();
}
void SymbolicEngineInfo::reset(){
    stop = StopInfo::NONE;
    addr = 0;
    breakpoint = string("");
    branch = nullptr;
    multibranch = MultiBranch(nullptr, nullptr, nullptr);
    mem_access = MemAccess(nullptr, 0, nullptr);
    path_constraint = nullptr;
}

ostream& operator<<(ostream& os, SymbolicEngineInfo& info){
    os << std::endl;
    if( info.stop == StopInfo::NONE ){
        // If NONE don't print info
        os << "No info currently set" << std::endl;
        return os;
    }
    // Check the stop reason
    if( info.stop == StopInfo::BREAKPOINT ){
        os << "Breakpoint: " << info.breakpoint << std::endl;
    }else if( info.stop == StopInfo::MISSING_FUNCTION ){
        os << "Stop:       simulated function has no implementation" << std::endl;
    }else if( info.stop == StopInfo::INSTR_COUNT ){
        os << "Stop:       reached max instruction count" << std::endl;
    }else if( info.stop == StopInfo::EXIT ){
        os << "Stop:       program exited" << std::endl;
    }else if( info.stop == StopInfo::ERROR ){
        os << "Stop:       fatal error during execution" << std::endl;
    }else if( info.stop == StopInfo::SYMBOLIC_PC ){
        os << "Stop:       program counter is symbolic" << std::endl;
    }else if( info.stop == StopInfo::SYMBOLIC_CODE ){
        os << "Stop:       code to execute is symbolic" << std::endl;
    }else{
        os << "Stop:       " << stopinfo_to_str(info.stop) << std::endl;
    }
    
    os << "Addr:       0x" << std::hex << info.addr << std::endl;
    if( info.branch != nullptr )
        os << "Branch to:  " << info.branch << std::endl;
    if( info.multibranch.is_set() ){
        os << std::endl << info.multibranch;
    }
    if( info.path_constraint != nullptr ){
        os << "Constraint: " << info.path_constraint << std::endl;
    }
    if( info.mem_access.is_set() ){
        os << std::endl << info.mem_access;
    }
    return os;
}       

/* ========================================== */
void PathManager::add(Constraint constr){
    _constraints.push_back(constr);
}
void PathManager::constraints_to_solver(Solver* s){
    for( auto constr : _constraints ){
        /* Add constraints in the solver */
        s->add(constr);
    }
}
unsigned int PathManager::take_snapshot(){
    return _constraints.size();
}
void PathManager::restore_snapshot(unsigned int snap_id){
    _constraints.resize(snap_id);
}
vector<Constraint>& PathManager::constraints(){
    return _constraints;
}
/* ========================================== */
SymbolicEngine::SymbolicEngine(){
    arch = nullptr;
    irmanager = nullptr;
    regs = nullptr;
    mem = nullptr;
    vars = nullptr;
    path = nullptr;
    snapshot_manager = nullptr;
    env = nullptr;
    options = 0;
    simplifier = nullptr;
#ifdef PYTHON_BINDINGS
    self_python_wrapper_object = nullptr;
#endif
}

SymbolicEngine::SymbolicEngine(ArchType a, SysType sys){
    if(a == ArchType::X86){
        arch = new ArchX86();
    }else{
        throw symbolic_exception("SymbolicEngine::SymbolicEngine() unsupported ArchType");
    }
#ifdef PYTHON_BINDINGS
    self_python_wrapper_object = nullptr;
#endif
    irmanager = new IRManager();
    vars = new VarContext(0);
    regs = new IRContext(arch->nb_regs, vars);
    snapshot_manager = new SnapshotManager();
    mem = new MemEngine(vars, snapshot_manager);
    env = new EnvManager(a, sys);
    /* init all register to concrete null values */
    for( reg_t reg = 0; reg < arch->nb_regs; reg++){
        regs->set(reg, exprcst(32, 0));
    }
    options = 0;
    path = new PathManager();
    simplifier = NewDefaultExprSimplifier();
    _cst_folding_simplifier.add(es_constant_folding);
    /* Enable options */
    enable(SymbolicEngineOption::FORCE_CST_FOLDING);
    enable(SymbolicEngineOption::OPTIMIZE_IR);
    enable(SymbolicEngineOption::SIMPLIFY_CONSTRAINTS);
    enable(SymbolicEngineOption::PRINT_ERRORS);
}

/* This function is here for unit-tests so that it can be used without
 * initializing all contextes according to a specific architecture. */
SymbolicEngine::SymbolicEngine(Arch* a, IRManager* irm, VarContext* vctx, IRContext* ictx, MemEngine* m, PathManager* pathm){
    /*assert(irm != nullptr);
    assert(vctx != nullptr);
    assert(ictx != nullptr);
    assert(m != nullptr);
    assert(a != nullptr);
    assert(pathm != nullptr);*/
    irmanager = irm;
    vars = vctx;
    regs = ictx;
    mem = m;
    arch = a;
    path = pathm;
    snapshot_manager = new SnapshotManager();
    options = 0;
    _cst_folding_simplifier.add(es_constant_folding);
    env = new EnvManager();
    simplifier = NewDefaultExprSimplifier();
#ifdef PYTHON_BINDINGS
    self_python_wrapper_object = nullptr;
#endif
}

#ifdef PYTHON_BINDINGS
void SymbolicEngine::set_self_python_wrapper_object(PyObject* obj){
    self_python_wrapper_object = obj;
}
#endif

SymbolicEngine::~SymbolicEngine(){
    delete irmanager; irmanager = nullptr;
    delete vars; vars = nullptr;
    delete regs; regs = nullptr;
    delete mem; mem = nullptr;
    delete arch; arch = nullptr;
    delete path; path = nullptr;
    delete env; env = nullptr;
    delete snapshot_manager; snapshot_manager = nullptr;
    delete simplifier; simplifier = nullptr;
}

/* Symbolic execution functions */
StopInfo SymbolicEngine::execute_from(addr_t addr, unsigned int max_instr){
    breakpoint_record.clear_asmlvl();
    regs->set(arch->pc(), exprcst(arch->bits, addr));
    irstate.reset();
    info.reset();
    return execute(max_instr);
}

/* Some util functions to manipulate values during symbolic execution */
inline void _set_tmp_var(int num, Expr e, int high, int low, vector<Expr>& tmp_vars){
    unsigned int tmp_vars_size = tmp_vars.size();
    if( tmp_vars_size > num ){
        if( tmp_vars[num] == nullptr )
            tmp_vars[num] = e;
        else
            tmp_vars[num] = _expand_lvalue(tmp_vars[num], e, high, low);
    }else if( tmp_vars_size == num ){
        tmp_vars.push_back(e);
    }else{
        /* Fill missing tmp variables if needed *//*
        for( int i = 0; i < (num - tmp_vars_size); i++){
            tmp_vars.push_back(nullptr);
        }*/
        std::fill_n(std::back_inserter(tmp_vars), (num - tmp_vars_size), nullptr);
        tmp_vars.push_back(e);
    }
}

Expr _reduce_rvalue(Expr e, exprsize_t high, exprsize_t low ){
    if( high-low+1 == e->size )
        return e;
    else
        return extract(e, high, low);
}

Expr _expand_lvalue(Expr current, Expr e, exprsize_t high, exprsize_t low){
    if( high-low+1 >= current->size )
        return e;
    else if(low == 0){
        return concat(extract(current, current->size-1, high+1), e);
    }else if(high == current->size-1){
        return concat(e, extract(current, low-1, 0));
    }else{
        return concat(extract(current, current->size-1, high+1),
                      concat(e, extract(current, low-1, 0))); 
    }
}

Expr _get_operand(IROperand& arg, IRContext* irctx, vector<Expr>& tmp_vars){
    if( arg.is_cst() ){
        if( arg.high-arg.low+1 == sizeof(cst_t)*8 )
            return exprcst(arg.high-arg.low+1, arg.cst());
        else
            return exprcst(arg.high-arg.low+1, 
                ((ucst_t)arg.cst() & (((ucst_t)1 << (arg.high+1))-1)) >> (ucst_t)arg.low);
    }else if( arg.is_var() ){
        return _reduce_rvalue(irctx->get(arg.var()), arg.high, arg.low);
    }else if( arg.is_tmp() ){
        return _reduce_rvalue(tmp_vars[arg.tmp()], arg.high, arg.low);
    }else{
        return nullptr;
    }
}

/* This function should be called when a breakpoint has been triggered. The 
 * symbolic engine checks if there is a callback or not and if the execution
 * should automatically continue or not. 
 * 
 * It returns true if the execution must continue
 * It returns false if the execution must stop */
bool SymbolicEngine::handle_breakpoint(){
    /* If the breakpoint has a callback call it */
    if( breakpoint._hit.callback_type != CallbackType::NONE ){
        if( breakpoint._hit.callback_type == CallbackType::NATIVE ){
            breakpoint._hit.callback(*this);
        }else if( breakpoint._hit.callback_type == CallbackType::PYTHON){
#ifdef PYTHON_BINDINGS
            PyObject* argslist = Py_BuildValue("(O)", self_python_wrapper_object);
            if( argslist == NULL ){
                throw runtime_exception("SymbolicEngine::handle_breakpoint(): failed to create args tuple for python callback");
            }
            Py_INCREF(argslist);
            PyObject* result = PyObject_CallObject(breakpoint._hit.python_callback, argslist);
            Py_DECREF(argslist);
            Py_XDECREF(result);
#endif
        }else{
            throw runtime_exception("SymbolicEngine::handle_breakpoint(): got unsupported CallbackType");
        }
        if( breakpoint._hit.resume ){
            /* If auto-resume  */
            info.reset(); // Clear stop info
        }else{
            return false;
        }
    }else{
        return false;
    }
    return true;
}

StopInfo SymbolicEngine::execute(unsigned int max_instr){
    Expr rvalue, dst, src1, src2;
    IRBasicBlock::iterator instr; 
    vector<IRBlock*> block_list;
    vector<InstructionLocation> instr_location_list;
    bool stop, next_block = true, next_bblock;
    int ir_instr_start; // Keep track of the first IR instr corresponding to the current executed instr
    IRBlock* block; // Executed block
    bool check_max_instr; // true if a max nb of instr to execute was specified in arguments
    mem_alert_t mem_alert;
    addr_t write_addr, to_exec;
    bool automodifying_block;
    int env_status;
    addr_t printed_addr=-1; // For printing only
    bool is_symbolic, is_tainted; // Used to detect symbolic/tainted code
    
    /* Check if a number of instructions has been given (default 0 = execute forever) */
    check_max_instr = ( max_instr != 0 );
    
    /* Check and reset stop info */
    if( info.stop == StopInfo::EXIT ){
        throw symbolic_exception("Cannot call SymbolicEngine::execute() because program exited");
    }
    info.reset();
    
    /* Execute forever while there is a block to execute */
    while( next_block ){
        next_block = false; // We don't have a next block to execute yet
        automodifying_block = false;
        
        /* ====== Get the address of the next instruction to execute ====== */
        if( regs->get(arch->pc())->is_symbolic(*vars)){
            info.stop = StopInfo::SYMBOLIC_PC;
            return StopInfo::SYMBOLIC_PC;
        }else{
            to_exec = cst_sign_trunc(regs->get(arch->pc())->size, regs->get(arch->pc())->concretize(vars));
        }
        
        /* ================ Simulate external functions ================== */
        /* Check if the address corresponds to a external function that must be
         * simulated ! */
        env_status = env->check_and_simulate(to_exec, *this);
        if( env_status == ENV_CALLBACK_SUCCESS || env_status == ENV_CALLBACK_SUCCESS_WITH_VALUE){
             // PC has changed depending on the return value, go back to main loop
             next_block = true;
             continue;
        }else if( env_status == ENV_CALLBACK_FAIL ){
            // Raise exception
            _print_error(_error_msg);
            throw env_exception(ExceptionFormatter() << "Failed to execute callback (at fake address: 0x" << 
            std::hex << to_exec << ")" >> ExceptionFormatter::to_str);
        }else if( env_status == ENV_CALLBACK_NOT_IMPLEMENTED ){
            // Warn that callback isn't implemented
            stringstream ss;
            ss << "Emulation not implemented for function at address: 0x" << std::hex << to_exec;
            _print_warning(ss.str());
            // Check if option to ignore unresolved imports is set, if not then stop
            if( is_enabled( SymbolicEngineOption::IGNORE_MISSING_IMPORTS) ){
                next_block = true;
                continue;
            }else{
                info.stop = StopInfo::MISSING_FUNCTION;
                info.addr = to_exec;
                return StopInfo::MISSING_FUNCTION;
            }
        }else if( env_status == ENV_CALLBACK_EXIT ){
            info.stop = StopInfo::EXIT;
            return StopInfo::EXIT;
        }else if( env_status == ENV_BREAKPOINT ){
            if( ! handle_breakpoint()){
                return StopInfo::BREAKPOINT;
            }else{
                /* Execution must continue after breakopint, just go back to the beginning
                 * of the block (i.e call the simulated function again) */
                next_block = true;
                continue;
            }
        }else if( env_status == ENV_NO_CALLBACK ){
            // They were no callbacks to execute, just do nothing
            // and continue like normal
        }else{
            throw runtime_exception("Got unsupported return code from simulated function!");
        }
        
        /* ================= Set the IR state to execute code =================== */
        /* If the ir state is set and valid */
        if( irstate.is_set ){
            /* Try to get the corresponding IRBlock (nullptr) if it has been deleted since then */
            block = irmanager->starts_at_addr(irstate.block_addr);
            if( block == nullptr ){
                throw runtime_exception("SymbolicEngine::execute(): couldn't find IRBlock while irstate is set!");
            }
        }else{
            /* If irstate is not set: find the next instruction to execute */
            /* Set address of instruction to execute in ir state */
            irstate.instr_addr = to_exec;
            /* Find the IR block */
            instr_location_list = irmanager->contains_instr(irstate.instr_addr);
            /* If block not disassembled do it */
            if( instr_location_list.empty() ){
                /* The block doesn't exist, we disassemble the corresponding
                 * code and create a new IRBlock */
                is_symbolic = false;
                is_tainted = false;
                block = arch->disasm->disasm_block(irstate.instr_addr, mem->mem_at(irstate.instr_addr), 0xfffffff, this, &is_symbolic, &is_tainted);
                
                /* Check if the block contains symbolic code */
                if( is_symbolic ){
                    // Print error
                    stringstream ss;
                    ss << "Trying to execute purely symbolic code in basic block starting from: 0x" << std::hex << irstate.instr_addr;
                    _print_error(ss.str());
                    info.stop = StopInfo::SYMBOLIC_CODE;
                    info.addr = irstate.instr_addr;
                    // Reset ir state
                    irstate.reset();
                    return StopInfo::SYMBOLIC_CODE;
                }
                
                /* Check if OPTIMIZE_IR option is enabled */
                if( is_enabled(SymbolicEngineOption::OPTIMIZE_IR)){
                    block->remove_unused_vars(arch->nb_regs, vector<IRVar>(1, arch->pc()));
                }
                irmanager->add(block);
                irstate.block_addr = block->start_addr;
                irstate.bblkid = 0;
                irstate.ir_instr_num = 0;
                
                /* Check if the block containted tainted instructions, but only
                 * after we added it */
                if( is_tainted && breakpoint.check_tainted_code(*this, irstate.instr_addr) ){
                    if( !handle_breakpoint()){
                        irstate.reset();
                        return StopInfo::BREAKPOINT;
                    }
                }
                // FOR DEBUG
                // std::cout << "\nGot new IRBlock: " << std::endl << *block << std::flush; 
            }else{
                /* The block already exists*/
                block = instr_location_list[0].block;
                irstate.block_addr = block->start_addr;
                irstate.bblkid = instr_location_list[0].bblkid;
                irstate.ir_instr_num = instr_location_list[0].instr_count;
            }
            irstate.is_set = true;
        }
        stop = false;
        
        
        /* ====================== Execute an IR basic block ======================== */ 
        /* Execute the basic block as long as there is no reason to stop */
        while( !stop ){
            /* Iterate through next bblock to execute */
            next_bblock = false;
            irstate.ir_instr_num--; // Decrement because we increment it at the beginning of the loop
            ir_instr_start = irstate.ir_instr_num+1; // Record at which IR instr the ASM instr started
            for( instr = block->get_bblock(irstate.bblkid).begin()+irstate.ir_instr_num+1; instr != block->get_bblock(irstate.bblkid).end(); instr++){
                // FOR DEBUG
                // std::cout << "DEBUG, executing " << *instr << std::endl;
                irstate.ir_instr_num++;
                /* Check if we changed asm instruction */
                if( instr->addr != irstate.instr_addr ){
                    //std::cout << "DEBUG, executing " << std::hex << *instr << instr->addr << std::dec << std::endl;
                    breakpoint_record.clear_asmlvl();
                    /* Change instruction address and ir count */
                    irstate.instr_addr = instr->addr;
                    ir_instr_start = irstate.ir_instr_num;
                    max_instr--;
                    /* Check if automodifying code has been detected */
                    if( automodifying_block ){
                        stop = true;
                        break;
                    }
                }
                
                /* Check if max_instr has been reached */
                if( check_max_instr && (max_instr == 0)){
                    info.stop = StopInfo::INSTR_COUNT;
                    return StopInfo::INSTR_COUNT;
                }
                
                /* Check if a breakpoint has to be triggered */
                /* ( for TAINTED_PC we check also that we are on the first ir instruction of the 
                 * current ASM instruction, we want to break at the beginning of the new one not when
                 * modifying the PC in the previous instruction semantics) */
                if(  breakpoint.check(*this, *instr, irstate.tmp_vars) ||
                    ((ir_instr_start == irstate.ir_instr_num) && breakpoint.check_pc(*this, regs->get(arch->pc()))) ||
                    (breakpoint.check_path(*this, *instr, irstate.tmp_vars)) ){
                    /* Handle the breakpoint (callbacks, etc) */
                    if( !handle_breakpoint()){
                        return StopInfo::BREAKPOINT;
                    }
                }
                
                /* Clear breakpoints for next instructions 
                 * This MUST be AFTER the breakpoints check otherwise we'll keep removing
                 * the breakpoint record and breaking forever */
                breakpoint_record.clear_irlvl();
                
                /* Print instructions if option is set */
                if( instr->addr != printed_addr && is_enabled(SymbolicEngineOption::PRINT_INSTRUCTIONS) ){
                    printed_addr = instr->addr;
                    stringstream ss;
                    ss << "Executing: 0x" << std::hex << instr->addr;
                    print_info(ss.str());
                }
                
                /* Get operands expressions */
                src1 = _get_operand(instr->src1, regs, irstate.tmp_vars);
                src2 = _get_operand(instr->src2, regs, irstate.tmp_vars);
                /* Arithmetic and logic operations */
                if( iroperation_is_assignment(instr->op)){
                    /* Build rvalue */
                    switch( instr->op ){
                        case IROperation::ADD: 
                            rvalue = src1 + src2;
                            break;
                        case IROperation::SUB:
                            rvalue = src1 - src2; 
                            break;
                        case IROperation::MUL: 
                            rvalue = src1 * src2;
                            break;
                        case IROperation::MULH: 
                            rvalue = mulh(src1, src2);
                            break;
                        case IROperation::SMULL: 
                            rvalue = smull(src1,src2);
                            break;
                        case IROperation::SMULH: 
                            rvalue = smulh(src1,src2);
                            break;
                        case IROperation::DIV:
                            rvalue = src1 / src2;
                            break;
                        case IROperation::SDIV: 
                            rvalue = sdiv(src1, src2);
                            break;
                        case IROperation::SHL: 
                            rvalue = shl(src1, src2);
                            break;
                        case IROperation::SHR: 
                            rvalue = shr(src1, src2);
                            break;
                        case IROperation::AND:
                            rvalue = src1 & src2;
                            break;
                        case IROperation::OR:
                            rvalue = src1 | src2;
                            break;
                        case IROperation::XOR:
                            rvalue = src1 ^ src2;
                            break;
                        case IROperation::MOD:
                            rvalue = src1 % src2;
                            break;
                        case IROperation::SMOD:
                            rvalue = smod(src1,src2);
                            break;
                        case IROperation::NEG:
                            rvalue = -src1;
                            break;
                        case IROperation::NOT:
                            rvalue = ~src1;
                            break;
                        case IROperation::MOV:
                            rvalue = src1;
                            break;
                        case IROperation::CONCAT:
                            rvalue = concat(src1, src2);
                            break;
                        default: throw runtime_exception("Unsupported assignment IROperation in SymbolicEngine::execute_block()");
                    }
                    /* If option enabled, do cst folding on non-tainted expressions */
                    if( is_enabled(SymbolicEngineOption::FORCE_CST_FOLDING) &&
                        !rvalue->is_tainted() ){
                        rvalue = _cst_folding_simplifier.simplify(rvalue);
                    }
                    
                    /* Affect lvalue */
                    if( instr->dst.is_tmp()){
                        _set_tmp_var(instr->dst.tmp(), rvalue, instr->dst.high, instr->dst.low, irstate.tmp_vars);
                    }else if( instr->dst.is_var()){
                        regs->set(instr->dst.var(), _expand_lvalue(regs->get(instr->dst.var()), rvalue,
                                                                        instr->dst.high, instr->dst.low));
                    }else{
                        throw runtime_exception("SymbolicEngine::execute_block() got invalid dst operand type");
                    }
                }else if(instr->op == IROperation::STM){
                    /* Store memory */
                    dst = _get_operand(instr->dst, regs, irstate.tmp_vars);
                    mem_alert = MEM_ALERT_NONE;
                    if( dst->is_symbolic(*vars) ){
                        throw runtime_exception("SymbolicEngine::execute_block(): full symbolic pointer write not yet supported");
                    }else{
                        write_addr = cst_sign_trunc(dst->size, dst->concretize(vars));
                        /* THEN execute the store */
                        mem->write(write_addr, src1, vars, mem_alert);
                        /* Check if we overwrote executable code */
                        if( mem_alert & MEM_ALERT_X_OVERWRITE ){
                            /* Check if it is inside a block already disassembled */
                            block_list = irmanager->contains_addr(write_addr);
                            for( auto block2 : block_list ){
                                // If its not this one just erase it and continue 
                                if( block2 != block ){
                                    irmanager->remove(block2->start_addr);
                                }else{
                                    automodifying_block = true; // --> finish this instruction, remove the block, then re-enter :) 
                                }
                            }
                        }
                    }
                
                }else if( instr->op == IROperation::LDM){
                    /* Load memory */
                    if( src1->is_symbolic(*vars) ){
                        throw runtime_exception("SymbolicEngine::execute_block(): full symbolic pointer read not yet supported");
                    }else{
                        rvalue = mem->read(cst_sign_trunc(src1->size, src1->concretize(vars)), (instr->dst.high-instr->dst.low+1)/8);
                    }
                    
                    /* Affect lvalue */
                    if( instr->dst.is_tmp()){
                        _set_tmp_var(instr->dst.tmp(), rvalue, instr->dst.high, instr->dst.low, irstate.tmp_vars);
                    }else if( instr->dst.is_var()){
                        regs->set(instr->dst.var(), _expand_lvalue(regs->get(instr->dst.var()), rvalue,
                                                                        instr->dst.high, instr->dst.low));
                    }else{
                        throw runtime_exception("SymbolicEngine::execute_block() got invalid dst operand type");
                    }
                }else if( instr->op == IROperation::BCC){
                    dst = _get_operand(instr->dst, regs, irstate.tmp_vars);
                    if( dst->is_symbolic(*vars) ){
                        throw runtime_exception("SymbolicEngine::execute_block(): BCC with symbolic condition not supported");
                    }
                    /* Record path constraint if option enabled */
                    if( is_enabled(SymbolicEngineOption::RECORD_PATH_CONSTRAINTS) &&
                            dst->is_tainted() && !instr->src2.is_none()){
                        if( is_enabled(SymbolicEngineOption::SIMPLIFY_CONSTRAINTS) ){
                            // If option set simplify the constraint
                            dst = simplifier->simplify(dst);
                        }
                        // Check if still tainted after modification
                        if( dst->is_tainted() ){
                            if( dst->concretize(vars) != 0){
                                path->add(dst != exprcst(dst->size, 0));
                            }else{
                                path->add(dst == exprcst(dst->size,0));
                            }
                        }
                    }
                    /* Check condition and update basic block to execute */
                    if( cst_sign_trunc(dst->size, dst->concretize(vars)) != 0){
                        if( src1->is_symbolic(*vars)){
                            throw runtime_exception("SymbolicEngine::execute_block(): BCC block number should not be symbolic");
                        }else{
                            irstate.bblkid = src1->concretize(vars);
                        }
                    }else{
                        if( src2->is_symbolic(*vars)){
                            throw runtime_exception("SymbolicEngine::execute_block(): BCC block number should not be symbolic");
                        }else{
                            irstate.bblkid = src2->concretize(vars);
                        }
                    }
                    next_bblock = true;
                    irstate.ir_instr_num = 0;
                    break;
                }else if( instr->op == IROperation::JCC ){
                    dst = _get_operand(instr->dst, regs, irstate.tmp_vars);
                    /* Check for symbolic branch */
                    if( dst->is_symbolic(*vars) ){
                        throw runtime_exception("SymbolicEngine::execute_block(): JCC with symbolic condition not supported");
                    }

                    /* Record path constraint if option enabled */
                    if( is_enabled(SymbolicEngineOption::RECORD_PATH_CONSTRAINTS) &&
                            dst->is_tainted() && !instr->src2.is_none()){
                        if( is_enabled(SymbolicEngineOption::SIMPLIFY_CONSTRAINTS) ){
                            // If option set simplify the constraint
                            dst = simplifier->simplify(dst);
                        }
                        // Check if still tainted after modification
                        if( dst->is_tainted() ){
                            if( dst->concretize(vars) != 0){
                                path->add(dst != exprcst(dst->size, 0));
                            }else{
                                path->add(dst == exprcst(dst->size,0));
                            }
                        }
                    }
                                        
                    /* Set new PC */
                    if( cst_sign_trunc(dst->size, dst->concretize(vars)) != 0){
                        regs->set(arch->pc(), _expand_lvalue(regs->get(arch->pc()), src1,
                                                                    instr->dst.high, instr->dst.low));
                    }else{
                        regs->set(arch->pc(), _expand_lvalue(regs->get(arch->pc()), src2,
                                                                    instr->dst.high, instr->dst.low));
                    }
                    /* Quit this block */
                    stop = true; // Go out of this block
                    next_block = true; // Say that we want to continue with another block
                    max_instr--; // JCC always finisheds an instruction so decrease the instr count (because we don't go back to the 
                                 // beginning of the loop that detects instruction change
                    breakpoint_record.clear_asmlvl(); // Clear the breakpoints record because address changes are not detected
                                               // when entering a new basic block
                    irstate.reset();
                    break; // Stop executing instructions in the basic block
                }else if(instr->op == IROperation::BISZ){
                    rvalue = bisz((instr->dst.high-instr->dst.low)+1 , src1, cst_sign_trunc(src2->size, src2->concretize(vars)));
                    /* Affect lvalue */
                    if( instr->dst.is_tmp()){
                        _set_tmp_var(instr->dst.tmp(), rvalue, instr->dst.high, instr->dst.low, irstate.tmp_vars);
                    }else if( instr->dst.is_var()){
                        regs->set(instr->dst.var(), _expand_lvalue(regs->get(instr->dst.var()), rvalue,
                                                                        instr->dst.high, instr->dst.low));
                    }else{
                        throw runtime_exception("SymbolicEngine::execute_block() got invalid dst operand type");
                    }
                
                }else if(instr->op == IROperation::INT){
                    /* Get the number of the interrupt and the return address */
                    cst_t num = cst_sign_trunc(instr->dst.size, _get_operand(instr->dst, regs, irstate.tmp_vars)->concretize());
                    addr_t ret = cst_sign_trunc(instr->src1.size, _get_operand(instr->src1, regs, irstate.tmp_vars)->concretize());
                    env->do_interrupt(num, ret, *this);
                    /* Quit this block */
                    stop = true; // Go out of this block
                    next_block = true; // Say that we want to continue with another block
                    max_instr--; // INT always finishes an instruction so decrease the instr count (because we don't go back to the 
                                 // beginning of the loop that detects instruction change
                    breakpoint_record.clear_asmlvl(); // Clear the breakpoints record because address changes are not detected
                                               // when entering a new basic block
                    irstate.reset();
                    break; // Stop executing instructions in the basic block
                }else if(instr->op == IROperation::SYSCALL){
                    /* Get the type of syscall and the return address */
                    cst_t syscall_type = cst_sign_trunc(instr->dst.size, _get_operand(instr->dst, regs, irstate.tmp_vars)->concretize());
                    addr_t ret = cst_sign_trunc(instr->src1.size, _get_operand(instr->src1, regs, irstate.tmp_vars)->concretize());
                    env->prepare_syscall(syscall_type, ret, *this);
                    /* Quit this block */
                    stop = true; // Go out of this block
                    next_block = true; // Say that we want to continue with another block
                    max_instr--; // INT always finishes an instruction so decrease the instr count (because we don't go back to the 
                                 // beginning of the loop that detects instruction change
                    breakpoint_record.clear_asmlvl(); // Clear the breakpoints record because address changes are not detected
                                               // when entering a new basic block
                    irstate.reset();
                    break; // Stop executing instructions in the basic block
                }else{
                    throw runtime_exception("SymbolicEngine::execute_block(): unknown IR instruction type");
                }
            }
            stop = stop || !next_bblock; // If no next basic block or forced stop then stop
            if( automodifying_block ){
                // Remove current block and exit the loop
                irmanager->remove(block->start_addr);
                block = nullptr;
                next_block = true;
                irstate.reset();
            }
            
        }
    }
    return StopInfo::NONE;
}

snapshot_id_t SymbolicEngine::take_snapshot(){
    /* Take snapshot with the snapshot manager */
    return snapshot_manager->take_snapshot(*this);
}
bool SymbolicEngine::restore_snapshot(snapshot_id_t id, bool remove){
    breakpoint_record.clear_asmlvl();
    info.reset();
    return snapshot_manager->restore(id, *this, remove);
}

bool SymbolicEngine::restore_snapshot(bool remove){
    breakpoint_record.clear_asmlvl();
    info.reset();
    return snapshot_manager->rewind(*this, remove);
}

void SymbolicEngine::enable(SymbolicEngineOption opt){
    options |= (int)opt;
}
void SymbolicEngine::disable(SymbolicEngineOption opt){
    options &= (~(int)opt);
}
bool SymbolicEngine::is_enabled(SymbolicEngineOption opt){
    return (int)opt & (int)options;
}

void SymbolicEngine::set_symbol_address(string name, addr_t addr){
    _symbols[name] = addr;
}

addr_t SymbolicEngine::get_symbol_address(string name){
    unordered_map<string, addr_t>::iterator res;
    if( (res = _symbols.find(name)) == _symbols.end()){
        throw symbolic_exception(ExceptionFormatter() << "Symbol '" << name << "' is unknown" >> ExceptionFormatter::to_str);
    }else{
        return res->second;
    }
}

/* Printing infos */
void SymbolicEngine::_print_info(string msg){
    print_info(msg);
}
void SymbolicEngine::_print_warning(string msg){
    if( is_enabled(SymbolicEngineOption::PRINT_WARNINGS)){
        print_warning(msg);
    }
}
void SymbolicEngine::_print_error(string msg){
     if( is_enabled(SymbolicEngineOption::PRINT_ERRORS)){
        print_error(msg);
    }
}
