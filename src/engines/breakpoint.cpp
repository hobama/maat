#include "breakpoint.hpp"
#include "symbolic.hpp"
#include "exception.hpp"


Breakpoint::Breakpoint(): type(BreakpointType::NONE), value(0), value2(0), name(""), callback(nullptr), resume(true){
#ifdef PYTHON_BINDINGS
    python_callback = nullptr;
#endif
}

Breakpoint::Breakpoint(BreakpointType t, string n, addr_t v, addr_t v2, void (*cb)(SymbolicEngine& sym), bool r):
    type(t), value(v), value2(v2), name(n), callback(cb), callback_type(CallbackType::NONE), resume(r){
    if( callback != nullptr ){
        callback_type = CallbackType::NATIVE;
    }
#ifdef PYTHON_BINDINGS
    python_callback = nullptr;
#endif
}
#ifdef PYTHON_BINDINGS
Breakpoint::Breakpoint(BreakpointType t, string n, addr_t v, addr_t v2, PyObject* pcb, bool r):
    type(t), value(v), value2(v2), name(n), callback(nullptr), python_callback(pcb), callback_type(CallbackType::NONE), resume(r){
    if( python_callback != nullptr ){
        callback_type = CallbackType::PYTHON;
        Py_INCREF(python_callback);
    }
}
#endif

Breakpoint::~Breakpoint(){
#ifdef PYTHON_BINDINGS
    if( callback_type == CallbackType::PYTHON && python_callback != nullptr)
        Py_DECREF(python_callback);
#endif
}


BreakpointManager::BreakpointManager(): _nb(0){}

bool _breakpoint_should_be_unique(BreakpointType t){
    return  t == BreakpointType::BRANCH ||
            t == BreakpointType::MULTIBRANCH ||
            t == BreakpointType::TAINTED_PC ||
            t == BreakpointType::TAINTED_CODE;
}

bool _breakpoint_is_asmlvl(BreakpointType t){
    return  t == BreakpointType::ADDR ||
            t == BreakpointType::TAINTED_PC ||
            t == BreakpointType::TAINTED_CODE;
}

void BreakpointManager::add(BreakpointType t, string n, addr_t v, void (*callback)(SymbolicEngine& sym), bool resume){
    /* We keep this so that for memory regions we can specify a single
     * address to watch, and gets converted to an intervalle [addr,addr].
     * If we had a default zero value for value2 then it would be unsound */
    add(t, n, v, v, callback, resume);
}

/* !!!!!!! If implementation changes, don't forget to update add_from_python as well :) */
void BreakpointManager::add(BreakpointType t, string n, addr_t v, addr_t v2, void (*callback)(SymbolicEngine& sym), bool resume){
    if( n.empty() ){
        throw breakpoint_exception("BreakpointManager::add() cannot add breakpoint with empty name");
    }
    /* Check that this breakpoint doesn't already exist */
    if( !_tainted_pc.name.compare(n) || !_path_constraint.name.compare(n) || !_tainted_code.name.compare(n)){
        throw breakpoint_exception("BreakpointManager::add(): cannot add two breakpoints with same name" );
    }else{
        for( int i = 0; i < _breakpoints.size(); i++){
            if( !_breakpoints[i].name.compare(n)){
                throw breakpoint_exception("BreakpointManager::add(): cannot add two breakpoints with same name" );
            }else if( _breakpoint_should_be_unique(t) && _breakpoints[i].type == t ){
                throw breakpoint_exception("BreakpointManager::add(): cannot add two breakpoints of this type");
            }
        }
    }
    /* Add new breakpoint */
    if( t == BreakpointType::TAINTED_PC ){
        if( _tainted_pc.type != BreakpointType::NONE ){
            throw breakpoint_exception("BreakpointManager::add() cannot add two TAINTED_PC breakpoints");
        }
        _tainted_pc = Breakpoint(t, n, 0, 0, callback, resume);
    }else if( t == BreakpointType::PATH_CONSTRAINT ){
        if( _path_constraint.type != BreakpointType::NONE ){
            throw breakpoint_exception("BreakpointManager::add() cannot add two PATH_CONSTRAINT breakpoints");
        }
        _path_constraint = Breakpoint(t, n, 0, 0, callback, resume);
    }else if( t == BreakpointType::TAINTED_CODE ){
        if( _tainted_code.type != BreakpointType::NONE ){
            throw breakpoint_exception("BreakpointManager::add() cannot add two TAINTED_CODE breakpoints");
        }
        _tainted_code = Breakpoint(t, n, 0, 0, callback, resume);
    }else{
        _breakpoints.push_back(Breakpoint(t, n, v, v2, callback, resume));
    }
    // Increment breakpoints count
    _nb++;
}

#ifdef PYTHON_BINDINGS
/* This add_from_python is exactly the same code as add() but with a different type for 'callback'. It's super ugly to
 * duplicate code like this but I didn't find a better way since:
   - callback is used as an argument to Breakpoint() and thus we must know its type
   - it's forbidden to cast function pointers
   - python bindings are not necessarily compiled
*/
void BreakpointManager::add_from_python(BreakpointType t, string n, addr_t v, addr_t v2, PyObject* callback, bool resume){
    if( n.empty() ){
        throw breakpoint_exception("BreakpointManager::add() cannot add breakpoint with empty name");
    }
    /* Check that this breakpoint doesn't already exist */
    if( !_tainted_pc.name.compare(n) || !_path_constraint.name.compare(n) || !_tainted_code.name.compare(n)){
        throw breakpoint_exception("BreakpointManager::add(): cannot add two breakpoints with same name" );
    }else{
        for( int i = 0; i < _breakpoints.size(); i++){
            if( !_breakpoints[i].name.compare(n)){
                throw breakpoint_exception("BreakpointManager::add(): cannot add two breakpoints with same name" );
            }else if( _breakpoint_should_be_unique(t) && _breakpoints[i].type == t ){
                throw breakpoint_exception("BreakpointManager::add(): cannot add two breakpoints of this type");
            }
        }
    }
    /* Add new breakpoint */
    if( t == BreakpointType::TAINTED_PC ){
        if( _tainted_pc.type != BreakpointType::NONE ){
            throw breakpoint_exception("BreakpointManager::add() cannot add two TAINTED_PC breakpoints");
        }
        _tainted_pc = Breakpoint(t, n, 0, 0, callback, resume);
    }else if( t == BreakpointType::PATH_CONSTRAINT ){
        if( _path_constraint.type != BreakpointType::NONE ){
            throw breakpoint_exception("BreakpointManager::add() cannot add two PATH_CONSTRAINT breakpoints");
        }
        _path_constraint = Breakpoint(t, n, 0, 0, callback, resume);
    }else if( t == BreakpointType::TAINTED_CODE ){
        if( _tainted_code.type != BreakpointType::NONE ){
            throw breakpoint_exception("BreakpointManager::add() cannot add two TAINTED_CODE breakpoints");
        }
        _tainted_code = Breakpoint(t, n, 0, 0, callback, resume);
    }else{
        _breakpoints.push_back(Breakpoint(t, n, v, v2, callback, resume));
    }
    // Increment breakpoints count
    _nb++;
}
#endif


void BreakpointManager::remove(string n){
    bool removed = false;
    if( !_tainted_pc.name.compare(n)){
        removed = true;
        _tainted_pc = Breakpoint();
    }else if( !_path_constraint.name.compare(n)){
        removed = true;
        _path_constraint = Breakpoint();
    }else if( !_tainted_code.name.compare(n)){
        removed = true;
        _tainted_code = Breakpoint();
    }else{
        for( int i = 0; i < _breakpoints.size(); i++){
            if( !_breakpoints[i].name.compare(n)){
                _breakpoints.erase(_breakpoints.begin() + i );
                removed = true;
                break;
            }
        }
    }
    if( removed ){
        _nb--;
    }
}

void BreakpointManager::remove_all(){
    _nb = 0;
    _tainted_pc = Breakpoint();
    _path_constraint = Breakpoint();
    _tainted_code = Breakpoint();
    _breakpoints.clear();
}

inline bool _reads_addr_range(IRInstruction& instr, addr_t lower, addr_t higher, SymbolicEngine& sym, vector<Expr>& tmp_vars ){
    Expr e;
    bool res;
    if( instr.op != IROperation::LDM )
        return false;
    e = _get_operand(instr.src1, sym.regs, tmp_vars);
    res =  ( !e->is_symbolic(*sym.vars)) && 
           (
                ((cst_sign_trunc(e->size, e->concretize(sym.vars)) >= lower) && (cst_sign_trunc(e->size, e->concretize(sym.vars)) <= higher)) || // Lower byte is in the range
                ((cst_sign_trunc(e->size, e->concretize(sym.vars)) + (e->size/8 -1) >= lower) && (cst_sign_trunc(e->size, e->concretize(sym.vars)) + (e->size/8 -1) <= higher)) || // Higher byte is in the range
                ((cst_sign_trunc(e->size, e->concretize(sym.vars)) <= lower) && (cst_sign_trunc(e->size, e->concretize(sym.vars)) + (e->size/8 -1) >= higher))  // Lower byte before the range and higher byte after the range (range included in the mem operation)
                );
    if( res ){
        sym.info.mem_access.addr = e;
        sym.info.mem_access.size = e->size/8;
        sym.info.mem_access.value = sym.mem->read(cst_sign_trunc(e->size, e->concretize(sym.vars)), instr.dst.size/8);
    }
    return res;
}

inline bool _writes_addr_range(IRInstruction& instr, addr_t lower, addr_t higher, SymbolicEngine& sym, vector<Expr>& tmp_vars ){
    Expr e;
    bool res;
    if( instr.op != IROperation::STM )
        return false;
    e = _get_operand(instr.dst, sym.regs, tmp_vars);
    res = ( !e->is_symbolic(*sym.vars)) && 
          (
                ((cst_sign_trunc(e->size, e->concretize(sym.vars)) >= lower) && (cst_sign_trunc(e->size, e->concretize(sym.vars)) <= higher)) || // Lower byte is in the range
                ((cst_sign_trunc(e->size, e->concretize(sym.vars)) + (e->size/8 -1) >= lower) && (cst_sign_trunc(e->size, e->concretize(sym.vars)) + (e->size/8 -1) <= higher)) || // Higher byte is in the range
                ((cst_sign_trunc(e->size, e->concretize(sym.vars)) <= lower) && (cst_sign_trunc(e->size, e->concretize(sym.vars)) + (e->size/8 -1) >= higher))  // Lower byte before the range and higher byte after the range (range included in the mem operation)
                );
    if( res ){
        sym.info.mem_access.addr = e;
        sym.info.mem_access.size = e->size/8;
        sym.info.mem_access.value = _get_operand(instr.src1, sym.regs, tmp_vars);
    }
    return res;
}

bool BreakpointManager::check(SymbolicEngine& sym, IRInstruction& instr, vector<Expr>& tmp_vars ){
    vector<Breakpoint>::iterator it;
    bool res = false;
    Expr cond, if_null, if_not_null;
    if( _breakpoints.size() == 0 ){
        return false;
    }
    for( it = _breakpoints.begin(); it != _breakpoints.end(); it++ ){
        if( sym.breakpoint_record.contains(it->name) ){
            continue;
        }switch(it->type){
            case BreakpointType::ADDR:
                res = (instr.addr >= it->value && instr.addr <= it->value2);
                break;
            case BreakpointType::REGISTER_R:
                res = instr.reads_var((IRVar)it->value);
                break;
            case BreakpointType::REGISTER_W: 
                res = instr.writes_var((IRVar)it->value);
                break;
            case BreakpointType::REGISTER_RW:
                res = instr.uses_var((IRVar)it->value);
                break;
            case BreakpointType::MEMORY_R: 
                res = _reads_addr_range(instr, it->value, it->value2, sym, tmp_vars);
                break;
            case BreakpointType::MEMORY_W:
                res = _writes_addr_range(instr, it->value, it->value2, sym, tmp_vars);
                break;
            case BreakpointType::MEMORY_RW:
                res = _reads_addr_range(instr, it->value, it->value2, sym, tmp_vars) ||
                      _writes_addr_range(instr, it->value, it->value2, sym, tmp_vars);
                break;
            case BreakpointType::BRANCH:
                if( instr.op == IROperation::JCC && instr.src2.is_none()){
                    sym.info.branch = _expand_lvalue(sym.regs->get(sym.arch->pc()), 
                                                    _get_operand(instr.src1, sym.regs, tmp_vars),
                                                    instr.dst.high, instr.dst.low);
                    res = true;
                }
                break;
            case BreakpointType::MULTIBRANCH:
                if( instr.op == IROperation::JCC && !instr.src2.is_none()){
                    if_not_null = _expand_lvalue(sym.regs->get(sym.arch->pc()), 
                                                    _get_operand(instr.src1, sym.regs, tmp_vars),
                                                    instr.dst.high, instr.dst.low);
                    if_null = _expand_lvalue(sym.regs->get(sym.arch->pc()), 
                                                    _get_operand(instr.src2, sym.regs, tmp_vars),
                                                    instr.dst.high, instr.dst.low);
                    cond = _get_operand(instr.dst, sym.regs, tmp_vars);
                    sym.info.multibranch = MultiBranch(cond, if_not_null, if_null);
                    res = true;
                }
                break;
            default:
                throw runtime_exception("BreakpointManager::check(): got unknown BreakpointType");
        }
        if( res )
            break;
    }
    
    if( res ){
        _hit = *it;
        /* Set stop info */
        sym.info.stop = StopInfo::BREAKPOINT;
        sym.info.breakpoint = it->name;
        sym.info.addr = instr.addr;
        /* Log the fact that this breakpoint has been triggered for this instruction */
        if( _breakpoint_is_asmlvl(it->type) ){
            sym.breakpoint_record.add_asmlvl(it->name);    
        }else{
            sym.breakpoint_record.add_irlvl(it->name);
        }
    }
    return res;
}

bool BreakpointManager::check_addr(SymbolicEngine& sym, addr_t addr){
    bool res = false;
    vector<Breakpoint>::iterator it;
    if( _breakpoints.size() == 0 ){
        return false;
    }
    for( it = _breakpoints.begin(); it != _breakpoints.end(); it++ ){
        if( sym.breakpoint_record.contains(it->name) ){
            continue;
        }
        if(     it->type == BreakpointType::ADDR &&
                it->value <= addr && it->value2 >=addr ){
            res = true;
            break;
        }
    }
    
    if( res ){
        _hit = *it;
        /* Set stop info */
        sym.info.stop = StopInfo::BREAKPOINT;
        sym.info.breakpoint = it->name;
        sym.info.addr = addr;
        /* Log the fact that this breakpoint has been triggered for this instruction */
        sym.breakpoint_record.add_asmlvl(it->name);
    }
    return res;
}

bool BreakpointManager::check_pc(SymbolicEngine& sym, Expr pc ){
    if( _tainted_pc.type != BreakpointType::TAINTED_PC )
        return false;
    if( sym.breakpoint_record.contains(_tainted_pc.name) ){
        return false;
    }
    if( pc->is_tainted() ){
        sym.info.stop = StopInfo::BREAKPOINT;
        sym.info.breakpoint = _tainted_pc.name;
        sym.info.addr = cst_sign_trunc(sym.arch->bits, sym.regs->concretize(sym.arch->pc())); 
        /* Log the fact that this breakpoint has been triggered for this instruction */
        sym.breakpoint_record.add_irlvl(_tainted_pc.name);
        _hit = _tainted_pc;
        return true;
    }else{
        return false;
    }
}

bool BreakpointManager::check_path(SymbolicEngine& sym, IRInstruction& instr, vector<Expr>& tmp_vars ){
    Expr cond;
    if( _path_constraint.type == BreakpointType::PATH_CONSTRAINT){
        if(     (instr.op == IROperation::JCC || instr.op == IROperation::BCC) &&
                !sym.breakpoint_record.contains(_path_constraint.name) ){
            cond = _get_operand(instr.dst, sym.regs, tmp_vars);
            if( cond->is_tainted() ){
                if( sym.is_enabled(SymbolicEngineOption::SIMPLIFY_CONSTRAINTS) ){
                    cond = sym.simplifier->simplify(cond);
                }
                if( !cond->is_tainted() ){
                    // If condition not tainted anymore after simplification, no break
                    return false;
                }
                /* Add path constraint if branch condition is tainted */
                if( cond->concretize(sym.vars) != 0 ){
                    sym.info.path_constraint = (cond != exprcst(cond->size, 0));
                }else{
                    sym.info.path_constraint = (cond == exprcst(cond->size, 0));
                }
                _hit = _path_constraint;
                sym.info.stop = StopInfo::BREAKPOINT;
                sym.info.addr = instr.addr;
                sym.info.breakpoint = _path_constraint.name;
                sym.breakpoint_record.add_irlvl(_path_constraint.name);
                return true;
            }
        }
    }
    return false;
}

/* This breakpoint doesn't actually checks anything, just triggers if the 
 _tainted_code breakpoint is set. That's because this function is called 
  by the symbolic engine only when tainted code has already been detected :)
*/
bool BreakpointManager::check_tainted_code(SymbolicEngine& sym, addr_t addr){
    if( _tainted_code.type == BreakpointType::TAINTED_CODE ){
        sym.info.addr = addr;
        sym.info.stop = StopInfo::BREAKPOINT;
        sym.info.breakpoint = _tainted_code.name;
        _hit = _tainted_code;
        sym.breakpoint_record.add_asmlvl(_tainted_code.name);
        return true;
    }
    return false;
}

/* ===================================== */
void BreakpointRecord::add_irlvl(string name){ irlvl_names.push_back(name); }
void BreakpointRecord::add_asmlvl(string name){ asmlvl_names.push_back(name); }
void BreakpointRecord::clear_asmlvl(){
    irlvl_names.clear();
    asmlvl_names.clear();
}
void BreakpointRecord::clear_irlvl(){
    irlvl_names.clear();
}
bool BreakpointRecord::contains(string& val){
    return std::find(irlvl_names.begin(), irlvl_names.end(), val ) != irlvl_names.end() || 
           std::find(asmlvl_names.begin(), asmlvl_names.end(), val ) != asmlvl_names.end();
}
