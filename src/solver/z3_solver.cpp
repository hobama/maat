#ifdef Z3_BACKEND
#include "solver.hpp"
#include "exception.hpp"

using namespace z3;

/* =========================================
 * Translations from maat to z3 expressions 
 * ========================================= */
z3::expr expr_to_z3_no_opt(z3::context* c, Expr e){
    switch(e->type){
        case ExprType::CST: return c->bv_val(cst_sign_trunc(e->size, e->cst()), e->size);
        case ExprType::VAR: return c->bv_const(e->name().c_str(), e->size);
        case ExprType::BINOP:
            switch(e->op()){
                case Op::ADD: return expr_to_z3_no_opt(c, e->args[0]) + expr_to_z3_no_opt(c, e->args[1]);
                case Op::MUL: 
                case Op::SMULL: return expr_to_z3_no_opt(c, e->args[0]) * expr_to_z3_no_opt(c, e->args[1]);
                case Op::MULH: return ( z3::zext(expr_to_z3_no_opt(c, e->args[0]), e->size)*z3::zext(expr_to_z3_no_opt(c, e->args[1]), e->size))
                                .extract(e->size*2 - 1, e->size); 
                case Op::SMULH: return ( z3::sext(expr_to_z3_no_opt(c, e->args[0]), e->size)*z3::sext(expr_to_z3_no_opt(c, e->args[1]), e->size))
                                .extract(e->size*2 - 1, e->size); 
                case Op::DIV: return z3::udiv(expr_to_z3_no_opt(c, e->args[0]), expr_to_z3_no_opt(c, e->args[1]));
                case Op::SDIV: return expr_to_z3_no_opt(c, e->args[0]) / expr_to_z3_no_opt(c, e->args[1]);
                case Op::MOD: return z3::mod(expr_to_z3_no_opt(c, e->args[0]), expr_to_z3_no_opt(c, e->args[1]));
                case Op::SMOD: return z3::srem(expr_to_z3_no_opt(c, e->args[0]), expr_to_z3_no_opt(c, e->args[1]));
                case Op::SHL: return z3::shl(expr_to_z3_no_opt(c, e->args[0]), expr_to_z3_no_opt(c, e->args[1]));
                case Op::SHR: return z3::lshr(expr_to_z3_no_opt(c, e->args[0]), expr_to_z3_no_opt(c, e->args[1])); 
                case Op::AND: return expr_to_z3_no_opt(c, e->args[0]) & expr_to_z3_no_opt(c, e->args[1]);
                case Op::OR: return expr_to_z3_no_opt(c, e->args[0]) | expr_to_z3_no_opt(c, e->args[1]);
                case Op::XOR: return expr_to_z3_no_opt(c, e->args[0]) ^ expr_to_z3_no_opt(c, e->args[1]);
                default:
                    throw runtime_exception("expr_to_z3_no_opt() got unsupported operation");
            }
        case ExprType::UNOP:
            switch(e->op()){
                case Op::NEG: return -expr_to_z3_no_opt(c, e->args[0]);
                case Op::NOT: return ~expr_to_z3_no_opt(c, e->args[0]);
                default:
                    throw runtime_exception("expr_to_z3_no_opt() got unsupported operation");
            }
        case ExprType::CONCAT:
            return z3::concat(expr_to_z3_no_opt(c, e->args[0]), expr_to_z3_no_opt(c, e->args[1]));
        case ExprType::EXTRACT:
            return expr_to_z3_no_opt(c, e->args[0]).extract(e->args[1]->cst(), e->args[2]->cst());
        case ExprType::BISZ:
            return z3::ite(expr_to_z3_no_opt(c, e->args[0]) == 0, c->bv_val(e->mode(), e->size), c->bv_val(1-e->mode(), e->size));
        default: throw runtime_exception("expr_to_z3_no_opt() got unsupported ExprType");
    }
}


z3::expr expr_to_z3(z3::context* c, Expr e, VarContext* ctx=nullptr){
    /* If expression is concrete, concretize it ! No need to add more
     * complexity to the solver */
    if( ctx != nullptr && !e->is_symbolic(*ctx) && !e->is_tainted()){
        return c->bv_val(cst_sign_trunc(e->size, e->concretize(ctx)), e->size);
    }else{
        return expr_to_z3_no_opt(c, e);
    }
}

z3::expr constr_to_z3(z3::context* c, Constraint& constr, VarContext* varctx=nullptr){
    switch(constr->type){
        case ConstraintType::AND: return constr_to_z3(c, constr->left_constr) && constr_to_z3(c, constr->right_constr);
        case ConstraintType::OR: return constr_to_z3(c, constr->left_constr) || constr_to_z3(c, constr->right_constr);
        case ConstraintType::EQ: return expr_to_z3(c, constr->left_expr) == expr_to_z3(c, constr->right_expr);
        case ConstraintType::NEQ: return expr_to_z3(c, constr->left_expr) != expr_to_z3(c, constr->right_expr);
        case ConstraintType::LE: return expr_to_z3(c, constr->left_expr) <= expr_to_z3(c, constr->right_expr);
        case ConstraintType::LT: return expr_to_z3(c, constr->left_expr) < expr_to_z3(c, constr->right_expr);
        default:
            throw runtime_exception("constr_to_z3() got unsupported ConstraintType");
    }
}

/* ========================================
 * Solver with Z3 backend
 * ======================================== */ 

Solver* NewSolver(VarContext* varctx){
    return new Z3Solver(varctx);
}

Z3Solver::Z3Solver(VarContext* varctx){
    ctx = new z3::context();
    sol = new z3::solver(*ctx);
    _model_id = 0x80000000;
    _varctx = varctx;
}

Z3Solver::~Z3Solver(){
    delete sol;
    sol = nullptr;
    delete ctx;
    ctx = nullptr;
}
void Z3Solver::reset(){
    sol->reset();
    _constraints.clear();
}
void Z3Solver::add(Constraint constr){
    /* Add the constraint */
    _constraints.push_back(constr);
}
unsigned int Z3Solver::snapshot(){
    return 0;
}
void Z3Solver::restore(unsigned int snapshot_id){
    return;
}
bool Z3Solver::check(VarContext* varctx){
    if( varctx == nullptr )
        varctx = _varctx;
    sol->reset();
    for( auto constr : _constraints ){
        /* Add constraints in the solver */
        sol->add(constr_to_z3(ctx, constr, varctx));
    }
    return sol->check() == z3::check_result::sat;
}

VarContext* Z3Solver::get_model(){
    if( sol->check() != z3::check_result::sat )
        return nullptr;
    z3::model m = sol->get_model();
    VarContext* res = new VarContext(_model_id++);
    for( int i = 0; i < m.num_consts(); i++ ){
        res->set(m[i].name().str(), cst_sign_extend( Z3_get_bv_sort_size(*ctx, m.get_const_interp(m[i]).get_sort()), m.get_const_interp(m[i]).get_numeral_uint64()));
    }
    return res;
}
#endif
