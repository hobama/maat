#include "constraint.hpp"
#include "exception.hpp"
#include <iostream>

using std::make_shared;

ConstraintObject::ConstraintObject(ConstraintType t, Expr l, Expr r):type(t), left_expr(l), right_expr(r), left_constr(nullptr), right_constr(nullptr){
    Expr bisz, cst;
    int mode;
    if( l->size != r->size ){
        throw constraint_exception(ExceptionFormatter() << "Can not create arithmetic constraint with expressions of different sizes (got " << l->size << " and " << r->size << ")" >> ExceptionFormatter::to_str);
    }
    /* Make some transformations to have clearer constraints */
    // Tweak constraints with bisz
    if( l->type == ExprType::BISZ && r->type == ExprType::CST ){
        bisz = l;
        cst = r;
    }else if( r->type == ExprType::BISZ && l->type == ExprType::CST) {
        bisz = r;
        cst = l;
    }else{
        return;
    }
    mode = bisz->mode();
    if( type == ConstraintType::NEQ ){
        // Set mode as if the constraint was == (to avoid a huge switch case after)
        mode ^= 1;
    }else if( type != ConstraintType::EQ ){
        return;
    }
    if( mode == 1 ){
        if( cst->cst() == 0 ){
            // bisz<1>(a) == 0  <==> a != 0 
            left_expr = bisz->args[0];
            right_expr = exprcst(left_expr->size, 0);
            type = ConstraintType::NEQ;
        }else if( cst->cst() == 1 ){
            // bisz<1>(a) == 1  <==> a == 0 
            left_expr = bisz->args[0];
            right_expr = exprcst(left_expr->size, 0);
            type = ConstraintType::EQ;
        }
    }else{
        if( cst->cst() == 0 ){
            // bisz<0>(a) == 0  <==> a == 0 
            left_expr = bisz->args[0];
            right_expr = exprcst(left_expr->size, 0);
            type = ConstraintType::EQ;
        }else if( cst->cst() == 1 ){
            // bisz<0>(a) == 1  <==> a != 0 
            left_expr = bisz->args[0];
            right_expr = exprcst(left_expr->size, 0);
            type = ConstraintType::NEQ;
        }
    }
}

ConstraintObject::ConstraintObject(ConstraintType t, Constraint l, Constraint r):type(t), left_expr(nullptr), right_expr(nullptr), left_constr(l), right_constr(r){}

Constraint ConstraintObject::invert(){
    switch(type){
        case ConstraintType::AND:
            return left_constr->invert() || right_constr->invert();
        case ConstraintType::OR:
            return left_constr->invert() && right_constr->invert();
        case ConstraintType::EQ:
            return left_expr != right_expr;
        case ConstraintType::NEQ:
            return left_expr == right_expr;
        case ConstraintType::LE:
            return left_expr > right_expr;
        case ConstraintType::LT:
            return left_expr >= right_expr;
        default:
            throw runtime_exception("ConstraintObject::invert() got unknown constraint type");
    }
}

ostream& operator<<(ostream& os, Constraint& constr){
    switch(constr->type){
        case ConstraintType::AND:
            os << "(" << constr->left_constr << " && " << constr->right_constr << ")"; break;
        case ConstraintType::OR:
            os << "(" << constr->left_constr << " || " << constr->right_constr << ")"; break;
        case ConstraintType::EQ:
            os << "(" << constr->left_expr << " == " << constr->right_expr << ")"; break;
        case ConstraintType::NEQ:
            os << "(" << constr->left_expr << " != " << constr->right_expr << ")"; break;
        case ConstraintType::LE:
            os << "(" << constr->left_expr << " <= " << constr->right_expr << ")"; break;
        case ConstraintType::LT:
            os << "(" << constr->left_expr << " < " << constr->right_expr << ")"; break;
        default:
            throw runtime_exception("operator<<(ostream&, Constraint): got unknown ConstraintType");
    }
    return os;
}

Constraint operator==(Expr left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::EQ, left, right);
}
Constraint operator==(Expr left, cst_t right){
    return make_shared<ConstraintObject>(ConstraintType::EQ, left, exprcst(left->size,right));
}
Constraint operator==(cst_t left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::EQ, exprcst(right->size, left), right);
}

Constraint operator!=(Expr left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::NEQ, left, right);
}
Constraint operator!=(Expr left, cst_t right){
    return make_shared<ConstraintObject>(ConstraintType::NEQ, left, exprcst(left->size,right));
}
Constraint operator!=(cst_t left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::NEQ, exprcst(right->size, left), right);
}

Constraint operator<=(Expr left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::LE, left, right);
}
Constraint operator<=(Expr left, cst_t right){
    return make_shared<ConstraintObject>(ConstraintType::LE, left, exprcst(left->size,right));
}
Constraint operator<=(cst_t left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::LE, exprcst(right->size, left), right);
}

Constraint operator<(Expr left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::LT, left, right);
}
Constraint operator<(Expr left, cst_t right){
    return make_shared<ConstraintObject>(ConstraintType::LT, left, exprcst(left->size,right));
}
Constraint operator<(cst_t left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::LT, exprcst(right->size, left), right);
}

Constraint operator>=(Expr left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::LE, right, left);
}
Constraint operator>=(Expr left, cst_t right){
    return make_shared<ConstraintObject>(ConstraintType::LE, exprcst(left->size,right), left);
}
Constraint operator>=(cst_t left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::LE, right, exprcst(right->size, left));
}

Constraint operator>(Expr left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::LT, right, left);
}
Constraint operator>(Expr left, cst_t right){
    return make_shared<ConstraintObject>(ConstraintType::LT, exprcst(left->size,right), left);
}
Constraint operator>(cst_t left, Expr right){
    return make_shared<ConstraintObject>(ConstraintType::LT, right, exprcst(right->size, left));
}

Constraint operator&&(Constraint left, Constraint right){
    return make_shared<ConstraintObject>(ConstraintType::AND, left, right);
}

Constraint operator||(Constraint left, Constraint right){
    return make_shared<ConstraintObject>(ConstraintType::OR, left, right);
}
