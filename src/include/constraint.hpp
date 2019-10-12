#ifndef CONSTRAINT_H
#define CONSTRAINT_H

#include "expression.hpp"

enum class ConstraintType{
    /* Logical combination */
    AND,
    OR,
    /* Arithmetic constraints */
    EQ,
    NEQ,
    LE,
    LT
};

/* Forward declarations */
class ConstraintObject;
typedef shared_ptr<ConstraintObject> Constraint;

/* Constraint class: constraints between expressions */
class ConstraintObject{
public:
    ConstraintType type;
    Expr left_expr;
    Expr right_expr;
    Constraint left_constr;
    Constraint right_constr;
    ConstraintObject(ConstraintType t, Expr l, Expr r);
    ConstraintObject(ConstraintType t, Constraint l, Constraint r);
    Constraint invert();
};

ostream& operator<<(ostream& os, Constraint& constr);

/* Operators overloading */
Constraint operator==(Expr left, Expr right);
Constraint operator==(Expr left, cst_t right);
Constraint operator==(cst_t left, Expr right);

Constraint operator!=(Expr left, Expr right);
Constraint operator!=(Expr left, cst_t right);
Constraint operator!=(cst_t left, Expr right);

Constraint operator<=(Expr left, Expr right);
Constraint operator<=(Expr left, cst_t right);
Constraint operator<=(cst_t left, Expr right);

Constraint operator<(Expr left, Expr right);
Constraint operator<(Expr left, cst_t right);
Constraint operator<(cst_t left, Expr right);

Constraint operator>=(Expr left, Expr right);
Constraint operator>=(Expr left, cst_t right);
Constraint operator>=(cst_t left, Expr right);

Constraint operator>(Expr left, Expr right);
Constraint operator>(Expr left, cst_t right);
Constraint operator>(cst_t left, Expr right);

Constraint operator&&(Constraint left, Constraint right);

Constraint operator||(Constraint left, Constraint right);
#endif
