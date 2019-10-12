#ifndef SOLVER_H
#define SOLVER_H

#include "constraint.hpp"
#include "expression.hpp"
#include <vector>
#include "constraint.hpp"

#ifdef Z3_BACKEND
#include "z3++.h"
#endif

class Solver{
friend class Z3Solver;
    vector<Constraint> _constraints;
    vector<unsigned int> _snapshots;
    int _model_id;
    VarContext* _varctx; // Not owned !
public:
    Solver(VarContext* varctx=nullptr){};
    ~Solver(){};
    virtual void reset() = 0;
    virtual void add(Constraint constr) = 0;
    virtual unsigned int snapshot() = 0;
    virtual void restore(unsigned int snapshot_id) = 0;
    virtual bool check(VarContext * varctx = nullptr) = 0;
    virtual VarContext* get_model() = 0;
};

Solver* NewSolver(VarContext* varctx=nullptr);

#ifdef Z3_BACKEND
class Z3Solver: public Solver{
public:
    z3::context* ctx;
    z3::solver* sol;
    Z3Solver(VarContext* varctx=nullptr);
    ~Z3Solver();
    void reset();
    void add(Constraint constr);
    unsigned int snapshot();
    void restore(unsigned int snapshot_id);
    bool check(VarContext* varctx=nullptr);
    VarContext* get_model();
};
#endif

#endif
