#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include "exception.hpp"
#include "expression.hpp"
#include "solver.hpp"
#include <iomanip>

#ifdef Z3_BACKEND
#include "z3++.h"
#endif

using std::cout;
using std::endl; 
using std::string;


/* Forward declaration*/
#ifdef Z3_BACKEND
z3::expr expr_to_z3(z3::context* c, Expr e);
#endif

namespace test{
    namespace solver{
#ifdef HAS_SOLVER_BACKEND
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }

        unsigned int unsat_constraints(Solver& s){
            unsigned int nb = 0;
            Expr e1, e2, e3, e4;
            e1 = exprvar(64, "var1");
            e2 = exprvar(64, "var2");
            e3 = exprvar(64, "var3");
            e4 = exprvar(64, "var4");
            
            s.reset();
            s.add(e1 == e2 && e2 == e3 && e3 == e4 && e1 != e4);
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add(e1 == exprcst(64, 1) && e2 == e1 && e2 != exprcst(64, 1));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add(e1 > exprcst(64, 3) && e2 == e1 && e2 < exprcst(64, -10));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add(e1 + e2 > e3 && e1 + e2 < e3);
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( e1 + exprcst(64, 2) < exprcst(64, 10) && ( e1 + exprcst(64, 4) > exprcst(64, 16)));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( e1 == exprcst(64, 0) && extract(e1, 15, 0) != exprcst(16, 0));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( bisz(32, e1, 1) == exprcst(32,0) && e1 == exprcst(64,0));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( e1 == bisz(64, e1, 1));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( bisz(64, e1, 1) == exprcst(64, 3));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            s.reset();
            s.add( shl(e1, e2) != exprcst(64, 0) );
            s.add( e2 >= exprcst(64, 64) );
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            
            
            s.reset();
            s.add( (exprcst(64, 0x8000) << e1) < (exprcst(64, 0x8000) >> e2 ) );
            s.add( e1 < exprcst(64, 8) && (e1 > exprcst(64, 0)));
            s.add( e2 < exprcst(64, 9) && (e2 > exprcst(64, 0)));
            nb += _assert(!s.check(), "Solver: got model for unsat constraint ! ");
            return nb;
        }
        
        unsigned int sat_constraints(Solver& s){
            unsigned int nb = 0;
            VarContext* model;
            Expr e1, e2, e3, e4;
            e1 = exprvar(32, "var1");
            e2 = exprvar(32, "var2");
            e3 = exprvar(32, "var3");
            e4 = exprvar(32, "var4");
            
            s.reset();
            s.add(e1 * e2 == exprcst(32, 0x78945));
            s.add(e1 - e3 == exprcst(32, 0x2));
            s.add(e3 > e4 );
            s.add(e3 / exprcst(32, 10) < e4);
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert((e1*e2)->concretize(model) == 0x78945, "Solver: got wrong model ! "); 
            nb += _assert((e1-e3)->concretize(model) == 2, "Solver: got wrong model ! ");
            nb += _assert((e3)->concretize(model) > e4->concretize(model), "Solver: got wrong model ! ");
            nb += _assert((e3->concretize(model))/10 < e4->concretize(model), "Solver: got wrong model ! ");
            delete model;
            
            s.reset();
            s.add(e1 << e2 == exprcst(32, 0x789000));
            s.add(e2 >> e3 == exprcst(32, 11));
            s.add(e1 * e4 == exprcst(32, 0x789000));
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert((e1<<e2)->concretize(model) == 0x789000, "Solver: got wrong model ! "); 
            nb += _assert((e2>>e3)->concretize(model) == 11, "Solver: got wrong model ! ");
            nb += _assert((e1*e4)->concretize(model) == 0x789000, "Solver: got wrong model ! ");
            delete model;
            
            /* Comment it because too slow
            s.reset();
            s.add(smulh(e1,e2) == exprcst(32, 0x1234));
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert((uint32_t)smulh(e1,e2)->concretize(model) == 0x1234, "Solver: got wrong model ! ");
            delete model; */
            
            s.reset();
            s.add(bisz(16, e1, 1) == exprcst(16, 0x1));
            s.add((e1|e2) > exprcst(32, 0x798424));
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert((uint16_t)bisz(16, e1, 1)->concretize(model) == 0x1, "Solver: got wrong model ! "); 
            nb += _assert((e1|e2)->concretize(model) > 0x798424, "Solver: got wrong model ! ");
            delete model;
            
            s.reset();
            s.add(smod(e1,e2) == exprcst(32, -8));
            s.add((e2*e3) == exprcst(32, 10));
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert(smod(e1, e2)->concretize(model) == -8, "Solver: got wrong model ! "); 
            nb += _assert((e3*e2)->concretize(model) == 10 , "Solver: got wrong model ! ");
            delete model;
            
            s.reset();
            s.add(e1 == (e2^exprcst(32, 0x11010101))
            );
            s.add((e1 * exprcst(32, 8) ^ (e1 >> exprcst(32, 2))) == e3);
            s.add((e3 ^ exprcst(32, 0x10110001)) == exprcst(32, 0x853ea65f));
            nb += _assert(s.check(), "Solver: got no model for sat constraint ! ");
            model = s.get_model();
            nb += _assert(e1->concretize(model) == (e2^exprcst(32, 0x11010101))->concretize(model), "Solver: got wrong model ! "); 
            nb += _assert((uint32_t)(e3^exprcst(32, 0x10110001))->concretize(model) == 0x853ea65f , "Solver: got wrong model ! ");
            delete model;
            
            
            return nb;
        }
#endif
    }
}

using namespace test::solver;
// All unit tests 
void test_solver(){
#ifdef HAS_SOLVER_BACKEND 
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing solver interface... " << std::flush;  
    Solver* s = NewSolver();
    total += unsat_constraints(*s);
    total += sat_constraints(*s);
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
#endif
}
