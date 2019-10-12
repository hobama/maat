#include "expression.hpp"
#include "simplification.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

using std::cout;
using std::endl; 
using std::string;

namespace test{
    namespace simplification{        
        unsigned int _assert_simplify(Expr e1, Expr e2, ExprSimplifier& simp){
            Expr tmp1 = simp.simplify(e1);
            Expr tmp2 = simp.simplify(e2);
            if( tmp1->neq(tmp2) ){
                cout << "\nFail: _assert_simplify: " << e1 << " => " << e2 << endl
                << "Note: instead simplified into " << tmp1 << " => " << tmp2 << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int basic(ExprSimplifier& s){
            Expr e1 = exprvar(32,"varA");
            return 0;
        }
        
        unsigned int const_folding(ExprSimplifier& s){
            unsigned int nb = 0;
            Expr e1 = exprcst(32,-1), e2 =exprcst(32, 1048567);
            nb += _assert_simplify(exprcst(16,2)+exprcst(16,4), exprcst(16,6), s);
            nb += _assert_simplify(exprcst(4,3)*exprcst(4,7),  exprcst(4, 5), s);
            nb += _assert_simplify(exprcst(8,0xc3)/exprcst(8,0x40),  exprcst(8, 3), s);
            nb += _assert_simplify(exprcst(16, 321)/exprcst(16, 40), exprcst(16, 321U/40U), s);
            nb += _assert_simplify(sdiv(exprcst(16, 567),exprcst(16, 56)), exprcst(16, 567/56), s);
            nb += _assert_simplify(exprcst(16, 0x2)&exprcst(16, 0x1234), exprcst(16, 0x2&0x1234), s);
            nb += _assert_simplify(exprcst(16, 0x2)|exprcst(16, 0x1234), exprcst(16, 0x2|0x1234), s);
            nb += _assert_simplify(exprcst(16, 0x2)^exprcst(16, 0x1234), exprcst(16, 0x2^0x1234), s);
            nb += _assert_simplify(shl(exprcst(16, 1),exprcst(16, 4)), exprcst(16, 16), s);
            nb += _assert_simplify(shr(exprcst(16, 16),exprcst(16, 4)), exprcst(16, 1), s);
            nb += _assert_simplify(shl(exprcst(16, 1), exprcst(16, 16)), exprcst(16,0), s);
            
            nb += _assert_simplify(extract(exprcst(8, 20), 4, 2), exprcst(3, 5), s);
            nb += _assert_simplify(concat(exprcst(8, 1), exprcst(4, -1)), exprcst(12, 0x1f), s);
            
            nb += _assert_simplify(-exprcst(7,3),  exprcst(7, -3), s);
            nb += _assert_simplify(~exprcst(7,3),  exprcst(7, ~3), s);
            
            nb += _assert_simplify(e2+e1-e1, e2, s);
            
            nb += _assert_simplify(bisz(32, e1, 1), exprcst(32, 0), s);
            nb += _assert_simplify(bisz(23, exprcst(32,0), 1), exprcst(23, 1), s);
            
            return nb; 
        }
        unsigned int neutral_elems(ExprSimplifier& s){
            unsigned int nb = 0;
            nb += _assert_simplify(exprvar(32,"var1")+exprcst(32, 0), exprvar(32, "var1"), s);
            nb += _assert_simplify(exprvar(32,"var1")*exprcst(32, 1), exprvar(32, "var1"), s);
            nb += _assert_simplify(exprvar(32,"var1")/exprcst(32, 1), exprvar(32, "var1"), s);
            nb += _assert_simplify(sdiv(exprvar(32,"var1"),exprcst(32, 1)), exprvar(32, "var1"), s);
            nb += _assert_simplify(exprvar(7,"var1")&exprcst(7, 0b1111111), exprvar(7, "var1"), s);
            nb += _assert_simplify(exprvar(6,"var1")|exprcst(6, 0), exprvar(6, "var1"), s);
            nb += _assert_simplify(exprvar(32,"var1")^exprcst(32, 0), exprvar(32, "var1"), s);
            nb += _assert_simplify(extract(exprvar(32,"var1"), 31, 0), exprvar(32, "var1"), s);
            return nb; 
        }
        
        unsigned int absorbing_elems(ExprSimplifier& s){
            unsigned int nb = 0;
            nb += _assert_simplify(exprvar(33,"var1")*exprcst(33,0), exprcst(33,0), s);
            nb += _assert_simplify(exprvar(6, "var1")|exprcst(6,0b111111), exprcst(6,0b111111), s);
            nb += _assert_simplify(exprvar(5,"var1")&exprcst(5,0), exprcst(5,0), s);
            nb += _assert_simplify(shl(exprvar(32,"var1"),exprcst(32, 50)), exprcst(32,0), s);
            nb += _assert_simplify(shr(exprvar(32,"var1"),exprcst(32, 32)), exprcst(32,0), s);
            return nb; 
        }
        
        unsigned int arithmetic_properties(ExprSimplifier& s){
            unsigned int nb = 0;
            Expr    e1 = exprvar(64, "var1"),
                    e2 = exprvar(64, "var2"),
                    e3 = exprvar(64, "var3"),
                    e4 = e1/e2,
                    c1 = exprcst(64, 1);
            nb += _assert_simplify( e1+(e1*e2), (e2+c1)*e1, s);
            nb += _assert_simplify( (e2*e1)+e1, (e2+c1)*e1, s);
            nb += _assert_simplify( (e1*e2)-e1, (e2-c1)*e1, s);
            nb += _assert_simplify( (e2*e1)-e1, (e2-c1)*e1, s);
            nb += _assert_simplify( (e1*e3)+(e2*e3), (e1+e2)*e3 , s);
            nb += _assert_simplify( (e3*e1)+(e2*e3), (e1+e2)*e3 , s);
            nb += _assert_simplify( (e1*e3)+(e3*e2), (e1+e2)*e3 , s);
            nb += _assert_simplify( (e3*e1)+(e3*e2), (e1+e2)*e3 , s);
            nb += _assert_simplify( (e4+(e4*e3)), (e3+c1)*e4, s);
            nb += _assert_simplify( (e4+(e3*e4)), (e3+c1)*e4, s);
            nb += _assert_simplify( (-e4+(e4*e3)), (e3-c1)*e4, s);
            nb += _assert_simplify( (-e4+(e3*e4)), (e3-c1)*e4, s);
            nb += _assert_simplify( (e4+e4) , e4*exprcst(64, 2), s); 
            nb += _assert_simplify( e4-e4, exprcst(64,0), s);
            nb += _assert_simplify( -e3+e3, exprcst(64,0), s);
            return nb; 
        }
        
        unsigned int involution(ExprSimplifier& s){
            unsigned int nb = 0;
            nb += _assert_simplify( -(-exprvar(64, "var1")), exprvar(64, "var1"), s);
            nb += _assert_simplify( ~~exprvar(64, "var1"), exprvar(64, "var1"), s);
            return nb; 
        }
        
        unsigned int extract_patterns(ExprSimplifier& s){
            unsigned int nb = 0;
            Expr e1 = exprvar(32,"var1"), e2 = exprvar(14, "var2"); 
            Expr e = concat(e1, e2);
            nb += _assert_simplify(extract(e, 45, 40), extract(e1, 31, 26), s);
            nb += _assert_simplify(extract(e, 8, 1), extract(e2, 8, 1), s);
            nb += _assert_simplify(extract(extract(e1, 28,10),8,1), extract(e1, 18,11), s);
            nb += _assert_simplify(extract(extract(exprcst(64,0xffffff), 31,0),10,10), 
                                   extract(exprcst(64,0xffffff), 10,10), s);
            return nb; 
        }
        
        unsigned int basic_transform(ExprSimplifier& s){
            unsigned int nb = 0;
            Expr e1 = exprvar(56, "var1");
            Expr e2 = exprmem(56, e1); 
            nb += _assert_simplify(shl(e1, exprcst(56, 3)), e1*exprcst(56, 8), s);
            nb += _assert_simplify(shr(e1, exprcst(56, 4)), e1/exprcst(56, 16), s);
            nb += _assert_simplify(exprcst(56, -1)*e1, -e1, s);
            nb += _assert_simplify((~e1)+exprcst(56,1), -e1, s);
            nb += _assert_simplify((~(-e1))+exprcst(56,1), e1, s);
            nb += _assert_simplify(e1*(-e2), -(e2*e1), s);
            nb += _assert_simplify((-e1)*e2, -(e2*e1), s);
            return nb; 
        }
        
        unsigned int logical_properties(ExprSimplifier& s){
            unsigned int nb = 0;
            Expr e = exprvar(64, "var1");
            nb += _assert_simplify(e&e, e, s);
            nb += _assert_simplify(e|e, e, s);
            nb += _assert_simplify(e&(~e), exprcst(64,0), s);
            nb += _assert_simplify((~e)&e, exprcst(64,0), s);
            nb += _assert_simplify((~e)^e, exprcst(64,-1), s);
            nb += _assert_simplify(e^(~e), exprcst(64,-1), s);
            nb += _assert_simplify((~e)|e, exprcst(64,-1), s);
            nb += _assert_simplify(e|(~e), exprcst(64,-1), s);
            nb += _assert_simplify(e^e, exprcst(64,0), s);
            return nb; 
        }
        
        unsigned int concat_patterns(ExprSimplifier& s){
            unsigned int nb = 0;
            Expr e = exprvar(64, "var1");
            Expr    v1 = exprvar(8, "a"),
                    c1 = exprcst(24, 0x100c3);
            Expr e1 = concat(v1, c1);
            nb += _assert_simplify(concat(extract(e, 63,10), extract(e,9,0)), e, s);
            nb += _assert_simplify(extract( concat(extract(e1, 31, 8), extract(e1, 7, 0)>>6), 7, 0) - 3,   (extract(e1, 7, 0)>>6)-3, s);
            return nb; 
        }
        
        unsigned int advanced(ExprSimplifier& s){
            unsigned int nb = 0; 
            Expr    e1 = exprvar(32,"varA"),
                    e2 = exprvar(32,"varB"),
                    e3 = exprcst(32, -1), 
                    e4 = exprcst(32, 0xffff7),
                    e5 = e3+e4, 
                    e6 = e4/e1,
                    e7 = shr(e5,exprcst(32, 1)),
                    e8 = exprmem(32, e3),
                    e9 = concat(extract(e1, 31, 16), extract(e4, 15, 0));
            
            nb += _assert_simplify(((e1-e2)*e6)^e8, e8^((e1-e2+e2-e2)*(e6&e6)), s);
            nb += _assert_simplify(e1+e2+e3-e1+e4-e2-e3, e4, s);
            nb += _assert_simplify(e3*e4, exprcst(32, 0xfffffffffff00009), s);
            nb += _assert_simplify(e4*e4, exprcst(32, 0xfffee00051), s);
            nb += _assert_simplify(exprcst(32, 0xfffee00051)*e3, exprcst(32, 0xffffff00011fffaf), s);
            nb += _assert_simplify(e4*(e3-e3+e4)*e3, e4*e3*e4, s);
            nb += _assert_simplify(e3*e4*(e1+e2+e3-e1+e4-e2-e3), e4*e4*e3, s);
            nb += _assert_simplify(e2/(e1+e1-e1), e2/e1, s);
            nb += _assert_simplify(e8, e8+e5-e5, s);
            nb += _assert_simplify((e6/e1/e8), (e6/(e8+e5-e5)/e1), s);
            nb += _assert_simplify((e6/e7/e8), (e6/(e8+e5-e5)/e7), s);
            nb += _assert_simplify(e9|e9, e9, s);
            nb += _assert_simplify((e2&(~e1))&e1, exprcst(32,0), s);
            //nb += _assert_simplify(extract(e8^(e9^~e8), 31, 0), e8&(-e6+(e9|e9)+e6) , s);
            /*nb += _assert_simplify(, , s);
            nb += _assert_simplify(, , s);
            nb += _assert_simplify(, , s);
            nb += _assert_simplify(, , s);*/
            //nb += _assert_simplify(, , s);
            return nb; 
        }
        
        unsigned int taint_preservation(ExprSimplifier& s){
            unsigned int nb = 0;
            Expr c1 = exprcst(32, 23);
            Expr c2 = exprcst(32, 0);
            Expr c3 = exprcst(32, 0x67, Taint::TAINTED);
            Expr c4 = exprcst(32, 1, Taint::TAINTED);
            
            nb += _assert( s.simplify(c2+c3-c2)->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( s.simplify((c2/c4)-c1)->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( s.simplify(~c4)->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( s.simplify(-c3)->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( s.simplify(bisz(1, c3, 1))->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( s.simplify(extract(c4, 12, 12))->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( s.simplify(concat(c1, c3))->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            
            nb += _assert( !s.simplify(c2+c1-c2)->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( !s.simplify((c2/c1)-c1)->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( !s.simplify(~c2)->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( !s.simplify(-c1)->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( !s.simplify(bisz(1, c1, 1))->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( !s.simplify(extract(c2, 12, 12))->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            nb += _assert( !s.simplify(concat(c1, c2))->is_tainted(), "Simplification: failed to propagate taint on constant folding");
            
            return nb;
            
        }
    }
}

using namespace test::simplification;
// All unit tests 
void test_simplification(){
    ExprSimplifier simp = ExprSimplifier();
    simp.add(es_constant_folding);
    simp.add(es_neutral_elements);
    simp.add(es_absorbing_elements);
    simp.add(es_arithmetic_properties);
    simp.add(es_involution);
    simp.add(es_extract_patterns);
    simp.add(es_basic_transform);
    simp.add(es_logical_properties);
    simp.add(es_concat_patterns);
    simp.add(es_arithmetic_factorize);
    //simp.add(es_generic_distribute);
    simp.add(es_generic_factorize);
    simp.add(es_deep_associative);
    
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << " Testing simplification module... " << std::flush;
    for( int i = 0; i < 1; i++){
        total += basic(simp);
        total += const_folding(simp);
        total += neutral_elems(simp);
        total += absorbing_elems(simp);
        total += arithmetic_properties(simp);
        total += involution(simp);
        total += extract_patterns(simp);
        total += basic_transform(simp);
        total += logical_properties(simp);
        total += concat_patterns(simp);
        total += advanced(simp);
        total += taint_preservation(simp);
    }
    
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
