#ifndef EXPRESSION_H
#define EXPRESSION_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <ostream>
#include <unordered_map>
#include "exception.hpp"

using std::string;
using std::vector;
using std::shared_ptr;
using std::ostream;
using std::unordered_map;

/* Type aliasing */
typedef uint16_t exprsize_t ;
typedef uint32_t hash_t;
typedef int64_t cst_t;
typedef uint64_t ucst_t;

/* Types of expressions
   ====================

Different expression types are supported: 
 - CST: constant value
 - VAR: symbolic variable, identified by its name
 - MEM: a memory content, identified by an address and the number of bits
        that are read
 - UNOP/BINOP:  unary and binary operations on expressions
 - EXTRACT: extraction of a bit-interval of another expression, the interval
            is specified with the values of the higher and lower bits to
            extract
 - CONCAT: binary concatenation of two expressions
 - BISZ: zero testing. Depending on its mode, it can be equal to 1 IFF 
         the argument is zero, or to 0 IFF the argument is zero
 - UNKNOWN: represents a value which is unknown or can't be computed
*/
enum class ExprType {
    VAR, 
    MEM,
    EXTRACT, 
    CONCAT,
    UNOP, 
    BINOP,
    BISZ,
    CST,
    UNKNOWN
};
bool operator<(ExprType t1, ExprType t2);

/* Types of operations
   ===================

Different operations on expressions are supported. Their effects are 
pretty straightforward. 

Note that unary and binary operations are a member of the same enum.
Note that there is no binary SUB operation, only a unary SUB.
*/
enum class Op {
    ADD=0,
    MUL,
    MULH,
    SMULL,
    SMULH,
    DIV,
    SDIV,
    NEG,
    AND,
    OR,
    XOR,
    SHL,
    SHR,
    MOD,
    SMOD,
    NOT,
    NONE // No operation
}; 
string op_to_str(Op op);
bool operator<(Op op1, Op op2);
bool op_is_symetric(Op op);
bool op_is_associative(Op op);
bool op_is_left_associative(Op op);
bool op_is_distributive_over(Op op1, Op op2);
bool op_is_multiplication(Op op);

enum class ExprStatus: uint8_t{
    CONCRETE = 0,
    SYMBOLIC = 1,
    NOT_COMPUTED = 2
};

ExprStatus operator|(ExprStatus, ExprStatus);

enum class Taint: uint8_t {
    NOT_TAINTED = 0,
    TAINTED = 1,
    NOT_COMPUTED = 2
};

/* Expressions
   ===========

Expressions are represented in a generic with the base class ExprObject.
Its most significant contents are:
 - the size in bits of the expression (to be understood as the length of
   the bitvector used to represent the expression)
 - the type of the expression (CST,VAR,MEM,BINOP,...)
 - a hash that uniquely identifies the expression (more info about expr 
   hashing is available in the .cpp file)

The different types are implemented in separate classes inheriting from
ExprObject: ExprCst, ExprVar, ExprMem, etc. They have specific fields and
methods.

How should expressions be created and manipualted ?
---------------------------------------------------
For performance and design reasons, expressions should never be used as 
direct instances of ExprCst, ExprVar, etc. Instead, all expressions must 
be created and manipulated as an instance of 'Expr'. 

The Expr type, is an alias for shared_ptr<ExprObject>. All the methods 
and fields from the pointed expression are accessible by simply using 
'->' instead of '.'. 

A new 'Expr' can be created through the functions exprcst(), exprmem(),
exprvar(), etc, defined in this file. Standard operators such as +,-,*,
/,&,|,^,etc have been implemented to work directly on 'Expr' instances.

As an example: 

    // DON'T TRY TO DO THIS...
    ExprCst e1 = ExprCst(32, 1);
    ExprVar e2 = ExprVar(32, "eax");
    ExprVar e3 = ExprBinop(Op::ADD, e1, e2);

    // ... BUT RATHER THIS
    Expr e1 = exprcst(32,1);
    Expr e2 = exprvar(32, "eax");
    Expr e3 = e1 + e2; 

Casting
-------
An 'Expr' instance is basically a pointer to an object inheriting from
ExprObject. It is trivial to access a member (function or field) of 
ExprObject from the Expr instance by dereferencing with '->'. However, 
it is not possible to access the specialized members, such as '_cst' for
constants, '_name' for variables.

In order to do this, we define accessors for all the specialized fields
directly in the base class ExprObject. Their default implementation raises
a exception, because they should only be used in child classes instances
that have re-defined them. 

In case no accessor is provided, or the ExprObject must be casted, we have
defined a set of macros that enable to do this: _cst_, _var_, _mem_, etc. 
They can be used as follows:

    // HEAVY CODE
    Expr e = exprvar(32,"eax");
    cout << (static_cast<ExprVar*>(e))->some_attribute;
    
    // WITH MACRO
    Expr e = exprvar(32, "eax");
    cout << _var_(e).some_attribute; 

Status and taint
----------------
Expressions have two properties, status and taint.
    
    - Status can be SYMBOLIC or CONCRETE. CONCRETE means that
      the expression has a concrete associated value in the VarContext with 
      which the status is evaluated. SYMBOLIC means that the expression is
      full-symbolic: it can not be concretized because it has no entry in 
      the VarContext
    
    - Taint is simply taint. Basic types (constant and vars) can be declared
      as tainted or not tainted. The taint for complex expressions is computed
      depending on its arguments taint

*/

/* Forward declarations */
class ExprObject;
typedef shared_ptr<ExprObject> Expr;
class VarContext;

/* Generic base class */ 
class ExprObject{
friend class ExprSimplifier;
protected:
    // Hash 
    bool _hashed;
    hash_t _hash;
    // Simplification
    Expr _simplified_expr;
    bool _is_simplified;
    // Taint
    Taint _taint;
    int _taint_ctx_id;
    // Concretization
    cst_t _concrete;
    int _concrete_ctx_id;
    // State
    ExprStatus _status;
    int _status_ctx_id;
    
public:
    // General
    const ExprType type;
    exprsize_t size;
    vector<Expr> args;

    ExprObject(ExprType type, exprsize_t size, bool _is_simp=false, Taint _t = Taint::NOT_COMPUTED);
    virtual void get_associative_args(Op op, vector<Expr>& vec){};
    virtual void get_left_associative_args(Op op, vector<Expr>& vec, Expr& leftmost){};
    
    /* Virtual accessors of specialized child classes members */
    virtual hash_t hash(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual cst_t cst(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual const string& name(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual Op op(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual cst_t mode(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual void print(ostream& out){out << "???";};
    
    /* Type */
    bool is_cst();
    bool is_var();
    bool is_mem();
    virtual bool is_unop(Op op=Op::NONE);
    virtual bool is_binop(Op op=Op::NONE);
    bool is_extract();
    bool is_concat();
    bool is_bisz();
    bool is_unknown();
    
    /* Taint */
    virtual bool is_tainted();
    void make_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    
    /* Status */
    virtual bool is_symbolic(VarContext& ctx);
    
    /* Equality between expressions */
    bool eq(Expr other);
    bool neq(Expr other);
    
    /* Priority between expressions */
    bool inf(Expr other);
};

/* Child specialized classes */
class ExprCst: public ExprObject{
    cst_t _cst;
public:
    ExprCst(exprsize_t size, cst_t cst, Taint taint = Taint::NOT_TAINTED);
    hash_t hash();
    cst_t cst();
    void print(ostream& out);
    virtual bool is_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    virtual bool is_symbolic(VarContext& ctx);
};

class ExprVar: public ExprObject{
    const string _name;
public:
    ExprVar(exprsize_t size, string name, Taint taint=Taint::NOT_TAINTED);
    hash_t hash();
    const string& name();
    void print(ostream& out);
    virtual bool is_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    virtual bool is_symbolic(VarContext& ctx);
};

class ExprMem: public ExprObject{
public:
    ExprMem(exprsize_t size, Expr addr);
    hash_t hash();
    void print(ostream& out);
    virtual bool is_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    virtual bool is_symbolic(VarContext& ctx);
};

class ExprUnop: public ExprObject{
    Op _op;
public:
    ExprUnop(Op op, Expr arg);
    hash_t hash();
    Op op();
    void print(ostream& out);
    bool is_unop(Op op);
    virtual bool is_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    virtual bool is_symbolic(VarContext& ctx);
};

class ExprBinop: public ExprObject{
    Op _op;
public:
    ExprBinop(Op op, Expr left, Expr right);
    hash_t hash();
    Op op();
    void get_associative_args(Op op, vector<Expr>& vec);
    void get_left_associative_args(Op op, vector<Expr>& vec, Expr& leftmost);

    void print(ostream& out);
    bool is_binop(Op op);
    virtual bool is_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    virtual bool is_symbolic(VarContext& ctx);
};

class ExprExtract: public ExprObject{
public:
    ExprExtract(Expr arg, Expr higher, Expr lower);
    hash_t hash();
    void print(ostream& out);
    virtual bool is_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    virtual bool is_symbolic(VarContext& ctx);
};

class ExprConcat: public ExprObject{
public:
    ExprConcat(Expr upper, Expr lower);
    hash_t hash();
    void print(ostream& out);
    virtual bool is_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    virtual bool is_symbolic(VarContext& ctx);
};

class ExprBisz: public ExprObject{
    cst_t _mode;
public:
    ExprBisz(exprsize_t size, Expr cond, cst_t mode);
    hash_t hash();
    cst_t mode();
    void print(ostream& out);
    virtual bool is_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    virtual bool is_symbolic(VarContext& ctx);
};

class ExprUnknown: public ExprObject{
public:
    ExprUnknown(exprsize_t size);
    hash_t hash();
    void print(ostream& out);
    virtual bool is_tainted();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    virtual cst_t as_unsigned(VarContext* ctx=nullptr);
    virtual cst_t as_signed(VarContext* ctx=nullptr);
    virtual bool is_symbolic(VarContext& ctx);
};

/* Helper functions to create new expressions */
// Create from scratch  
Expr exprcst(exprsize_t size, cst_t cst, Taint tainted = Taint::NOT_COMPUTED);
Expr exprvar(exprsize_t size, string name, Taint tainted = Taint::NOT_TAINTED);
Expr exprmem(exprsize_t size, Expr addr);
Expr exprbinop(Op op, Expr left, Expr right);
Expr extract(Expr arg, unsigned long higher, unsigned long lower);
Expr extract(Expr arg, Expr higher, Expr lower);
Expr concat(Expr upper, Expr lower);
Expr bisz(exprsize_t size, Expr arg, cst_t mode);
Expr exprunknown(exprsize_t size);

// Binary operations 
Expr operator+(Expr left, Expr right);
Expr operator+(Expr left, cst_t right);
Expr operator+(cst_t left, Expr right);

Expr operator-(Expr left, Expr right);
Expr operator-(Expr left, cst_t right);
Expr operator-(cst_t left, Expr right);

Expr operator*(Expr left, Expr right);
Expr operator*(Expr left, cst_t right);
Expr operator*(cst_t left, Expr right);

Expr operator/(Expr left, Expr right);
Expr operator/(Expr left, cst_t right);
Expr operator/(cst_t left, Expr right);

Expr operator&(Expr left, Expr right);
Expr operator&(Expr left, cst_t right);
Expr operator&(cst_t left, Expr right);

Expr operator|(Expr left, Expr right);
Expr operator|(Expr left, cst_t right);
Expr operator|(cst_t left, Expr right);

Expr operator^(Expr left, Expr right);
Expr operator^(Expr left, cst_t right);
Expr operator^(cst_t left, Expr right);

Expr operator%(Expr left, Expr right);
Expr operator%(Expr left, cst_t right);
Expr operator%(cst_t left, Expr right);

Expr operator<<(Expr left, Expr right);
Expr operator<<(Expr left, cst_t right);
Expr operator<<(cst_t left, Expr right);

Expr operator>>(Expr left, Expr right);
Expr operator>>(Expr left, cst_t right);
Expr operator>>(cst_t left, Expr right);

Expr shl(Expr arg, Expr shift);
Expr shl(Expr arg, cst_t shift);
Expr shl(cst_t arg, Expr shift);

Expr shr(Expr arg, Expr shift);
Expr shr(Expr arg, cst_t shift);
Expr shr(cst_t arg, Expr shift);

Expr sdiv(Expr left, Expr right);
Expr sdiv(Expr left, cst_t right);
Expr sdiv(cst_t left, Expr right);

Expr smod(Expr left, Expr right);
Expr smod(Expr left, cst_t right);
Expr smod(cst_t left, Expr right);

Expr mulh(Expr left, Expr right);
Expr mulh(Expr left, cst_t right);
Expr mulh(cst_t left, Expr right);

Expr smull(Expr left, Expr right);
Expr smull(Expr left, cst_t right);
Expr smull(cst_t left, Expr right);

Expr smulh(Expr left, Expr right);
Expr smulh(Expr left, cst_t right);
Expr smulh(cst_t left, Expr right);

// Unary operations
Expr operator~(Expr arg);
Expr operator-(Expr arg);

/* Printing expressions */
ostream& operator<< (ostream& os, Expr e);

/* Canonizing expressions */
Expr expr_canonize(Expr e);

cst_t cst_sign_trunc(exprsize_t size, cst_t val);
cst_t cst_mask(exprsize_t size);
cst_t cst_sign_extend(exprsize_t size, cst_t val);

/* VarContext
   ==========
A VarContext associates a list of concrete values to a list of variables.
It used with the variables names as keys for lookup. */
class VarContext{
    unordered_map<string, cst_t> umap;
public:
    int id;
    VarContext(int id=0);
    void set(const string& name, cst_t value);
    cst_t get(const string& name);
    vector<uint8_t> get_as_buffer(string name);
    void remove(const string& name);
    bool contains(const string& name);
    string new_name_from(string& name);
    void update_from(VarContext& other);
    void print(ostream& os);
};

ostream& operator<<(ostream& os, VarContext& c);
#endif

// Macros to statically cast expressions to access fields if needed
#define _exprobject_(e) (*(static_cast<ExprObject*>(e.get())))
#define _cst_(e) (*(static_cast<ExprCst*>(e.get())))
#define _var_(e) (*(static_cast<ExprVar*>(e.get())))
#define _mem_(e) (*(static_cast<ExprMem*>(e.get())))
#define _unop_(e) (*(static_cast<ExprUnop*>(e.get())))
#define _binop_(e) (*(static_cast<ExprBinop*>(e.get())))
#define _extract_(e) (*(static_cast<ExprExtract*>(e.get())))
#define _concat_(e) (*(static_cast<ExprConcat*>(e.get())))
#define _bisz_(e) (*(static_cast<ExprBisz*>(e.get())))
#define _unknown_(e) (*(static_cast<ExprUnknown*>(e.get())))
