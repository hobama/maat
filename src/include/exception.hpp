#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <sstream>
#include <string>
#include <exception>

using std::string;

/* From github */
class ExceptionFormatter{
public:
    ExceptionFormatter() {}
    ~ExceptionFormatter() {}

    template <typename Type>
    ExceptionFormatter & operator << (const Type & value)
    {
        stream_ << value;
        return *this;
    }

    std::string str() const         { return stream_.str(); }
    operator std::string () const   { return stream_.str(); }

    enum ConvertToString 
    {
        to_str
    };
    std::string operator >> (ConvertToString) { return stream_.str(); }

private:
    std::stringstream stream_;

    ExceptionFormatter(const ExceptionFormatter &);
    ExceptionFormatter & operator = (ExceptionFormatter &);
};

/* Generic exception 
 * This exception is thrown when an unexpected error or inconsistency occurs
 * and execution should not continue */
class runtime_exception: public std::exception {
    string _msg;
public:
    explicit runtime_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
};

/* Memory engine exceptions */ 
class mem_exception: public std::exception{
    string _msg;
public:
    explicit mem_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
};

/* Expression exception */
class expression_exception: public std::exception {
    string _msg;
public:
    explicit expression_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
};

class constraint_exception: public std::exception {
    string _msg;
public:
    explicit constraint_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
};

class snapshot_exception: public std::exception {
    string _msg;
public:
    explicit snapshot_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
};

class var_context_exception: public std::exception {
    string _msg;
public:
    explicit var_context_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
};

/* IR Exception */
class ir_exception: public std::exception {
    string _msg;
public:
    explicit ir_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
};

/* Breakpoint Exception */
class breakpoint_exception: public std::exception {
    string _msg;
public:
    explicit breakpoint_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
}; 

/* Loader Exception */
class loader_exception: public std::exception {
    string _msg;
public:
    explicit loader_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
}; 

/* Symbolic Exception */
class symbolic_exception: public std::exception {
    string _msg;
public:
    explicit symbolic_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
}; 

class unsupported_instruction_exception: public std::exception {
    string _msg;
public:
    explicit unsupported_instruction_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
}; 

/* Environment Exception */
class env_exception: public std::exception {
    string _msg;
public:
    explicit env_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
}; 


/* Test exception */ 
class test_exception : public std::exception {
   const char * what () const throw () {
      return "Unit test failure";
   }
};



#endif
