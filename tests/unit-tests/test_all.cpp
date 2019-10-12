#include "exception.hpp"
#include <string>
#include <cstring>
#include <iostream>
#include <exception>

using std::cout;
using std::endl;
using std::string;

void test_expression();
void test_simplification();
void test_memory();
void test_ir();
void test_symbolic();
void test_archX86();
void test_solver();
void test_loader();
void test_env();

int main(int argc, char ** argv){
    string bold = "\033[1m";
    string def = "\033[0m";
    string red = "\033[1;31m";
    string green = "\033[1;32m";
    
    cout << bold << "\nRunnning maat unitary tests" << def << endl
                 <<   "===========================" << endl << endl;
     for(int i = 0; i < 1; i++){
        try{
            if( argc == 1 ){
            /* If no args specified, test all */
                test_expression();
                test_simplification();
                test_memory();
                test_ir();
                test_symbolic();
                test_archX86();
                test_solver();
                test_env();
                test_loader();
            }else{
            /* Iterate through all options */
                for( int i = 1; i < argc; i++){
                    if( !strcmp(argv[i], "expr"))
                        test_expression();
                    else if (!strcmp(argv[i], "simp"))
                        test_simplification();
                    else if( !strcmp(argv[i], "mem"))
                        test_memory();
                    else if( !strcmp(argv[i], "ir"))
                        test_ir();
                    else if( !strcmp(argv[i], "sym"))
                        test_symbolic();
                    else if( !strcmp(argv[i], "X86"))
                        test_archX86();
                    else if( !strcmp(argv[i], "solver"))
                        test_solver();
                    else if( !strcmp(argv[i], "loader"))
                        test_loader();
                    else if( !strcmp(argv[i], "env"))
                        test_env();
                    else
                        std::cout << "[" << red << "!" << def << "] Skipping unknown test: " << argv[i] << std::endl;
                }
            }
        }catch(test_exception& e){
            cout << red << "Fatal: Unit test failed" << def << endl << endl;
            return 1; 
        }
    }
    cout << endl;
    return 0;
}
