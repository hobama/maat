#include "exception.hpp"
#include <string>
#include <cstring>
#include <iostream>
#include <exception>

using std::cout;
using std::endl;
using std::string;

void test_hash();
void test_solver_revert_hash();
void test_code_coverage();

int main(int argc, char ** argv){
    string bold = "\033[1m";
    string def = "\033[0m";
    string red = "\033[1;31m";
        string green = "\033[1;32m";
    
    cout << bold << "\nRunnning maat advanced tests" << def << endl
                 <<   "============================" << endl << endl;
     for(int i = 0; i < 1; i++){
        try{
            if( argc == 1 ){
            /* If no args specified, test all */
                test_hash();
                test_solver_revert_hash();
                test_code_coverage();
            }else{
            /* Iterate through all options */
                for( int i = 1; i < argc; i++){
                    if( !strcmp(argv[i], "hash"))
                        test_hash();
                    else if( !strcmp(argv[i], "solve_hash") )
                        test_solver_revert_hash();
                    else if( !strcmp(argv[i], "code_coverage"))
                        test_code_coverage();
                    else
                        std::cout << "[" << red << "!" << def << "] Skipping unknown test: " << argv[i] << std::endl;
                }
            }
        }catch(test_exception& e){
            cout << red << "Fatal: Advanced test failed" << def << endl << endl;
            return 1; 
        }
    }
    cout << endl;
    return 0;
}
