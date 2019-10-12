#include "io.hpp"
#include <iostream>

using std::string;

void print_warning(string msg){
    string bold = "\033[1m";
    string def = "\033[0m";
    string yellow = "\033[1;33m";

    std::cout << bold << "[" << yellow << "Warning" << def << bold << "] " << def << msg << std::endl;
}

void print_info(string msg){
    string bold = "\033[1m";
    string def = "\033[0m";
    string green = "\033[1;32m";

    std::cout << bold << "[" << green << "Info" <<  def << bold << "] " << def << msg << std::endl;
}

void print_error(string msg){
    string bold = "\033[1m";
    string def = "\033[0m";
    string red = "\033[1;31m";

    std::cout << bold << "[" << red << "Error" <<  def << bold << "] " << def << msg << std::endl;
}
