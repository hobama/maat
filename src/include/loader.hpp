#ifndef LOADER_H
#define LOADER_H

#include "memory.hpp"
#include "symbolic.hpp"
#include <vector>
#include <memory>

#ifdef LIEF_BACKEND
#include <LIEF/LIEF.hpp>
#endif

using std::unique_ptr;
using std::string;
using std::vector;

enum class BinType{
    ELF32,
    ELF64,
    PE32,
    PE64,
    NONE
};

class CmdlineArg{
public:
    string str;
    size_t len;
    bool is_symbolic;
    bool is_tainted;
    CmdlineArg(){};
    CmdlineArg(string s, bool it=false): str(s + "\0"), len(s.size()+1), is_tainted(it), is_symbolic(false) {};
    CmdlineArg(string s, size_t l, bool it=false): str(s), len(l+1), is_tainted(it), is_symbolic(true){};
};


class Loader{
friend class LIEFLoader;
    SymbolicEngine& sym;
    BinType bin_type;
    virtual void _parse_binary(string name, BinType type) = 0;
public:
    Loader(SymbolicEngine& s): sym(s), bin_type(BinType::NONE){};
    virtual void load(string name, BinType type, uint64_t base=0, vector<CmdlineArg> cmdline_args=vector<CmdlineArg>{}, 
        vector<string> env_variables = vector<string>{}) = 0;
};

Loader * NewLoader(SymbolicEngine& sym);


#ifdef LIEF_BACKEND
class LIEFLoader: public Loader{
    unique_ptr<LIEF::ELF::Binary> _elf32;
    uint64_t base_address;
    
    void _parse_binary(string name, BinType type);
    void _perform_x86_relocations(SymbolicEngine& sym);
    void _import_env_functions(SymbolicEngine& sym);
    void _load_ctype_b_loc_table(SymbolicEngine& sym);
    void _init_signal_handlers(SymbolicEngine& sym);
public:
    LIEFLoader(SymbolicEngine& sym);
    void load(string name, BinType type, uint64_t base=0, vector<CmdlineArg> cmdline_args=vector<CmdlineArg>{},
        vector<string> env_variables = vector<string>{});

};
#endif

#endif
