#ifdef LIEF_BACKEND 
#include "loader.hpp"
#include "exception.hpp"
#include "environment.hpp"
#include "io.hpp"
#include <sstream>

using std::vector;
using std::string;
using std::stringstream;

Loader* NewLoader(SymbolicEngine& sym){
    return new LIEFLoader(sym);
}

LIEFLoader::LIEFLoader(SymbolicEngine& s): Loader(s), base_address(0){} 

void LIEFLoader::_parse_binary(string name, BinType type){
    /* Check if format is supported */
    if( type == BinType::ELF32 ){
        _elf32 = LIEF::ELF::Parser::parse(name);
    }else{
        throw loader_exception("LIEFLoader::_parse_binary(): Got unsupported binary format for LIEF backend Loader");
    }
}

segment_flags_t _get_elf_segment_flags(LIEF::ELF::Segment& segment){
    segment_flags_t flags = 0;
    if( segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_R) ){
        flags |= MEM_FLAG_R;
    }
    if( segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_W) ){
        flags |= MEM_FLAG_W;
    }
    if( segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_X) ){
        flags |= MEM_FLAG_X;
    }
    return flags;
}
/* Find where to create a new segment in memory */
addr_t _create_segment(SymbolicEngine& sym, addr_t init_base, addr_t size, addr_t step, segment_flags_t flags, string name = ""){
    addr_t base = init_base;
    bool ok = false;
    do{
        if( sym.mem->is_free(base, base+size-1) && base+size-1 < 0x100000000){
            ok = true;
            sym.mem->new_segment(base, base+size-1, flags, name);
            return base;
        }
        base = (base + step) % 0x100000000;
    }while( !ok && base != init_base );
    
    throw loader_exception("Could create segment where to point external function relocations");
}

void _set_simu_irblock_addr(IRBlock* irblock, addr_t addr){
    for( int i = 0; i < irblock->nb_bblocks(); i++ ){
        IRBasicBlock& bblock = irblock->get_bblock(i);
        for( IRInstruction& instr : bblock  ){
            instr.addr = addr;
        }
    }
    irblock->start_addr = addr;
    irblock->end_addr = addr;
}

addr_t _call_ifunc_resolver(SymbolicEngine& sym, addr_t resolver_addr){
    /* Set a fake return address and breakpoint 
       before the ret */
    sym.regs->set(X86_ESP, sym.regs->get(X86_ESP)-4);
    sym.mem->write((uint32_t)sym.regs->concretize(X86_ESP), 0x12345678, 4);
    sym.breakpoint.add(BreakpointType::MEMORY_R, "resolver_end", (uint32_t)sym.regs->concretize(X86_ESP));
    try{
        sym.execute_from(resolver_addr);
        if( sym.info.breakpoint != "resolver_end" ){
            throw loader_exception(ExceptionFormatter() << "LIEFLoader: failed to break after resolver for IFUNC at " << 
                                                        std::hex << resolver_addr >> ExceptionFormatter::to_str);
        }
        sym.regs->set(X86_ESP, sym.regs->get(X86_ESP)+4); // Reset ESP at its initial value
        sym.breakpoint.remove_all();
    }catch(std::exception& e ){
        throw loader_exception(ExceptionFormatter() << "LIEFLoader: engine error when executing resolver for IFUNC at " << 
                                                    std::hex << resolver_addr << ": " << e.what() >> ExceptionFormatter::to_str);
    }
    /* Get the address in eax */
    return (uint32_t)sym.regs->concretize(X86_EAX);
}


void LIEFLoader::_perform_x86_relocations(SymbolicEngine& sym){
    /* Values when performing relocations:
       -----------------------------------
        A   This means the addend used to compute the value of the relocatable field.
        B   This means the base address at which a shared object has been loaded into memory duringexecution.  Generally, a shared object file is built with a 0 base virtual address, but the execution address will be different
        G   This means the offset into the global offset table at which the address of the relocation entry’s symbol will reside during execution.
        GOT This means the address of the global offset table.
        L   This means the place (section offset or address) of the procedure linkage table entry for a symbol.  
            A procedure linkage table entry redirects a function call to the proper destination. 
            The link editor builds the initial procedure linkage table, and the dynamic linker modifies theentries during execution.
        P   This means the place (section offset or address) of the storage unit being relocated (computedusingr_offset).
        S   This means the value of the symbol whose index resides in the relocation entry

     X86 Relocations 
     ---------------
        Name 	 	        Calculation
        R_386_NONE 	        None
        R_386_32 	        S + A
        R_386_PC32 		    S + A – P
        R_386_GOT32 	    G + A
        R_386_PLT32 	    L + A – P
        R_386_COPY 	        Value is copied directly from shared object
        R_386_GLOB_DAT 	    S
        R_386_JMP_SLOT 	    S
        R_386_RELATIVE 	    B + A
        R_386_GOTOFF 	    S + A – GOT
        R_386_GOTPC 	    GOT + A – P
        R_386_32PLT 	    L + A
        R_386_16 	        S + A       (word)
        R_386_PC16          S + A – P   (word)
        R_386_8 	        S + A       (byte)
        R_386_PC8 	        S + A – P   (byte)
        R_386_SIZE32        Z + A
        R_386_IRELATIVE     The value (B+A) points to a resolver function which must be executed 
                            by the loader and returns in EAX the address of the choosen implementation
        
    */
    
    // Simulate imported functions 
    addr_t simu_func_segment = _create_segment(sym, 0x00dead00, 0x400, 0x01000000, MEM_FLAG_RWX, "Simulated external functions" );
    // Simulate imported data (values initialized later if needed)
    addr_t simu_data_segment_size = 0;
    addr_t simu_data_segment = 0;
    addr_t simu_data_offset = 0; 
    
    for( LIEF::ELF::Relocation& reloc : _elf32->relocations() ){
        uint64_t B = base_address;
        int64_t A = reloc.is_rela() ? reloc.addend() : 0;
        uint64_t S = reloc.symbol().value() + base_address; // Value of the symbol (its virtual address) (+ base_address)
        uint64_t P = reloc.address() + base_address; // Address of the relocation (virtual address) (+base_address)
        uint64_t symbol_size = reloc.symbol().size();
        uint64_t reloc_addr = reloc.address() + base_address;
        uint64_t reloc_new_value;
        uint64_t simu_data_symbol_addr = 0; // Address where we load imported data if any
        
        /* Check if the relocation is imported ! */
        if(     ((reloc.type() != LIEF::ELF::RELOC_i386::R_386_RELATIVE) &&
                (reloc.type() != LIEF::ELF::RELOC_i386::R_386_IRELATIVE) &&
                reloc.has_symbol() && 
                reloc.symbol().value() == 0 && 
                (LIEF::ELF::SYMBOL_SECTION_INDEX)reloc.symbol().section_idx() == LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF )
            ||    
                (reloc.type() == LIEF::ELF::RELOC_i386::R_386_COPY)  
            ){
            /* Check if function relocation */
            if( (LIEF::ELF::ELF_SYMBOL_TYPES)reloc.symbol().type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_FUNC ){
                if( ! sym.env->simulates_function(reloc.symbol().demangled_name())){
                    stringstream ss;
                    ss << "Imported function '" <<  reloc.symbol().demangled_name() << "' not supported by simulated environment";
                    sym._print_warning(ss.str());
                }
                
                // If env supports the function get it, otherwise return the non_implemented callback
                EnvFunction& func = sym.env->simulates_function(reloc.symbol().demangled_name()) ? 
                                    sym.env->get_function(reloc.symbol().demangled_name())  :
                                    sym.env->new_not_implemented_function(reloc.symbol().demangled_name(), ABI::X86_CDECL);
                
                if( func.is_loaded )
                    S = func.load_addr;
                else{
                    // If not yet loaded, load it and increment the simu_segment address for next function
                    S = simu_func_segment;
                    func.load_addr = simu_func_segment++;
                    func.is_loaded = true;
                    /* Check what type of function */
                    if( func.type == EnvFunctionType::FROM_IR ){
                        // If simulation from ir, set the instructions address and add it to the 
                        // ir manager
                        _set_simu_irblock_addr(func.irblock, func.load_addr);
                        sym.irmanager->add(func.irblock);
                    }
                }
                sym.set_symbol_address( reloc.symbol().demangled_name(), func.load_addr );
            /* Check if imported data relocation */
            }else if( (LIEF::ELF::ELF_SYMBOL_TYPES)reloc.symbol().type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_OBJECT ){
                // If the environment supports this symbol get it, otherwise just set the symobl address to 0
                if( sym.env->simulates_data(reloc.symbol().demangled_name()) ){
                    EnvData& data = sym.env->get_data(reloc.symbol().demangled_name());
                    if( data.is_loaded ){
                        S = data.load_addr;
                    }else{
                        // Data not yet loaded, load it and increment the simu_data offset counter
                        if( data.size != reloc.symbol().size() ){
                            throw loader_exception("Environment defines imported data with different size than the one defined in symbol info");
                        }
                        if( simu_data_offset + data.size >= simu_data_segment_size ){
                            // Create new segment
                            simu_data_segment_size = 0x1000;
                            simu_data_segment = _create_segment(sym, 0x000aa000, simu_data_segment_size, simu_data_segment_size, MEM_FLAG_RW, "Simulated external data" );
                            simu_data_offset = simu_data_segment; 
                        }
                        // Write the data content 
                        sym.mem->write(simu_data_offset, data.data, data.size);
                        simu_data_symbol_addr = simu_data_offset;
                        data.is_loaded = true;
                        data.load_addr = simu_data_symbol_addr;
                        simu_data_offset += data.size;
                    }
                    // Add the symbol to the symbolic engine
                    sym.set_symbol_address(data.name, data.load_addr);
                // If not supported, do nothing
                }else{
                    stringstream ss;
                    ss << "Imported data '" <<  reloc.symbol().demangled_name() << "' not supported by simulated environment";
                    sym._print_warning(ss.str());
                }
            }else{
                stringstream ss;
                ss << "Imported symbol '" <<  reloc.symbol().demangled_name() << "' has unsupported type";
                sym._print_warning(ss.str());
            }
        }

        if( reloc.type() == LIEF::ELF::RELOC_i386::R_386_JUMP_SLOT ){
            reloc_new_value = S;
            sym.mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }else if( reloc.type() == LIEF::ELF::RELOC_i386::R_386_32 ){
            reloc_new_value = sym.mem->read(reloc_addr, 4)->concretize() + S + A;
            sym.mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }else if( reloc.type() == LIEF::ELF::RELOC_i386::R_386_PC32){
            reloc_new_value = sym.mem->read(reloc_addr, 4)->concretize() + S + A - P;
            sym.mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }else if( reloc.type() == LIEF::ELF::RELOC_i386::R_386_GLOB_DAT){
            reloc_new_value = sym.mem->read(reloc_addr, 4)->concretize() + S;
            sym.mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }else if( reloc.type() == LIEF::ELF::RELOC_i386::R_386_RELATIVE){
            reloc_new_value = sym.mem->read(reloc_addr, 4)->concretize() + B + A;
            sym.mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }else if( reloc.type() == LIEF::ELF::RELOC_i386::R_386_JUMP_SLOT){
            reloc_new_value = sym.mem->read(reloc_addr, 4)->concretize() + S;
            sym.mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }else if( reloc.type() == LIEF::ELF::RELOC_i386::R_386_COPY ){
            if( simu_data_symbol_addr != 0 ){
                sym.mem->write(P, sym.mem->mem_at(simu_data_symbol_addr), reloc.symbol().size(), true ); // Ignore memory flags
            }
        }else if( reloc.type() == LIEF::ELF::RELOC_i386::R_386_IRELATIVE ){
            //reloc_new_value = _call_ifunc_resolver(sym, (uint32_t)sym.mem->read(reloc_addr, 4)->concretize() + B + A);
            reloc_new_value = (uint32_t)sym.mem->read(reloc_addr, 4)->concretize() + B + A;
            sym.mem->write(reloc_addr, reloc_new_value, 4, true); // Ignore memory flags
        }else{
            throw loader_exception(ExceptionFormatter() << "LIEFLoader: Got unsupported X86 relocation type: " << reloc.type() >> ExceptionFormatter::to_str);
        }
    }
}

void LIEFLoader::_import_env_functions(SymbolicEngine& sym){
    // Simulate imported functions 
    addr_t simu_func_segment = _create_segment(sym, 0x00dead00, 0x400, 0x01000000, MEM_FLAG_RWX, "Simulated external functions" );
    for( string func_name : sym.env->all_function_names() ){
        EnvFunction& func = sym.env->get_function(func_name);
        if( ! func.is_loaded ){
            // If not yet loaded, load it and increment the simu_segment address for next function
            func.load_addr = simu_func_segment++;
            func.is_loaded = true;
            /* Check what type of function */
            if( func.type == EnvFunctionType::FROM_IR ){
                // If simulation from ir, set the instructions address and add it to the 
                // ir manager
                _set_simu_irblock_addr(func.irblock, func.load_addr);
                sym.irmanager->add(func.irblock);
            }
            sym.set_symbol_address( func_name, func.load_addr );
        }
    }
}

void LIEFLoader::_load_ctype_b_loc_table(SymbolicEngine& sym){
    size_t table_size = (256 + 127 + 1) * 2; // 384 entries of 2 bytes each
    addr_t table_segment = _create_segment(sym, 0x4000, 0x400, 0x400, MEM_FLAG_RW, "ctype_loc_b table");
    addr_t table_addr = table_segment + 0x10;
    // Write a pointer to the table
    sym.mem->write(table_segment, table_addr + (128*2), (unsigned int)4); // Because first 128 entries are negative offsets
    // Write the table in memory
    sym.mem->write(table_addr, (uint8_t*)sym.env->ctype_b_loc_table, table_size);
    // Set the ctype_b_loc pointer address in the environment
    sym.env->ctype_b_loc_table_ptr = table_segment; 
}

// !! Must be executed AFTER functions have been loaded
void LIEFLoader::_init_signal_handlers(SymbolicEngine& sym){
    for( auto it : sym.env->default_signal_handlers ){
        EnvFunction& func = sym.env->get_function(it.second);
        sym.env->current_signal_handlers[it.first] = func.load_addr;
    }
}

void LIEFLoader::load(string name, BinType type, uint64_t base, vector<CmdlineArg> cmdline_args, vector<string> env_variables){

    /* Parse binary with LIEF */
    _parse_binary(name, type);
    bin_type = type;
    base_address = base;
    
    /* Write all segments to memory */
    uint8_t* data;
    unsigned int virtual_size, physical_size;
    uint64_t addr;
    segment_flags_t flags;
    addr_t stack_base, stack_size, heap_base, heap_size, kernel_stack_size, kernel_stack_base;
    addr_t gs, fs;
    
    int i;
    if( bin_type == BinType::ELF32 ){
        for (LIEF::ELF::Segment& segment: _elf32->segments() ){
            if( segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_LOAD ){
                if( segment.content().size() != segment.physical_size() ){
                    throw loader_exception("LIEFLoader: Got unconsistent sizes for segment content and its physical size");
                }
                
                /* Copy segment content (vector<uint8_t>) into a buffer */
                data = new uint8_t[segment.physical_size()];
                i = 0;
                for( auto b : segment.content()){
                    data[i++] = b;
                }
                virtual_size = segment.virtual_size();
                physical_size = segment.physical_size();
                addr = segment.virtual_address() + base_address;
                flags = _get_elf_segment_flags(segment);
                // Create new segment
                sym.mem->new_segment(addr, addr+virtual_size-1, flags);
                // Write content
                sym.mem->write(addr, data, physical_size, true);
                delete [] data; data = nullptr;
            }
        }
    }else{
        throw loader_exception("LIEFLoader: Got unsupported binary format for LIEF backend Loader");
    }
    
    /* Setup stack */
    stack_size = 0x04000000;
    stack_base = _create_segment(sym, 0xfb000000, stack_size, 0x01000000, MEM_FLAG_RW, "Stack");
    sym.regs->set(X86_ESP, exprcst(32, stack_base + stack_size));
    sym.regs->set(X86_EBP, exprcst(32, stack_base + stack_size));
    
    /* Setup kernel stack */
    kernel_stack_size = 0x000c000;
    kernel_stack_base = _create_segment(sym, 0x4000, kernel_stack_size, 0x0010000, MEM_FLAG_RW, "Kernel Stack");
    sym.env->kernel_stack = kernel_stack_base + kernel_stack_size;
    
    /* Setup heap */
    heap_size = 0x06000000;
    heap_base = _create_segment(sym, 0x09000000, heap_size, 0x01000000, MEM_FLAG_RW, "Heap");
    sym.env->init_mem_allocator(heap_base, heap_base+heap_size-1);
    
    /* Allocate some segments for GS and FS segment selectors */
    gs = _create_segment(sym, 0x00aa0000, 0x1000, 0x1000, MEM_FLAG_RW, "Fake GS: segment");
    fs = _create_segment(sym, 0x00aa0000, 0x1000, 0x1000, MEM_FLAG_RW, "Fake FS: segment");
    sym.regs->set(X86_GS, exprcst(32, gs));
    sym.regs->set(X86_FS, exprcst(32, fs));
    
    /* Load misc. things */
    _load_ctype_b_loc_table(sym);
    
    /* Load all env functions */
    _import_env_functions(sym);
    
    /* Initialize default signal handlers */
    _init_signal_handlers(sym);
    
    /* Perform relocations */
    if( bin_type == BinType::ELF32 ){
        _perform_x86_relocations(sym);
    }else{
        throw loader_exception("LIEFLoader: Relocations: Got unsupported binary format for LIEF backend Loader");
    }
    
    /* Setup args, env, auxilliary vector, etc in memory */
    
    // First add the binary name to the args
    cmdline_args.insert(cmdline_args.begin(), CmdlineArg(name));
    // Compute total size needed to put the args and env
    vector<addr_t> argv_addresses;
    vector<addr_t> env_addresses;
    int args_total_size = 0, env_total_size = 0;
    int argc = 0;
    string arg_name, var_name, var;
    stringstream ss;
    Taint taint;
    CmdlineArg arg;
    for( auto arg : cmdline_args ){
        args_total_size += arg.len;
        argc++;
    }
    addr_t mem_arg_addr = (uint32_t)(sym.regs->concretize(X86_ESP)) - args_total_size - env_total_size;
    // Adjust ESP so it points after the program args and env variables
    sym.regs->set(X86_ESP, exprcst(32, mem_arg_addr));
    // Write args in memory
    for( i = 0; i < cmdline_args.size(); i++){
        arg = cmdline_args[i];
        // Write arg
        taint = arg.is_tainted ? Taint::TAINTED : Taint::NOT_TAINTED;
        if( arg.is_symbolic ){
            arg_name = arg.str + "_";
            for( int j = 0; j < arg.len-1; j++ ){
                ss.str("");
                ss << std::dec << arg_name << j;
                var_name = ss.str();
                sym.mem->write(mem_arg_addr+j, exprvar(8, var_name, taint));
            }
            sym.mem->write(mem_arg_addr+arg.len-1, exprcst(8, 0));
        }else{
            ss.str("");
            ss << "argv[" << std::dec << i << "]_";
            arg_name = ss.str();
            for( int j = 0; j < arg.len-1; j++ ){
                if( arg.is_tainted ){
                    ss.str("");
                    ss << std::dec << arg_name << j;
                    var_name = ss.str();
                    sym.mem->write(mem_arg_addr+j, exprvar(8, var_name, Taint::TAINTED));
                    sym.vars->set(var_name, (uint8_t)(arg.str[j]));
                }else{
                    sym.mem->write(mem_arg_addr+j, exprcst(8, (uint8_t)(arg.str[j])));
                }
            }
            sym.mem->write(mem_arg_addr+arg.len-1, exprcst(8, 0));
        }
        
        // Record address
        argv_addresses.push_back(mem_arg_addr);
        // Increment address
        mem_arg_addr += arg.len;
    }
    
    // Write auxilliary vector in memory
    // --> So far not supported, do nothing 
    
    // Write env variables in memory
    for( i = 0; i < env_variables.size(); i++ ){
        var = env_variables[i];
        // Decrease esp of its size + 1 for null byte
        mem_arg_addr = (uint32_t)sym.regs->concretize(X86_ESP) - var.size() - 1;
        sym.regs->set(X86_ESP, exprcst(32, mem_arg_addr));
        sym.mem->write(mem_arg_addr, (uint8_t*)var.c_str(), var.size()+1);
        env_addresses.insert(env_addresses.begin(), mem_arg_addr);
    }


    /* When calling _start the memory must be environment variables, then
     * program arguments, then argument count 
     Low Addr.
                argc      <--- esp
                &argv[0]
                &argv[1]
                ...
                0
                &env[0]
                &env[1]
                ...
                0
     High Addr.
    */

    // Setup auxilliary vector
    // At the end of aux add two null pointers (termination key/value)
    sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 8));
    sym.mem->write((uint32_t)(sym.regs->concretize(X86_ESP)), (cst_t)0, (unsigned int)8); 
    // --> TODO: write auxilliary vector

    // Setup env
    sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 4) );
    sym.mem->write((uint32_t)(sym.regs->concretize(X86_ESP)), (cst_t)0, (unsigned int)4); // At the end of env variables add a null pointer
    for( vector<addr_t>::reverse_iterator it = env_addresses.rbegin(); it != env_addresses.rend(); it++ ){
        sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 4) );
        sym.mem->write((uint32_t)(sym.regs->concretize(X86_ESP)), *it, 4);
    }
    sym.env->env_array = (uint32_t)(sym.regs->concretize(X86_ESP)); // Set env[] pointer in environment :)

    // Setup argv
    sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 4) );
    sym.mem->write((uint32_t)(sym.regs->concretize(X86_ESP)), (cst_t)0, (unsigned int)4); // At the end of argv add a null pointer
    for( vector<addr_t>::reverse_iterator it = argv_addresses.rbegin(); it != argv_addresses.rend(); it++ ){
        sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 4) );
        sym.mem->write((uint32_t)(sym.regs->concretize(X86_ESP)), *it, 4);
    }
    // Setup argc
    sym.regs->set(X86_ESP, exprcst(32, sym.regs->concretize(X86_ESP) - 4) );
    sym.mem->write((uint32_t)(sym.regs->concretize(X86_ESP)), argc, 4);
    
    // Setup instruction pointer and reset IR state (in case we executed IFUNC resolvers already...)
    sym.irstate.reset();
    sym.regs->set(X86_EIP, exprcst(32, _elf32->entrypoint() + base_address));
    
    // Add 3 dummy file descriptors to the env (for stdin, stdout, and stderr)
    sym.env->filesystem.create_file_num("__stdin", 0);
    sym.env->filesystem.create_file_num("__stdout", 1);
    sym.env->filesystem.create_file_num("__stderr", 2);
    
    
}

#endif
