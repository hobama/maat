#include "memory.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <sstream>

using std::get;
using std::stringstream;

/* ==================================== */
MemStatusBitmap::MemStatusBitmap():_bitmap(nullptr), _size(0){}
MemStatusBitmap::MemStatusBitmap(offset_t nb_bytes){
    // +1 to be sure to not loose bytes if nb_bytes is
    // not a multiple of 8 
    // {0} to initialize everything to concrete by default
    try{
        _size = (nb_bytes/8) + 1;
        _bitmap = new uint8_t[_size]{0};
    }catch(std::bad_alloc){
        throw mem_exception(ExceptionFormatter() << "Failed to allocate MemStatusBitmap of size " << nb_bytes >> ExceptionFormatter::to_str );
    }
}
MemStatusBitmap::~MemStatusBitmap(){
    if( _bitmap != nullptr )
        delete [] _bitmap;
    _bitmap = nullptr;
}
void MemStatusBitmap::mark_as_symbolic(offset_t off){
    offset_t qword = off/8;
    uint8_t mask = 1 << (off%8);
    _bitmap[qword] |= mask;
}
void MemStatusBitmap::mark_as_symbolic(offset_t start, offset_t end){
    offset_t qword = start/8, last_qword=end/8;
    uint8_t final_mask = 0xff >> (8-1-(end%8));
    uint8_t first_mask = (0xff << (start%8));
    if( qword == last_qword ){
        _bitmap[qword] |= (final_mask&first_mask);
        return;
    }
    _bitmap[qword++] |= first_mask;
    while( qword < last_qword ){
        _bitmap[qword++] = 0xff;
    }
    _bitmap[last_qword] |= final_mask;
}
void MemStatusBitmap::mark_as_concrete(offset_t off){
    offset_t qword = off/8;
    uint8_t mask = ~(1 << (off%8));
    _bitmap[qword] &= mask;
}
void MemStatusBitmap::mark_as_concrete(offset_t start, offset_t end){
    offset_t qword = start/8, last_qword=end/8;
    uint8_t first_mask = 0xff >> (8-(start%8));
    uint8_t final_mask = (0xfe << (end%8));
    if( qword == last_qword ){
        _bitmap[qword] &= (first_mask|final_mask);
        return;
    }
    _bitmap[qword++] &= first_mask;
    while( qword < last_qword ){
        _bitmap[qword++] = 0x0;
    }
    _bitmap[last_qword] &= final_mask;
}
bool MemStatusBitmap::is_symbolic(offset_t off){
    offset_t qword = off/8;
    uint8_t mask = 1 << (off%8);
    return _bitmap[qword] & mask;
}
bool MemStatusBitmap::is_concrete(offset_t off){
    offset_t qword = off/8;
    uint8_t mask = 1 << (off%8);
    return _bitmap[qword] ^ mask;
}

/* Reutnr the offset of the first byte that is not symbolic */
offset_t MemStatusBitmap::is_symbolic_until(offset_t off , unsigned int max){
    offset_t qword = off/8;
    offset_t max_qword = ((max+off-1)/8)+1;
    offset_t res = off;
    uint8_t m;
    // Test the 8 first bytes
    m = (uint8_t)1 << (off%8);
    while( m != 0){
        if( (_bitmap[qword] & m) == 0 ){
            return res; 
        }
        res += 1; 
        m = m << 1; 
    }
    qword++; // Continue from next qword

    // Test 8 bytes per 8 bytes
    while( qword < _size && qword < max_qword && _bitmap[qword] == 0xff){
        res += 8;
        qword++;
    }
    // If we reached the end or the max to read return it 
    if( qword == _size){
        return res + 7;
    }else if( qword == max_qword ){
        return res;
    }
    // Else test the 7 last ones one by one
    m = 1; 
    while( (m != 0) && ((_bitmap[qword] & m) != 0)){
        m = m << 1; 
        res++;
    }
    return res;
}
offset_t MemStatusBitmap::is_concrete_until(offset_t off, unsigned int max ){
    offset_t qword = off/8;
    offset_t max_qword = ((off+max-1)/8)+1; 
    offset_t res = off;
    uint8_t m;
    // Test the 8 first bytes
    m = (uint8_t)1 << (off%8);
    while( m != 0){
        if( (_bitmap[qword] & m ) != 0 ){
            return res; 
        }
        res += 1; 
        m = m << 1; 
    }
    qword++; // Continue from next qword
    
    // Test 8 bytes per 8 bytes
    while( qword < _size && qword < max_qword && _bitmap[qword] == 0x0){
        res += 8;
        qword++;
    }
    // If we reached the end return it
    if( qword == _size ){
        return res + 7; 
    }else if( qword == max_qword ){
        return res;
    }
    // Else test the 7 last ones one by one
    m = 1; 
    while( (m != 0) && ((_bitmap[qword] & m) == 0)){
        m = m << 1;
        res++;
    }
    return res;
}

/* ==================================== */
MemConcreteBuffer::MemConcreteBuffer():_mem(nullptr){}
MemConcreteBuffer::MemConcreteBuffer(offset_t nb_bytes){
    try{
        _mem = new uint8_t[nb_bytes]{0};
    }catch(std::bad_alloc){
        throw mem_exception(ExceptionFormatter() << "Failed to allocate MemConcreteBuffer of size " << nb_bytes >> ExceptionFormatter::to_str );
    }
}
MemConcreteBuffer::~MemConcreteBuffer(){
    if( _mem != nullptr )
        delete [] _mem;
    _mem = nullptr;
}
uint8_t MemConcreteBuffer::read_u8(offset_t off){return *(uint8_t*)((uint8_t*)_mem+off);}
uint16_t MemConcreteBuffer::read_u16(offset_t off){return *(uint16_t*)((uint8_t*)_mem+off);}
uint32_t MemConcreteBuffer::read_u32(offset_t off){return *(uint32_t*)((uint8_t*)_mem+off);}
uint64_t MemConcreteBuffer::read_u64(offset_t off){return *(uint64_t*)((uint8_t*)_mem+off);}
int8_t MemConcreteBuffer::read_i8(offset_t off){return *(int8_t*)((uint8_t*)_mem+off);}
int16_t MemConcreteBuffer::read_i16(offset_t off){return *(int16_t*)((uint8_t*)_mem+off);}
int32_t MemConcreteBuffer::read_i32(offset_t off){return *(int32_t*)((uint8_t*)_mem+off);}
int64_t MemConcreteBuffer::read_i64(offset_t off){return *(int64_t*)((uint8_t*)_mem+off);}
void MemConcreteBuffer::write_u8(offset_t off, uint8_t val){*(uint8_t*)((uint8_t*)_mem+off) = val;}
void MemConcreteBuffer::write_u16(offset_t off, uint16_t val){*(uint16_t*)((uint8_t*)_mem+off) = val;}
void MemConcreteBuffer::write_u32(offset_t off, uint32_t val){*(uint32_t*)((uint8_t*)_mem+off) = val;}
void MemConcreteBuffer::write_u64(offset_t off, uint64_t val){*(uint64_t*)((uint8_t*)_mem+off) = val;}
void MemConcreteBuffer::write_i8(offset_t off, int8_t val){*(int8_t*)((uint8_t*)_mem+off) = val;}
void MemConcreteBuffer::write_i16(offset_t off, int16_t val){*(int16_t*)((uint8_t*)_mem+off) = val;}
void MemConcreteBuffer::write_i32(offset_t off, int32_t val){*(int32_t*)((uint8_t*)_mem+off) = val;}
void MemConcreteBuffer::write_i64(offset_t off, int64_t val){*(int64_t*)((uint8_t*)_mem+off) = val;}
void MemConcreteBuffer::write_buffer(offset_t off, uint8_t* buff, int nb_bytes){
    for( int i = 0; i < nb_bytes; i++){
        _mem[off+i] = buff[i];
    }
}
/* ==================================== */

/* Memory symbolic buffer 
   ======================

Symbolic expressions are stored in a hashmap <offset : (expr, byte_num)>. 
 - offset: is the offset in the buffer (the address) 
 - expr: expr is the expression written at address addr
 - byte_num: is the number of the particular octet of 'expr' that is at 
        address addr
  For example, assuming little endian,  writing v1 = exprvar(32, "var1")
  at offset 0x100 gives:
    - <0x100: (v1, 0)>
    - <0x101: (v1, 1)>
    - <0x102: (v1, 2)>
    - <0x103: (v1, 3)>

For read operations, if the value read overlaps between two different
expressions stored in memory, the class automatically concatenates/extracts
the corresponding parts.
*/
MemSymbolicBuffer::MemSymbolicBuffer(){
    _mem = symbolic_mem_map_t();
}
/* 1°) !! Reading function assumes little endian !!
 *  
 * 2°) !! This code assumes that the MemSymbolicBuffer has been used in a 
 * consistent way. In particular, if a read() operation is performed on 
 * an address range that has NOT been written, it will return wrong results
 * or more likely result in a crash. !! 
 * 
 * */
Expr MemSymbolicBuffer::read(offset_t off, unsigned int nb_bytes){
    int i = nb_bytes-1;
    int off_byte, low_byte; 
    Expr res = nullptr, tmp=nullptr;
    symbolic_mem_map_t::iterator it, it2;
    while( nb_bytes > 0 ){
        it = _mem.find(off+nb_bytes-1); // Take next byte 
        tmp = it->second.first; // Get associated expr
        off_byte = it->second.second; // Get associated exproffset
        low_byte = off_byte;
        /* Find until where the same expression is in memory */
        i = nb_bytes-1; 
        while( i >= 0 ){
            it2 = _mem.find(off+i); // Get expr
            if( it2->second.first->neq(tmp) ){
                /* Found different expr */
                if( res == nullptr ){
                    res = extract(tmp, (off_byte*8)+7, low_byte*8);
                }else{
                    res = concat(res, extract(tmp, (off_byte*8)+7, low_byte*8));
                }
                nb_bytes = i+1; // Updates nb bytes to read 
                break;
            }
            low_byte = it2->second.second; // Same expr, decrememnt exproffset counter
            if( low_byte == 0){
                /* Reached beginning of the memory write */
                if( res == nullptr ){
                    // If the size corresponds the the offset_byte, then use the whole expr
                    // Else extract lower bits 
                    res = ( tmp->size == (off_byte+1)*8 ? tmp : extract(tmp, (off_byte*8)+7, 0)); 
                }else{
                    res = concat(res,  ( tmp->size == (off_byte+1)*8 ? tmp : extract(tmp, (off_byte*8)+7, 0))); 
                }
                nb_bytes = i;
                break;
            }else{
                /* Not different expr, not beginning, continue to next */
                i--; // Go to prev offset 
            }
        }
        if( i < 0 ){
            /* We reached the requested address, so extract and return */
            if( res == nullptr ){
                res = extract(tmp, (off_byte*8)+7, low_byte*8);
            }else{
                res = concat(res, extract(tmp, (off_byte*8)+7, low_byte*8)); 
            }
            break;
        }
        /* Else just loop back and read next instruction */
    }
    return res;
}

void MemSymbolicBuffer::write(offset_t off, Expr e){
    for( offset_t i = 0; i < (e->size/8); i++ ){
        _mem[off+i] = std::make_pair(e, i);
    }
}
/* ==================================== */
MemSegment::MemSegment(addr_t s, addr_t e):start(s),end(e), _bitmap(MemStatusBitmap(e-s+1)), 
                        _concrete(MemConcreteBuffer(e-s+1)), _symbolic(MemSymbolicBuffer()), flags(MEM_FLAG_R | MEM_FLAG_W | MEM_FLAG_X) {
    name = "";
    if(start > end){
        throw mem_exception("Cannot create segment with start address bigger than end address");
    }
}
MemSegment::MemSegment(addr_t s, addr_t e, segment_flags_t f, string n):start(s),end(e), _bitmap(MemStatusBitmap(e-s+1)), 
                        _concrete(MemConcreteBuffer(e-s+1)), _symbolic(MemSymbolicBuffer()), flags(f) {
    name = n;
    if(start > end){
        throw mem_exception("Cannot create segment with start address bigger than end address");
    }
}

bool MemSegment::has_flags(segment_flags_t f ){return (f&flags) == f;}
bool MemSegment::contains(addr_t addr){
    return addr >= start && addr <= end;
}
Expr MemSegment::read(addr_t addr, unsigned int nb_bytes){
    offset_t off = addr - start;
    offset_t from = off, to, bytes_to_read;
    Expr tmp = nullptr, tmp2;
    do{
        /* Try if concrete or symbolic */
        to = _bitmap.is_concrete_until(from, nb_bytes);
        if( to != from ){
            /* Concrete */
            bytes_to_read = to-from; // Bytes that can be read as concrete
            if( bytes_to_read > nb_bytes ){ // We don't want more that what's left to read
                bytes_to_read = nb_bytes; 
            }
            nb_bytes -= bytes_to_read; // Update the number of bytes left to read
            /* Read */
            switch(bytes_to_read){
                case 1: tmp2 = exprcst(8, _concrete.read_i8(from)); break;
                case 2: tmp2 = exprcst(16, _concrete.read_i16(from)); break;
                case 3: tmp2 = exprcst(24, _concrete.read_i32(from) & 0x00ffffff); break; // Assumes little endian
                case 4: tmp2 = exprcst(32, _concrete.read_i32(from)); break;
                case 5: tmp2 = exprcst(40, _concrete.read_i64(from) & 0x000000ffffffffff); break; // Assumes little endian
                case 6: tmp2 = exprcst(48, _concrete.read_i64(from) & 0x0000ffffffffffff); break; // Assumes little endian
                case 7: tmp2 = exprcst(56, _concrete.read_i64(from) & 0x00ffffffffffffff); break;// Assumes little endian
                case 8: tmp2 = exprcst(64, _concrete.read_i64(from)); break;
                default: throw runtime_exception("MemSegment: should not be reading more than 8 bytes at a time!");
            }
            /* Update result */
            if( tmp == nullptr )
                tmp = tmp2;
            else
                tmp = concat(tmp2, tmp); // Assumes little endian
        }else{
            to = _bitmap.is_symbolic_until(from, nb_bytes);
            /* Symbolic */
            bytes_to_read = to-from; // Bytes that can be read as concrete
            if( bytes_to_read > nb_bytes ){ // We don't want more that what's left to read
                bytes_to_read = nb_bytes; 
            }
            nb_bytes -= bytes_to_read; // Update the number of bytes left to read
            /* Read */
            tmp2 = _symbolic.read(from, bytes_to_read);
            /* Update result */
            if( tmp == nullptr )
                tmp = tmp2;
            else
                tmp = concat(tmp2, tmp); // Assumes little endian
        }
        from += bytes_to_read;
    }while(nb_bytes > 0);
    return tmp;
}

cst_t MemSegment::concrete_snapshot(addr_t addr, int nb_bytes){
    offset_t off = addr - start;
    switch(nb_bytes){
        case 1: return _concrete.read_i8(off);
        case 2: return _concrete.read_i16(off);
        case 4: return _concrete.read_i32(off);
        case 8:
            return _concrete.read_i64(off);
        default: throw runtime_exception("MemSegment::concrete_snapshot with wrong size !");
    }
}


vector<pair<Expr, int>>* MemSegment::symbolic_snapshot(addr_t addr, int nb_bytes){
    vector<pair<Expr, int>>* res = new vector<pair<Expr, int>>();
    offset_t off = addr - start;
    for( int i = 0; i < nb_bytes; i++){
        if( _bitmap.is_symbolic(off+i) ){
            res->push_back(_symbolic._mem.find(off+i)->second);
        }else{
            res->push_back(std::make_pair(nullptr, 0));
        }
    }
    return res; 
}

void MemSegment::write(addr_t addr, Expr e, VarContext& ctx){
    cst_t concrete;
    offset_t off = addr - start;
    if( e->is_symbolic(ctx) || e->is_tainted()){
        /* Add symbolic value */
        _symbolic.write(off, e);
        /* Update the bitmap */
        _bitmap.mark_as_symbolic(off, off+(e->size/8)-1);
    }else{
        /* Update the bitmap */
        _bitmap.mark_as_concrete(off, off+(e->size/8)-1);
    }
    
    /* ALWAYS Add concrete value if possible (even if its tainted
     * in case it is code that'll be disassembled, but DON'T update
     * the bitmap */
    if( !e->is_symbolic(ctx)){
        concrete = e->concretize(&ctx);
        switch(e->size){
            case 8: _concrete.write_u8(off, concrete); break;
            case 16: _concrete.write_u16(off, concrete); break;
            case 32: _concrete.write_u32(off, concrete); break;
            case 64: _concrete.write_u64(off, concrete); break;
            default: throw runtime_exception(ExceptionFormatter() << "MemSegment: should not be writing expression of size" 
                                    << e->size << " bits " >> ExceptionFormatter::to_str );
                
        }
    }
}

void MemSegment::write(addr_t addr, uint8_t* src, int nb_bytes){
    offset_t off = addr-start;
    if( addr + nb_bytes -1 > end){
        throw mem_exception("MemSegment: buffer copy: nb_bytes exceeds segment");
    }
    _concrete.write_buffer(off, src, nb_bytes);
    _bitmap.mark_as_concrete(off, off+nb_bytes-1);
}

void MemSegment::write(addr_t addr, cst_t val, unsigned int nb_bytes){
    offset_t off = addr - start;
    if( nb_bytes == 1 ){
        _concrete.write_u8(off, val);
    }else if( nb_bytes == 2 ){
        _concrete.write_u16(off, val);
    }else if( nb_bytes == 4 ){
        _concrete.write_u32(off, val);
    }else if( nb_bytes == 8 ){
        _concrete.write_u64(off,val);
    }else{
        throw mem_exception(ExceptionFormatter() << "Trying to write a constant on " << nb_bytes << " bytes in memory, supported size is\
 only 1, 2, 4, or 8" >> ExceptionFormatter::to_str );
    }
}

void MemSegment::write_from_concrete_snapshot(addr_t addr, cst_t val, int nb_bytes){
    // !! Doesn't update the bitmap !!
    offset_t off = addr - start;
    switch(nb_bytes){
        case 1: _concrete.write_i8(off, val); break;
        case 2: _concrete.write_i16(off, val); break;
        case 4: _concrete.write_i32(off, val); break;
        case 8: _concrete.write_i64(off, val); break;
        default: throw runtime_exception("MemSegment::write_from_concrete_snapshot with wrong size !");
    }
}

void MemSegment::write_from_symbolic_snapshot(addr_t addr, vector<std::pair<Expr, int>>* snap){
    vector<std::pair<Expr, int>>::iterator it;
    offset_t off = addr - start, i = 0;
    for( it = snap->begin(); it != snap->end(); it++){
        if( it->first == nullptr )
            _bitmap.mark_as_concrete(off+i);
        else{
            _symbolic._mem[off+i] = *it;
            _bitmap.mark_as_symbolic(off+i);
        }
        i++;
    }
}

uint8_t* MemSegment::mem_at(addr_t addr){
    offset_t off = addr - start;
    return ((uint8_t*)_concrete._mem)+off;
}

/* Test status */
addr_t MemSegment::is_symbolic_until(addr_t addr1, addr_t addr2){
    return start + _bitmap.is_symbolic_until(addr1-start, addr2-start);
}
addr_t MemSegment::is_concrete_until(addr_t addr1, addr_t addr2){
    return start + _bitmap.is_concrete_until(addr1-start, addr2-start);
}

/* Compare start address of segments */
bool mem_segment_before(MemSegment* s1, MemSegment* s2){
    return s1->start < s2->start;
}



/* ==================================== */
MemEngine::MemEngine(VarContext* varctx, SnapshotManager* sm): _varctx(varctx),
        _snapshot_manager(sm){}

MemEngine::~MemEngine(){
    vector<MemSegment*>::iterator it; 
    for( it = _segments.begin(); it != _segments.end(); it++){
        delete *it;
        *it = nullptr; 
    }
}

void MemEngine::new_segment(addr_t start, addr_t end, segment_flags_t flags, string name){
    if( !is_free(start, end)){
        throw mem_exception("Trying to create a segment that overlaps with another segment");
    }
    MemSegment* seg = new MemSegment(start, end, flags, name);
    _segments.insert(std::lower_bound(_segments.begin(), _segments.end(), seg, mem_segment_before), seg);
}

vector<MemSegment*>& MemEngine::segments(){
    return _segments;
}

bool MemEngine::is_free(addr_t start, addr_t end){
    for( MemSegment* segment : _segments ){
        if( segment->start <= end && segment->end >= start )
            return false;
    }
    return true;
}

Expr MemEngine::read(addr_t addr, unsigned int nb_bytes){
    mem_alert_t junk;
    return read(addr, nb_bytes, junk);
}

Expr MemEngine::read(addr_t addr, unsigned int nb_bytes, mem_alert_t& alert){
    vector<MemSegment*>::iterator it;
    alert = 0;
    /* Find the segment we read from */
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(addr) ){
            /* Check flags */
            if( !( (*it)->has_flags(MEM_FLAG_R)))
                throw mem_exception(ExceptionFormatter() << "Reading at address 0x" << std::hex << addr << " in segment that doesn't have R flag set" << std::dec >> ExceptionFormatter::to_str);
            /* Return read */
            return (*it)->read(addr, nb_bytes);
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw mem_exception(ExceptionFormatter() << "Trying to read at address 0x" << std::hex << addr << " not mapped in memory" << std::dec >> ExceptionFormatter::to_str);
}

void MemEngine::write(addr_t addr, Expr e, VarContext* ctx){
    mem_alert_t junk;
    if( ctx == nullptr )
        write(addr, e, _varctx, junk);
    else
        write(addr, e, ctx, junk);
}

void MemEngine::write(addr_t addr, Expr e, VarContext* ctx, mem_alert_t& alert){
    vector<MemSegment*>::iterator it; 
    alert = 0;
    
    /* If breakpoints enabled record the write */
    if( _snapshot_manager ){
        _snapshot_manager->record_write(addr, e->size/8, *this);
    }
    
    /* Find the segment we write to */
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(addr) ){
            /* Check flags */
            if( !( (*it)->has_flags(MEM_FLAG_W)))
                throw mem_exception(ExceptionFormatter() << "Writing at address 0x" << std::hex << addr << " in segment that doesn't have W flag set" << std::dec >> ExceptionFormatter::to_str);
            /* If executable segment, set alert */
            if( (*it)->has_flags(MEM_FLAG_X))
                alert |= MEM_ALERT_X_OVERWRITE;
            /* Perform write*/
            (*it)->write(addr, e, *ctx);
            return;
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw mem_exception(ExceptionFormatter() << "Trying to write at address 0x" << std::hex << addr << " not mapped int memory" << std::dec >> ExceptionFormatter::to_str);
}

void MemEngine::write(addr_t addr, cst_t val, unsigned int nb_bytes, bool ignore_flags){
    mem_alert_t junk;
    write(addr, val, nb_bytes, junk, ignore_flags);
}

void MemEngine::write(addr_t addr, cst_t val, unsigned int nb_bytes, mem_alert_t& alert, bool ignore_flags){
    vector<MemSegment*>::iterator it; 
    alert = 0; 

    /* If breakpoints enabled record the write */
    if( _snapshot_manager ){
        _snapshot_manager->record_write(addr, nb_bytes, *this);
    }
    
    /* Find the segment we write to */
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(addr) ){
            /* Check flags */
            if( !( (*it)->has_flags(MEM_FLAG_W)) && !ignore_flags)
                throw mem_exception(ExceptionFormatter() << "Writing at address 0x" << std::hex << addr << " in segment that doesn't have W flag set" << std::dec >> ExceptionFormatter::to_str);
            /* If executable segment, set alert */
            if( (*it)->has_flags(MEM_FLAG_X))
                alert |= MEM_ALERT_X_OVERWRITE;
            /* Perform write*/
            (*it)->write(addr, val, nb_bytes);
            return;
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw mem_exception(ExceptionFormatter() << "Trying to write at address 0x" << std::hex << addr << " not mapped int memory" << std::dec >> ExceptionFormatter::to_str);

}

/* Memcpy */
void MemEngine::write(addr_t addr, uint8_t* src, int nb_bytes, bool ignore_flags){
    vector<MemSegment*>::iterator it;
    
    /* If breakpoints enabled record the write */
    if( _snapshot_manager ){
        _snapshot_manager->record_write(addr, nb_bytes, *this);
    }
    
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(addr) ){
            if( !ignore_flags && !(*it)->has_flags(MEM_FLAG_W )){
                throw mem_exception(ExceptionFormatter() << "Writing at address 0x" << std::hex << addr << " in segment that doesn't have W flag set" << std::dec >> ExceptionFormatter::to_str);
            }else{
                return (*it)->write(addr, src, nb_bytes);
            }
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw mem_exception(ExceptionFormatter() << "Trying to write at address 0x" << std::hex << addr << 
                                                    std::dec << " not mapped int memory" >> ExceptionFormatter::to_str);
}

string MemEngine::make_symbolic(addr_t addr, unsigned int nb_elems, unsigned int elem_size, string name){
    stringstream ss;
    vector<string> res;
    if( _varctx == nullptr ){
        throw runtime_exception("MemEngine::make_symbolic(): called with _varctx == NULL!");
    }
    if( elem_size != 1 && elem_size != 2 && elem_size != 4 && elem_size != 8 ){
        throw mem_exception(ExceptionFormatter() << "MemEngine::make_symbolic(): called with unsupported elem_size: " << elem_size >> ExceptionFormatter::to_str);
    }
    
    string new_name = _varctx->new_name_from(name);
    _varctx->set(new_name, -1); // Just set to say that this buffer name is taken

    for( unsigned int i = 0; i < nb_elems; i++){
        ss.str(""); ss.clear();
        ss << new_name << "_" << std::dec << i;
        write(addr + i*elem_size, exprvar(elem_size*8, ss.str()));
    }
    return new_name;
}


string MemEngine::make_tainted(addr_t addr, unsigned int nb_elems, unsigned int elem_size, string name){
    if( name.empty()){
        _make_tainted_no_var(addr, nb_elems, elem_size);
        return "";
    }else{
        return _make_tainted_var(addr, nb_elems, elem_size, name);
    }
}

void MemEngine::_make_tainted_no_var(addr_t addr, unsigned int nb_elems, unsigned int elem_size){
    Expr e;
    vector<string> res;
    if( _varctx == nullptr ){
        throw runtime_exception("MemEngine::_make_tainted_no_var(): called with _varctx == NULL!");
    }
    if( elem_size != 1 && elem_size != 2 && elem_size != 4 && elem_size != 8 ){
        throw mem_exception(ExceptionFormatter() << "MemEngine::_make_tainted_no_var(): called with unsupported elem_size: " << elem_size >> ExceptionFormatter::to_str);
    }
    for( unsigned int i = 0; i < nb_elems; i++){
        e = read(addr + i*elem_size, elem_size);
        e->make_tainted();
        write(addr + i*elem_size, e);
    }
}

string MemEngine::_make_tainted_var(addr_t addr, unsigned int nb_elems, unsigned int elem_size, string name){
    Expr e;
    stringstream ss;
    vector<string> res;
    if( _varctx == nullptr ){
        throw runtime_exception("MemEngine::_make_tainted_var(): called with _varctx == NULL!");
    }
    if( elem_size != 1 && elem_size != 2 && elem_size != 4 && elem_size != 8 ){
        throw mem_exception(ExceptionFormatter() << "MemEngine::_make_tainted_var(): called with unsupported elem_size: " << elem_size >> ExceptionFormatter::to_str);
    }

    string new_name = _varctx->new_name_from(name);
    _varctx->set(new_name, -1); // Just set to say that this buffer name is taken

    for( unsigned int i = 0; i < nb_elems; i++){
        ss.str(""); ss.clear();
        ss << new_name << "_" << std::dec << i;
        e = read(addr + i*elem_size, elem_size);
        _varctx->set(ss.str(), e->concretize(_varctx)); // Save the concrete value
        write(addr + i*elem_size, exprvar(elem_size*8, ss.str(), Taint::TAINTED)); // Write the new exprvar
    }
    
    return new_name;
}

cst_t MemEngine::concrete_snapshot(addr_t addr, int nb_bytes){
    vector<MemSegment*>::iterator it;
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(addr) ){
            return (*it)->concrete_snapshot(addr, nb_bytes);
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw runtime_exception(ExceptionFormatter() << "Trying to concrete-snapshot address 0x" << std::hex << addr << 
                                                    " not mapped int memory" << std::dec >> ExceptionFormatter::to_str);
    
}

vector<std::pair<Expr, int>>* MemEngine::symbolic_snapshot(addr_t addr, int nb_bytes){
    vector<MemSegment*>::iterator it;
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(addr) ){
            return (*it)->symbolic_snapshot(addr, nb_bytes);
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw runtime_exception(ExceptionFormatter() << "Trying to symbolic-snapshot address " << std::hex << addr << 
                                                    " not mapped int memory" >> ExceptionFormatter::to_str);
}
void MemEngine::write_from_concrete_snapshot(addr_t addr, cst_t val, int nb_bytes, mem_alert_t& alert){
    vector<MemSegment*>::iterator it;
    alert = MEM_ALERT_NONE;
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(addr) ){
            if( (*it)->has_flags(MEM_FLAG_X)){
                alert |= MEM_ALERT_X_OVERWRITE;
            }
            (*it)->write_from_concrete_snapshot(addr, val, nb_bytes);
            return;
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw runtime_exception(ExceptionFormatter() << "Trying to restore from concrete-snapshot at address 0x" << std::hex << addr << 
                                                    " not mapped int memory" << std::dec >> ExceptionFormatter::to_str);
}


void MemEngine::write_from_symbolic_snapshot(addr_t addr, vector<std::pair<Expr, int>>* snap, mem_alert_t& alert){
    vector<MemSegment*>::iterator it;
    alert = MEM_ALERT_NONE;
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(addr) ){
            if( (*it)->has_flags(MEM_FLAG_X)){
                alert |= MEM_ALERT_X_OVERWRITE;
            }
            (*it)->write_from_symbolic_snapshot(addr, snap);
            return;
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw runtime_exception(ExceptionFormatter() << "Trying to restore from symbolic-snapshot at address 0x" << std::hex << addr << 
                                                    " not mapped int memory" >> ExceptionFormatter::to_str);
}

uint8_t* MemEngine::mem_at(addr_t addr){
    vector<MemSegment*>::iterator it;
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(addr) ){
            return (*it)->mem_at(addr);
        }
    }
    /* If addr isn't in any segment, throw exception */
    throw runtime_exception(ExceptionFormatter() << "Trying to get raw pointer of address 0x" << std::hex << addr << 
                                                    " not mapped int memory" >> ExceptionFormatter::to_str);
}

void MemEngine::check_status(addr_t start, addr_t end, VarContext& varctx, bool& is_symbolic, bool& is_tainted){
    vector<MemSegment*>::iterator it;
    if( start > end ){
        throw runtime_exception("MemEngine::check_mem_status(): got start bigger than end");
    }
    is_symbolic = false;
    is_tainted = false;
    Expr e;
    addr_t start_sym = start;
    /* Find the segment */
    for( it = _segments.begin(); it != _segments.end(); it++){
        if( (*it)->contains(start) ){
            if( (start_sym = (*it)->is_concrete_until(start, end)) < end+1 ){
                // If not full concrete check the not concrete bytes
                while( start_sym <= end ){
                    e = read(start_sym, 1);
                    if( e->is_tainted() ){
                        is_tainted = true;
                    }
                    if( e->is_symbolic(varctx)){
                        is_symbolic = true;
                        return; // Break as soon as symbolic code detected
                    }
                    start_sym++;
                }
            }
            return; 
        }
    }
}

string _mem_flags_to_string(segment_flags_t flags){
    stringstream ss;
    if( flags & MEM_FLAG_R )
        ss << "R";
    else
        ss << "-";
        
    if( flags & MEM_FLAG_W )
        ss << "W";
    else
        ss << "-";
    
    if( flags & MEM_FLAG_X )
        ss << "X";
    else
        ss << "-";    
    return ss.str();
}

ostream& operator<<(ostream& os, MemEngine& mem){
    unsigned int addr_w = 20;
    os << std::endl << std::left << std::setw(addr_w) << "Start" << std::left << std::setw(addr_w) << "End" 
       << std::left << std::setw(8) << "Perm." << std::left << std::setw(8) << "Name" << std::endl;
    os << std::left << std::setw(addr_w) << "-----" << std::left << std::setw(addr_w) << "---" 
       << std::left << std::setw(8) << "-----" << std::left << std::setw(8) << "----" << std::endl;
    for( MemSegment* segment : mem._segments ){
        os << std::hex << "0x" << std::left << std::setw(addr_w-2) << segment->start << "0x" << std::left << std::setw(addr_w-2) << segment->end 
           << std::left << std::setw(8) << _mem_flags_to_string(segment->flags);
        if( !segment->name.empty() )
            os << segment->name;
        os << std::endl;
    }
    return os;
}
