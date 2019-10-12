#ifndef MEMORY_H
#define MEMORY_H

#include "expression.hpp"
#include <cstdint>
#include <unordered_map>
#include <iomanip>
#include <iostream>
#include "typedefs.hpp"

using std::pair; 
using std::vector;
using std::tuple;

#include "snapshot.hpp" 

/* Memory symbolic status
   ======================

This class is used to keep track of the symbolic or concrete state
of memory. Each bit represents one address (BYTE PTR). A bit to one 
means that the value at the corresponding address is symbolic, a bit to
zero means that is has been concretized. 

Each byte in the bitmap represents a QWORD, so 8 bytes. The lower address
is represented as the lowest significant bit of the bitmap byte. The 
higher address is represented by the highest significant bit. 

            HSB           LSB
             0 0 1 0 0 0 1 1
    0x107----*     *       *--- 0x100
                   *--- 0x104

!! is_concrete_until() and is_symbolic_until() functions take a 'max' 
parameter. This parameter specifies the maximum number of bytes we want 
to check for before returning. It is used to reduce the overhead that
appears when checking a huge memory area of the same type when we want 
to write only a few bytes. Therefore, for performance reasons, it is possible
that the function returns an offset bigger than off+nb_bytes-1, just
keep that in mind when using it.

*/
class MemStatusBitmap{
    uint8_t * _bitmap;
    unsigned int _size;
public:
    MemStatusBitmap();
    MemStatusBitmap(offset_t nb_bytes);
    ~MemStatusBitmap();
    void mark_as_symbolic(offset_t off);
    void mark_as_symbolic(offset_t start, offset_t end);
    void mark_as_concrete(offset_t off);
    void mark_as_concrete(offset_t start, offset_t end);
    bool is_symbolic(offset_t off);
    bool is_concrete(offset_t off);
    offset_t is_symbolic_until(offset_t off, unsigned int max=0xffffffff);
    offset_t is_concrete_until(offset_t off, unsigned int max=0xffffffff);
};

/* Memory concrete buffer 
   ======================

This class represents a concrete memory area. It's basically a wrapper 
around a buffer that enables to read/write constants of different sizes

!! For performance reasons, no real checks are performed on the r/w 
operations, so it is up to the caller to verify that the arguments passed
are consistent.
*/

class MemConcreteBuffer{
friend class MemSegment;
    
    uint8_t* _mem;
public:
    MemConcreteBuffer();
    MemConcreteBuffer(offset_t nb_bytes);
    ~MemConcreteBuffer();
    /* Reading memory */
    uint8_t read_u8(offset_t off);
    uint16_t read_u16(offset_t off);
    uint32_t read_u32(offset_t off);
    uint64_t read_u64(offset_t off);
    int8_t read_i8(offset_t off);
    int16_t read_i16(offset_t off);
    int32_t read_i32(offset_t off);
    int64_t read_i64(offset_t off);
    /* Writing memory */
    void write_u8(offset_t off, uint8_t val);
    void write_u16(offset_t off, uint16_t val);
    void write_u32(offset_t off, uint32_t val);
    void write_u64(offset_t off, uint64_t val);
    void write_i8(offset_t off, int8_t val);
    void write_i16(offset_t off, int16_t val);
    void write_i32(offset_t off, int32_t val);
    void write_i64(offset_t off, int64_t val);
    void write_buffer(offset_t off, uint8_t* buff, int nb_bytes); 
};

/* Memory symbolic buffer 
   ======================

This class represents a memory area where symbolic expressions are stored.
It enables to read/write any expression of size 8, 16, 32, or 64 bits.
More details about the implementation are found in the .cpp file. 

!! For performance reasons, no real checks are performed on the r/w 
operations, so it is up to the caller to verify that the arguments passed
are consistent.
*/

class MemSymbolicBuffer{
friend class MemSegment;    

    symbolic_mem_map_t _mem;
public:
    MemSymbolicBuffer();
    /* Reading memory */
    Expr read(offset_t off, unsigned int nb_bytes);
    /* Writing memory */
    void write(offset_t addr, Expr e);
};

#define MEM_FLAG_R 1U
#define MEM_FLAG_W 2U
#define MEM_FLAG_RW 3U
#define MEM_FLAG_X 4U
#define MEM_FLAG_RX 5U
#define MEM_FLAG_WX 6U
#define MEM_FLAG_RWX 7U

/* Memory segment
   ==============

This class is an wrapper that represents a mapped memory segment. It can
be used transparently to write and read both symbolic and concrete
expressions. To do so, it uses a concrete buffer, a symbolic buffer, and 
a memory status bitmap to keep track of what is symbolic and what is
concrete 

A segment has start/end addresses (included), and RWX flags.
*/

class MemSegment{
    MemStatusBitmap _bitmap;
    MemConcreteBuffer _concrete;
    MemSymbolicBuffer _symbolic;
public:
    addr_t start;
    addr_t end;
    segment_flags_t flags;
    string name;
    
    MemSegment(addr_t start, addr_t end);
    MemSegment(addr_t start, addr_t end, segment_flags_t flags, string n=" ");
    bool contains(addr_t addr);
    /* Reading memory */
    Expr read(addr_t addr, unsigned int nb_bytes);
    /* Writing memory */
    void write(addr_t addr, Expr e, VarContext& ctx);
    void write(addr_t addr, cst_t val, unsigned int nb_bytes);
    
    /* Memcpy */
    void write(addr_t addr, uint8_t* src, int nb_bytes);
    
    /* Special reading and writing (for snapshoting) */
    vector<std::pair<Expr, int>>* symbolic_snapshot(addr_t addr, int nb_bytes);
    cst_t concrete_snapshot(addr_t addr, int nb_bytes);
    void write_from_concrete_snapshot(addr_t addr, cst_t val, int nb_bytes);
    void write_from_symbolic_snapshot(addr_t addr, vector<std::pair<Expr, int>>* snap);
    
    /* Raw pointer to concrete buffer */
    uint8_t* mem_at(addr_t addr);
    
    /* Test flags */
    bool has_flags(segment_flags_t f);

    /* Test status */
    addr_t is_symbolic_until(addr_t start, addr_t end);
    addr_t is_concrete_until(addr_t start, addr_t end);
};

#define MEM_ALERT_NONE 0x0 /* No alert */
#define MEM_ALERT_X_OVERWRITE 0x1 /* Writting in executable segment */

/* Memory Engine
   =============

A full memory engine consisting in several memory segments. It is possible
to add segments and read/write into them.

The _save vector is used to take micro snapshots everytime we write something
in memory. This is used by the symbolic engine when dealing with breakpoints.
Memory operations need to be recorded in case some would need to be rewinded
when a breakpoint is hit. The record_changes boolean variables indicates if
changes need to be recorded or not.

*/

/* Type aliasing */ 
typedef tuple<addr_t, cst_t, vector<pair<Expr, int>>*> mem_write_event_t;

class MemEngine{
friend class SymbolicEngine;
friend class BreakpointManager;    
    vector<MemSegment*> _segments;
    VarContext* _varctx; // Not owned
    SnapshotManager * _snapshot_manager; // Not owned
public:
    MemEngine(VarContext * varctx=nullptr, SnapshotManager* sm=nullptr);
    ~MemEngine();
    
    void new_segment(addr_t start, addr_t end, segment_flags_t flags=MEM_FLAG_RWX, string name=" ");
    vector<MemSegment*>& segments();
    bool is_free(addr_t start, addr_t end);
    
    /* Normal read/write */
    Expr read(addr_t addr, unsigned int nb_bytes); 
    void write(addr_t addr, Expr e, VarContext* varctx=nullptr);
    void write(addr_t addr, cst_t val, unsigned int nb_bytes, bool ignore_flags=false);
    Expr read(addr_t addr, unsigned int nb_bytes, mem_alert_t& alert);
    void write(addr_t addr, Expr e, VarContext* ctx, mem_alert_t& alert);
    void write(addr_t addr, cst_t val, unsigned int nb_bytes, mem_alert_t& alert, bool ignore_flags=false);
    
    /* Other */
    // Make a buffer purely symbolic, return the name of the buffer: buffname_*
    string make_symbolic(addr_t addr, unsigned int nb_elems, unsigned int elem_size,  string name);
    // Make a buffer tainted and give it a name
    string make_tainted(addr_t addr, unsigned int nb_elems, unsigned int elem_size, string name="");
    void _make_tainted_no_var(addr_t addr, unsigned int nb_elems, unsigned int elem_size);
    string _make_tainted_var(addr_t addr, unsigned int nb_elems, unsigned int elem_size, string name);
    
    /* Memcpy */
    void write(addr_t addr, uint8_t* src, int nb_bytes, bool ignore_flags=false);
    
    /* Special reading and writing (for snapshoting) */
    vector<std::pair<Expr, int>>* symbolic_snapshot(addr_t addr, int nb_bytes);
    cst_t concrete_snapshot(addr_t addr, int nb_bytes);
    void write_from_concrete_snapshot(addr_t addr, cst_t val, int nb_bytes, mem_alert_t& alert);
    void write_from_symbolic_snapshot(addr_t addr, vector<std::pair<Expr, int>>* snap, mem_alert_t& alert);

    /* Getting pointers to the raw concrete buffers */
    uint8_t * mem_at(addr_t addr);
    
    /* Check memory status between start and end (included), if it is symbolic/concrete/tainted 
     * If at least one byte is symbolic, set is_symbolic
     * It at least one byte is tainted, set is_tainted */
    void check_status(addr_t start, addr_t end, VarContext& varctx, bool& is_symbolic, bool& is_tainted);
    
    /* Printing */
    friend ostream& operator<<(ostream& os, MemEngine& mem);
};
#endif
