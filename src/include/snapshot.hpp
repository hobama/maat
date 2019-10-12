#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include "memory.hpp"
#include "expression.hpp"
#include "instruction.hpp"
#include "breakpoint.hpp"
#include "block.hpp"
#include "irstate.hpp"
#include <vector>

using std::pair;
using std::vector;
using std::tuple;
using std::string;

class IRBlock;

/* Type aliasing */ 
typedef tuple<addr_t, cst_t, vector<pair<Expr, int>>*> mem_write_event_t;
typedef unsigned int snapshot_id_t;

#include "symbolic.hpp"

/* Snapshot
   ========

A snapshot is used to save the memory and variables state at some point.

A snapshot has a pointer to an IRContext that and that contains
the values of the IR Variables when the snapshot is taken. The snapshots
owns the ctx, so it should delete it in the constructor. 

Instead of copying the whole memory the snapshot holds a vector of 
mem_write_event_t objects. They are basically record at which address the
memory was written, and what where the (symbolic and concrete) values at
this address before the write 

A snapshot also holds the addresse of the next instruction to be executed
we starting back from it. 

*/

class Snapshot{
public:
    IRContext* ctx;
    snapshot_id_t path_snapshot_id;
    snapshot_id_t env_snapshot_id;
    vector<mem_write_event_t> mem_writes;
    IRState irstate;
    BreakpointRecord bp_record;
    Snapshot(IRContext* ctx, IRState& irs, snapshot_id_t path_snapshot_id=0, snapshot_id_t env_snapshot_id=0);
};

/* SnapshotManager
   ===============

A snapshot is an object with a simple interface that holds a series of 
snapshots

A snapshot can be taken with the take_snapshot() function

The record_write() records a memory write in the last snapshot taken

The rewind() function restores memory and variables to their state in the
last snapshot saved and then deletes the last snapshot

 */

#define MAX_SNAPSHOTS 2000000
class SnapshotManager{
    vector<Snapshot> _snapshots;
public:
    snapshot_id_t take_snapshot(SymbolicEngine& sym);
    void record_write(addr_t addr, int nb_bytes, MemEngine& mem);
    bool rewind(SymbolicEngine& sym, bool remove=false);
    bool restore(snapshot_id_t snapshot_id, SymbolicEngine& sym, bool remove=false);
    bool is_active();
};

#endif
