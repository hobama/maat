#include "memory.hpp"
#include "symbolic.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

using std::cout;
using std::endl; 
using std::string;

namespace test{
    namespace symbolic{
        
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int snapshot(){
            MemEngine* mem = new MemEngine();
            VarContext* varctx = new VarContext(0);
            IRContext* irctx = new IRContext(2);
            PathManager* path = new PathManager();
            Expr    e1 = exprvar(32, "var0"),
                    e2 = exprvar(64, "var1", Taint::TAINTED), 
                    c1 = exprcst(64, 0x12345678c0c0babe);
            SnapshotManager snap = SnapshotManager();
            IRManager* irmanager = new IRManager(); 
            SymbolicEngine sym = SymbolicEngine(nullptr, irmanager, varctx, irctx, mem, path);
            snapshot_id_t s1, s2;
            unsigned int nb = 0;
            // Init 
            varctx->set("var0", 0x41414141);
            irctx->set(0, e1);
            irctx->set(1, e2);
            mem->new_segment(0x2000, 0x2fff);
            mem->write(0x21b4, e2, varctx);
            // Snapshot
            s1 = snap.take_snapshot(sym);
            // Do some more writes
            snap.record_write(0x21b6, 8, *mem);
            mem->write(0x21b6, c1, varctx);
            snap.record_write(0x21b4, 4, *mem);
            mem->write(0x21b4, e1, varctx);
            snap.restore(s1, sym);
            // Rewind
            nb += _assert(mem->read(0x21b4, 8)->eq(e2), "SnapshotManager rewind failed to reset memory correctly"); 
            
            // Write and snapshot two times
            mem->write(0x2200, c1, varctx);
            s1 = snap.take_snapshot(sym);
            
            snap.record_write(0x2204, 8, *mem);
            mem->write(0x2204, c1, varctx);
            irctx->set(0, e1+e1);
            irctx->set(1,e2+c1);
            s2 = snap.take_snapshot(sym);
            
            irctx->set(0, e1*e1);
            snap.record_write(0x2207, 8, *mem);
            mem->write(0x2207, e2, varctx);
            
            snap.restore(s2, sym, true);
            nb += _assert(mem->read(0x2204, 8)->eq(c1), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(mem->read(0x2200, 8)->eq(exprcst(64, 0xc0c0babec0c0babe)), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(irctx->get(0)->eq( e1+e1), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(irctx->get(1)->eq(c1+e2), "SnapshotManager: rewind failed for two consecutive snapshots");
            
            snap.restore(s1, sym, true);
            nb += _assert(irctx->get(0)->eq(e1), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(irctx->get(1)->eq(e2), "SnapshotManager: rewind failed for two consecutive snapshots");
            nb += _assert(mem->read(0x2200, 8)->eq(c1), "SnapshotManager: rewind failed for two consecutive snapshots");
            
            // Rewind on mixed symbolic and concrete memory writes
            mem->write(0x2300, c1, varctx);
            mem->write(0x22fa, e2, varctx);
            mem->write(0x2302, e1, varctx);
            s1 = snap.take_snapshot(sym);
            
            snap.record_write(0x22fc, 8, *mem);
            mem->write(0x22fc, exprcst(64, 0x4141414141414141), varctx);
            snap.record_write(0x2306, 8, *mem);
            mem->write(0x2306, exprcst(64, 0x4141414141414141), varctx);
            snap.record_write(0x2302, 8, *mem);
            mem->write(0x2302, exprvar(64, "var3", Taint::TAINTED), varctx);
            s2 = snap.take_snapshot(sym);
            
            snap.restore(s1, sym);
            
            nb += _assert(mem->read(0x2300, 2)->eq(extract(e2, 63, 48)), "SnapshotManager: rewind failed for mixed symbolic and concrete writes");
            nb += _assert(mem->read(0x2300, 8)->eq(concat( exprcst(48, 0x123441414141 ), extract(e2, 63, 48))), "SnapshotManager: rewind failed for mixed symbolic and concrete writes");
            
            return nb;
        }
        
        unsigned int snapshot_X86(){
            unsigned int nb = 0;
            SymbolicEngine sym = SymbolicEngine(ArchType::X86);
            snapshot_id_t s1, s2, s3;
            /* Code to execute 
                0:  89 d8                   mov    eax,ebx
                2:  01 d1                   add    ecx,edx
                4:  89 15 00 20 00 00       mov    DWORD PTR ds:0x2000,edx
                a:  29 15 00 30 00 00       sub    DWORD PTR ds:0x3000,edx
                10: 53                      push   ebx
                11: 89 d3                   mov    ebx,edx
                13: ba 02 00 00 00          mov    edx,0x2
                18: 90                      nop
                19: 0b 0e                   jmp 0x10
                * 
                * { 0x89, 0xD8, 0x01, 0xD1, 0x89, 0x15, 0x00, 0x20, 0x00, 0x00, 0x29, 0x15, 0x00, 0x30, 0x00, 0x00, 0x53, 0x89, 0xD3, 0xBA, 0x02, 0x00, 0x00, 0x00, 0x90, 0xeb, 0x0e}
                * 
                * "\x89\xD8\x01\xD1\x89\x15\x00\x20\x00\x00\x29\x15\x00\x30\x00\x00\x53\x89\xD3\xBA\x02\x00\x00\x00\x90\xeb\x0e"
            */
            
            /* Initialize */
            uint8_t code[27] = { 0x89, 0xD8, 0x01, 0xD1, 0x89, 0x15, 0x00, 0x20, 0x00, 0x00, 0x29, 0x15, 0x00, 0x30, 0x00, 0x00, 0x53, 0x89, 0xD3, 0xBA, 0x02, 0x00, 0x00, 0x00, 0x90, 0xeb, 0x0e };
            sym.regs->set(X86_EAX, exprcst(32, 1));
            sym.regs->set(X86_EBX, exprcst(32, 2));
            sym.regs->set(X86_ECX, exprcst(32, 3));
            sym.regs->set(X86_EDX, exprcst(32, 4));
            sym.regs->set(X86_ESP, exprcst(32, 0x4000));
            
            sym.mem->new_segment(0x0000, 0x4000, MEM_FLAG_RW);
            sym.mem->write(0x2000, exprcst(32, 0x12345678), sym.vars);
            sym.mem->write(0x3000, exprcst(32, 0x87654321), sym.vars);
            
            sym.mem->new_segment(0x5000, 0x5100, MEM_FLAG_RWX);
            sym.mem->write(0x5000, code, sizeof(code));
            
            /* Set breakpoint */
            sym.breakpoint.add(BreakpointType::ADDR, "end", 0x5000+0x18);
            
            /* Take snapshots */
            s1 = sym.take_snapshot();
            sym.execute_from(0x5000, 3);
            s2 = sym.take_snapshot();
            sym.execute(3);
            s3 = sym.take_snapshot();
            sym.execute();
            
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT && sym.info.breakpoint == "end" , "Snapshot X86: failed to hit end breakpoint");
            nb += _assert(sym.regs->concretize(X86_EAX) != 1, "Snapshot X86: unexpected state");
            nb += _assert(sym.regs->concretize(X86_EBX) != 2, "Snapshot X86: unexpected state");
            nb += _assert(sym.regs->concretize(X86_ECX) != 3, "Snapshot X86: unexpected state");
            nb += _assert(sym.regs->concretize(X86_EDX) != 4, "Snapshot X86: unexpected state");
            nb += _assert((uint32_t)sym.mem->read(0x2000, 4)->concretize(sym.vars) == 4, "Snapshot X86: unexpected state");
            nb += _assert((uint32_t)sym.mem->read(0x3000, 4)->concretize(sym.vars) == 0x8765431d, "Snapshot X86: unexpected state");
            
            /* Restore last */
            sym.restore_snapshot(s3, true);
            nb += _assert(sym.regs->concretize(X86_EDX) == 4, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_EAX) != 1, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_EBX) != 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_ECX) != 3, "Snapshot X86: failed to restore snapshot");
            nb += _assert((uint32_t)sym.mem->read(0x2000, 4)->concretize(sym.vars) != 0x12345678, "Snapshot X86: failed to restore snapshot");
            nb += _assert((uint32_t)sym.mem->read(0x3000, 4)->concretize(sym.vars) != 0x87654321, "Snapshot X86: failed to restore snapshot");
            
            /* Restore again */
            sym.restore_snapshot();
            nb += _assert(sym.regs->concretize(X86_EDX) == 4, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_EAX) == 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_EBX) == 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_ECX) == 7, "Snapshot X86: failed to restore snapshot");
            nb += _assert((uint32_t)sym.mem->read(0x2000, 4)->concretize(sym.vars) == 4, "Snapshot X86: failed to restore snapshot");
            nb += _assert((uint32_t)sym.mem->read(0x3000, 4)->concretize(sym.vars) == 0x87654321, "Snapshot X86: failed to restore snapshot");
            
            /* Restore to first */
            sym.restore_snapshot(s1, true);
            nb += _assert(sym.regs->concretize(X86_EDX) == 4, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_EAX) == 1, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_EBX) == 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_ECX) == 3, "Snapshot X86: failed to restore snapshot");
            nb += _assert((uint32_t)sym.mem->read(0x2000, 4)->concretize(sym.vars) == 0x12345678, "Snapshot X86: failed to restore snapshot");
            nb += _assert((uint32_t)sym.mem->read(0x3000, 4)->concretize(sym.vars) == 0x87654321, "Snapshot X86: failed to restore snapshot");
            
            /* ====== same code with some symbolic registers */
            sym.regs->set(X86_EAX, exprcst(32, 1));
            sym.regs->set(X86_EBX, exprcst(32, 2));
            sym.regs->set(X86_ECX, exprcst(32, 3));
            sym.regs->set(X86_EDX, exprvar(32, "edx"));
            sym.vars->remove("edx");
            sym.regs->set(X86_ESP, exprcst(32, 0x4000));
            
            /* Take snapshots */
            s1 = sym.take_snapshot();
            sym.execute_from(0x5000, 3);
            s2 = sym.take_snapshot();
            sym.execute(3);
            s3 = sym.take_snapshot();
            sym.execute();

            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT && sym.info.breakpoint == "end" , "Snapshot X86: failed to hit end breakpoint");
            nb += _assert(sym.regs->concretize(X86_EAX) != 1, "Snapshot X86: unexpected state");
            nb += _assert(sym.regs->get(X86_EBX)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");
            nb += _assert(sym.regs->get(X86_ECX)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");
            nb += _assert(!sym.regs->get(X86_EDX)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");
            nb += _assert(sym.regs->concretize(X86_EDX) == 2, "Snapshot X86: unexpected state");
            nb += _assert(sym.mem->read(0x2000, 4)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");
            nb += _assert(sym.mem->read(0x3000, 4)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");

            sym.restore_snapshot(s2);
            nb += _assert(!sym.regs->get(X86_EBX)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");
            nb += _assert(sym.regs->concretize(X86_EBX) == 2, "Snapshot X86: unexpected state");
            nb += _assert(sym.regs->get(X86_ECX)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");
            nb += _assert(sym.regs->get(X86_EDX)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");
            nb += _assert(sym.mem->read(0x2000, 4)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");
            nb += _assert(!sym.mem->read(0x3000, 4)->is_symbolic(*sym.vars), "Snapshot X86: unexpected state");
            nb += _assert((uint32_t)sym.mem->read(0x3000, 4)->concretize(sym.vars) == 0x87654321, "Snapshot X86: failed to restore snapshot");
            
            sym.restore_snapshot(s1, true);
            nb += _assert(sym.regs->get(X86_EDX)->is_symbolic(*sym.vars), "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_EAX) == 1, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_EBX) == 2, "Snapshot X86: failed to restore snapshot");
            nb += _assert(sym.regs->concretize(X86_ECX) == 3, "Snapshot X86: failed to restore snapshot");
            nb += _assert((uint32_t)sym.mem->read(0x2000, 4)->concretize(sym.vars) == 0x12345678, "Snapshot X86: failed to restore snapshot");
            nb += _assert((uint32_t)sym.mem->read(0x3000, 4)->concretize(sym.vars) == 0x87654321, "Snapshot X86: failed to restore snapshot");
            
            return nb;
        }
        
        
        unsigned int assignment_operations_64bits(){
            unsigned int nb = 0;
            /* DEBUG comment until ArchX64 implemented
            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(0);
            IRContext* irctx = new IRContext(8);
            Arch* arch = new ArchX64();
            Expr    e0 = exprvar(64, "var0"),
                    e1 = exprvar(64, "var1", ExprStatus::SYMBOLIC, Taint::TAINTED), 
                    e2 = exprvar(64, "var2", ExprStatus::SYMBOLIC, Taint::TAINTED),
                    e3 = exprvar(64, "var3"),
                    e4 = exprvar(64, "var4"),
                    e5 = exprvar(64, "var5"),
                    e6 = exprvar(64, "var6"),
                    e7 = exprvar(64, "var7"),
                    c1 = exprcst(64, 0x12345678c0c0babe),
                    c2 = exprcst(64, 0xdeadface12345678);
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            irctx->set(4, e4);
            irctx->set(5, e5);
            irctx->set(6, e6);
            irctx->set(7, e7);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            
            // Create basic block 
            IRBlock* block = new IRBlock("at_0x0");
            IRBasicBlockId bblkid = block->new_bblock();
            // v0 <- v0 + v1
            block->add_instr(bblkid, IRInstruction(IROperation::ADD, IROperand(IROperandType::VAR, 0, 63, 0),
                                IROperand(IROperandType::VAR, 0, 63, 0), IROperand(IROperandType::VAR, 1, 63, 0)));
            // v1 <- 0x1235 - 0x1234
            block->add_instr(bblkid, IRInstruction(IROperation::SUB, IROperand(IROperandType::VAR, 1, 63, 0),
                                IROperand(IROperandType::CST, 0x1235, 63, 0), IROperand(IROperandType::CST, 0x1234, 63, 0)));
            // v2 <- v0 / v3
            block->add_instr(bblkid, IRInstruction(IROperation::DIV, IROperand(IROperandType::VAR, 2, 63, 0),
                                IROperand(IROperandType::VAR, 0, 63, 0), IROperand(IROperandType::VAR, 3, 63, 0)));
            // v4 <- v4 , const
            block->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 4, 31, 0),
                                IROperand(IROperandType::CST, 0x41414141, 31, 0), IROperand()));
            // v5 <- concst, v5
            block->add_instr(bblkid, IRInstruction(IROperation::MUL, IROperand(IROperandType::VAR, 5, 63, 32),
                                IROperand(IROperandType::CST, 0x2, 31, 0), IROperand(IROperandType::CST, 0x3, 31, 0)));
            
            // Use tmp variables 
            // tmp0 <- -v6
            block->add_instr(bblkid, IRInstruction(IROperation::NEG, IROperand(IROperandType::TMP, 0, 63, 0),
                                IROperand(IROperandType::VAR, 6, 63, 0), IROperand()));
            // tmp1 <- ~v7 
            block->add_instr(bblkid, IRInstruction(IROperation::NOT, IROperand(IROperandType::TMP, 1, 63, 0),
                                IROperand(IROperandType::VAR, 7, 63, 0), IROperand()));
            // v7 <- tmp0
            block->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 7, 63, 0),
                                IROperand(IROperandType::TMP, 0, 63, 0), IROperand()));
            // v6 <- tmp1
            block->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 6, 63, 0),
                                IROperand(IROperandType::TMP, 1, 63, 0), IROperand()));
            irm->add(0x0, block);
            sym.execute_from(0x0);
            
            // Test 
            nb += _assert(irctx->get(0) == e0 + e1, "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(1) == exprcst(64,0x1235)-exprcst(64, 0x1234), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(2) == (e0+e1) / e3, "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(3) == e3, "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(4) == concat(extract(e4, 63, 32), exprcst(32, 0x41414141)), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(5) == concat(exprcst(32, 0x2)*exprcst(32,0x3), extract(e5, 31, 0)), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(6) == ~e7, "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(7) == -e6, "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            */
            return nb;
        }
        
        unsigned int assignment_operations_32bits(){
            unsigned int nb = 0;
            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30);
            Arch* arch = new ArchX86();
            Expr    e0 = exprvar(32, "var0"),
                    e1 = exprvar(32, "var1", Taint::TAINTED), 
                    e2 = exprvar(32, "var2", Taint::TAINTED),
                    e3 = exprvar(32, "var3"),
                    e4 = exprvar(32, "var4"),
                    e5 = exprvar(32, "var5"),
                    e6 = exprvar(32, "var6"),
                    e7 = exprvar(32, "var7"),
                    c1 = exprcst(32, 0xc0c0babe),
                    c2 = exprcst(32, 0xdeadface);
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            irctx->set(4, e4);
            irctx->set(5, e5);
            irctx->set(6, e6);
            irctx->set(7, e7);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            
            // Create basic block 
            IRBlock* block = new IRBlock("at_0x0", 0, 100);
            IRBasicBlockId bblkid = block->new_bblock();
            
            // v0 <- (v0 << v1)
            block->add_instr(bblkid, IRInstruction(IROperation::SHL, IROperand(IROperandType::VAR, 0, 31, 0),
                                IROperand(IROperandType::VAR, 0, 31, 0), IROperand(IROperandType::VAR, 1, 31, 0), 0x0));
            // v1 <- cst:v1
            block->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 1, 31, 16),
                                IROperand(IROperandType::CST, 0x4141, 15, 0), IROperand()));
            // v2 <- v4 | v3
            block->add_instr(bblkid, IRInstruction(IROperation::OR, IROperand(IROperandType::VAR, 2, 31, 0),
                                IROperand(IROperandType::VAR, 4, 31, 0), IROperand(IROperandType::VAR, 3, 31, 0)));
            // v4 <- sdiv(e4,e5)
            block->add_instr(bblkid, IRInstruction(IROperation::SDIV, IROperand(IROperandType::VAR, 4, 31, 0),
                                IROperand(IROperandType::VAR, 4, 31, 0), IROperand(IROperandType::VAR, 5, 31, 0)));
            // v5 <- v5,v6
            block->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::TMP, 0, 15, 0),
                                IROperand(IROperandType::VAR, 6, 17, 2), IROperand()));
            block->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 5, 15, 0),
                                IROperand(IROperandType::TMP, 0, 15, 0), IROperand()));
            // tmp1 <- -v6
            block->add_instr(bblkid, IRInstruction(IROperation::NEG, IROperand(IROperandType::TMP, 1, 31, 0),
                                IROperand(IROperandType::VAR, 6, 31, 0), IROperand()));
            // tmp2 <- ~v7 
            block->add_instr(bblkid, IRInstruction(IROperation::NOT, IROperand(IROperandType::TMP, 2, 31, 0),
                                IROperand(IROperandType::VAR, 7, 31, 0), IROperand()));
            // v7 <- tmp1
            block->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 7, 31, 0),
                                IROperand(IROperandType::TMP, 1, 31, 0), IROperand()));
            // v6 <- tmp2
            block->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 6, 31, 0),
                                IROperand(IROperandType::TMP, 2, 31, 0), IROperand()));
            irm->add(block);
            sym.execute_from(0x0);
            
            // Test 
            nb += _assert(irctx->get(0)->eq(shl(e0,e1)), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(1)->eq(concat(exprcst(16, 0x4141),extract(e1, 15,0))), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(2)->eq((e4|e3)), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(4)->eq(sdiv(e4,e5)), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(5)->eq(concat(extract(e5, 31, 16),extract(e6, 17, 2))), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(6)->eq(~e7), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            nb += _assert(irctx->get(7)->eq(-e6), "SymbolicEngine: basic execution on IR failed (assignment operations)" );
            return nb;
        }
        
        unsigned int rw_operations(){
            unsigned int nb = 0;
            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30);
            Arch* arch = new ArchX86();
            Expr    e0 = exprvar(32, "var0", Taint::TAINTED),
                    e1 = exprvar(32, "var1", Taint::TAINTED),
                    e2 = exprvar(64, "var2", Taint::TAINTED),
                    e3 = exprvar(32, "var3"),
                    e4 = exprvar(32, "var4"),
                    e5 = exprvar(32, "var5"),
                    e6 = exprvar(32, "var6"),
                    e7 = exprvar(32, "var7");        
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            irctx->set(4, e4);
            irctx->set(5, e5);
            irctx->set(6, e6);
            irctx->set(7, e7);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            mem->new_segment(0x40000, 0x7fffff);
            // Create basic block 
            IRBlock* block = new IRBlock("at_0x0", 0, 100);
            IRBasicBlockId bblkid = block->new_bblock();
            irm->add(block);
            
            // Write
            block->add_instr(bblkid, IRInstruction(IROperation::STM, IROperand(IROperandType::CST, 0x40000, 31, 0), 
                                                  IROperand(IROperandType::VAR, 0, 31, 0), IROperand()));
            block->add_instr(bblkid, IRInstruction(IROperation::STM, IROperand(IROperandType::CST, 0x40004, 31, 0), 
                                                  IROperand(IROperandType::VAR, 1, 31, 0), IROperand()));
            block->add_instr(bblkid, IRInstruction(IROperation::STM, IROperand(IROperandType::CST, 0x40006, 31, 0), 
                                                  IROperand(IROperandType::CST, 0x1234, 15, 0), IROperand()));
            block->add_instr(bblkid, IRInstruction(IROperation::STM, IROperand(IROperandType::CST, 0x7fff8, 63, 0), 
                                                  IROperand(IROperandType::VAR, 2, 63, 0), IROperand()));
            block->add_instr(bblkid, IRInstruction(IROperation::ADD, IROperand(IROperandType::TMP, 0, 31, 0), 
                                                  IROperand(IROperandType::VAR, 0, 31, 0), IROperand(IROperandType::VAR, 1, 31, 0)));
            block->add_instr(bblkid, IRInstruction(IROperation::STM, IROperand(IROperandType::CST, 0x50000, 31, 0), 
                                                  IROperand(IROperandType::TMP, 0, 31, 0), IROperand()));
            // Read
            block->add_instr(bblkid, IRInstruction(IROperation::LDM, IROperand(IROperandType::VAR, 3, 31, 0), 
                                                  IROperand(IROperandType::CST, 0x40000, 31, 0), IROperand()));
            block->add_instr(bblkid, IRInstruction(IROperation::LDM, IROperand(IROperandType::VAR, 4, 31, 0), 
                                                  IROperand(IROperandType::CST, 0x40004, 31, 0), IROperand()));
            block->add_instr(bblkid, IRInstruction(IROperation::LDM, IROperand(IROperandType::VAR, 5, 31, 0), 
                                                  IROperand(IROperandType::CST, 0x7fffc, 31, 0), IROperand()));
            block->add_instr(bblkid, IRInstruction(IROperation::LDM, IROperand(IROperandType::TMP, 1, 31, 0), 
                                                  IROperand(IROperandType::CST, 0x50000, 31, 0), IROperand()));
            block->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 6, 31, 0), 
                                                  IROperand(IROperandType::TMP, 1, 31, 0), IROperand()));
            // Execute
            sym.execute_from(0x0);
            // Check memory
            nb += _assert(mem->read(0x40000, 4)->eq(e0), "SymbolicEngine::execute_from() failed to write expression in memory");
            nb += _assert(mem->read(0x40004, 4)->eq(concat(exprcst(16, 0x1234), extract(e1, 15,0))), "SymbolicEngine::execute_from() failed on overlapping expressions write");
            nb += _assert(mem->read(0x7fff8, 8)->eq(e2), "SymbolicEngine::execute_from() failed to write expression in memory");
            nb += _assert(mem->read(0x50000, 4)->eq(e0+e1), "SymbolicEngine::execute_from() failed to write tmp expression in memory");
            
            // Check read expressions
            nb += _assert(irctx->get(3)->eq(e0) , "SymbolicEngine::execute_from() failed to read expression from memory");
            nb += _assert(irctx->get(4)->eq(concat(exprcst(16, 0x1234), extract(e1, 15,0))) , "SymbolicEngine::execute_from() failed to read expression from memory");
            nb += _assert(irctx->get(5)->eq(extract(e2, 63, 32)), "SymbolicEngine::execute_from() failed to read expression from memory");
            nb += _assert(irctx->get(6)->eq(e0+e1) , "SymbolicEngine::execute_from() failed to read tmp expression from memory");
            return nb;
        }
        
        unsigned int bcc_operation(){
            unsigned int nb = 0;
            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30);
            Arch* arch = new ArchX86();
            Expr    e0 = exprvar(32, "var0", Taint::TAINTED),
                    e1 = exprvar(32, "var1", Taint::TAINTED),
                    e2 = exprvar(32, "var2", Taint::TAINTED);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            mem->new_segment(0x80000, 0x9fffff);
            /* Simple bcc with cst condition */
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            IRBlock* block = new IRBlock("at_0x0", 0, 100);
            IRBasicBlockId bblkid = block->new_bblock(), taken = block->new_bblock(), not_taken = block->new_bblock();
            irm->add(block);
            block->add_instr(bblkid, IRInstruction(IROperation::BCC, IROperand(IROperandType::CST, 1, 31, 0),
                                    IROperand(IROperandType::CST, taken, 31, 0), IROperand(IROperandType::CST, not_taken, 31, 0)));
            block->add_instr(taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 1, 31, 0), IROperand()));
            block->add_instr(not_taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 2, 31, 0)));
            
            sym.execute_from(0x0);
            nb += _assert(irctx->get(0)->eq(irctx->get(1)), "SymbolicEngine: failed to execute simple BCC with constant condition");
            /* Same with other jump */
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            block = new IRBlock("at_0x100", 0x100, 0x1ff);
            bblkid = block->new_bblock();
            taken = block->new_bblock();
            not_taken = block->new_bblock();
            irm->add(block);
            block->add_instr(bblkid, IRInstruction(IROperation::BCC, IROperand(IROperandType::CST, 0, 31, 0),
                                    IROperand(IROperandType::CST, taken, 31, 0), IROperand(IROperandType::CST, not_taken, 31, 0), 0x100));
            block->add_instr(taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 1, 31, 0), IROperand()));
            block->add_instr(not_taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 2, 31, 0)));
            sym.execute_from(0x100);
            nb += _assert(irctx->get(0)->eq(irctx->get(2)), "SymbolicEngine: failed to execute simple BCC with constant condition");                       
            /* Same with symbolic value */
            irctx->set(0, exprcst(32, 2)+exprcst(32, 1));
            irctx->set(1, e1);
            irctx->set(2, e2);
            block = new IRBlock("at_0x200", 0x200, 0x2ff);
            bblkid = block->new_bblock();
            taken = block->new_bblock();
            not_taken = block->new_bblock();
            irm->add(block);
            block->add_instr(bblkid, IRInstruction(IROperation::BCC, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::CST, taken, 31, 0), IROperand(IROperandType::CST, not_taken, 31, 0), 0x200));
            block->add_instr(taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 1, 31, 0), IROperand()));
            block->add_instr(not_taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 2, 31, 0)));
            sym.execute_from(0x200);
            nb += _assert(irctx->get(0)->eq(irctx->get(1)), "SymbolicEngine: failed to execute simple BCC with variable condition");                       
            /* Same with symbolic value */
            irctx->set(0, exprcst(32, 2)-exprcst(32, 2));
            irctx->set(1, e1);
            irctx->set(2, e2);
            block = new IRBlock("at_0x300", 0x300, 0x3ff);
            bblkid = block->new_bblock();
            taken = block->new_bblock();
            not_taken = block->new_bblock();
            irm->add(block);
            block->add_instr(bblkid, IRInstruction(IROperation::BCC, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::CST, taken, 31, 0), IROperand(IROperandType::CST, not_taken, 31, 0), 0x300));
            block->add_instr(taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 1, 31, 0), IROperand()));
            block->add_instr(not_taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 2, 31, 0)));
            sym.execute_from(0x300);
            nb += _assert(irctx->get(0)->eq(irctx->get(2)), "SymbolicEngine: failed to execute simple BCC with variable condition");                       
            /* First some ops and then BCC */
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            block = new IRBlock("at_0x400", 0x400, 0x4ff);
            bblkid = block->new_bblock();
            taken = block->new_bblock();
            not_taken = block->new_bblock();
            irm->add(block);
            block->add_instr(bblkid, IRInstruction(IROperation::ADD, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 1, 31, 0), IROperand(IROperandType::VAR, 2, 31, 0), 0x400));
            block->add_instr(bblkid, IRInstruction(IROperation::MUL, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::CST, 1, 31, 0), IROperand(IROperandType::CST, 678767, 31, 0)));
            block->add_instr(bblkid, IRInstruction(IROperation::BCC, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::CST, taken, 31, 0), IROperand(IROperandType::CST, not_taken, 31, 0)));
            block->add_instr(taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 1, 31, 0), IROperand()));
            block->add_instr(not_taken, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 2, 31, 0)));
            sym.execute_from(0x400);
            nb += _assert(irctx->get(0)->eq(irctx->get(1)), "SymbolicEngine: failed to execute simple BCC with complex condition");
            return nb;
        }
        
        unsigned int jcc_operation(){
            unsigned int nb = 0; 
            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30);
            Expr    e0 = exprvar(32, "var0", Taint::TAINTED),
                    e1 = exprvar(32, "var1", Taint::TAINTED),
                    e2 = exprvar(32, "var2", Taint::TAINTED);
            IRManager *irm = new IRManager();
            Arch* arch = new ArchX86();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            mem->new_segment(0x80000, 0x9fffff);
            /* Simple bcc with cst condition */
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            IRBlock* block = new IRBlock("at_0x0", 0x0, 0xff), *jcc1 = new IRBlock("at_0x100", 0x100, 0x1ff), 
                     *jcc2 = new IRBlock("at_0x200", 0x200, 0x2ff), *end = new IRBlock("at_0x300", 0x300, 0x3ff);
            irm->add(block);
            irm->add(jcc1);
            irm->add(jcc2);
            irm->add(end);
            IRBasicBlockId bblkid = block->new_bblock();
            /* 1) Const jump true */
            block->add_instr(bblkid, IRInstruction(IROperation::JCC, IROperand(IROperandType::CST, 1, 31, 0),
                                    IROperand(IROperandType::CST, 0x100, 31, 0), IROperand(IROperandType::CST, 0x200, 31, 0), 0));
            bblkid = jcc1->new_bblock();
            jcc1->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 1, 31, 0), IROperand(), 0x100));
            jcc1->add_instr(bblkid, IRInstruction(IROperation::JCC, IROperand(IROperandType::CST, 1, 31, 0),
                                    IROperand(IROperandType::CST, 0x300, 31, 0), IROperand()));
            bblkid = jcc2->new_bblock();
            jcc2->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::VAR, 2, 31, 0), IROperand(), 0x200));
            jcc2->add_instr(bblkid, IRInstruction(IROperation::JCC, IROperand(IROperandType::CST, 1, 31, 0),
                                    IROperand(IROperandType::CST, 0x300, 31, 0), IROperand()));               
            bblkid = end->new_bblock();
            end->add_instr(bblkid, IRInstruction(IROperation::MOV, IROperand(IROperandType::VAR, 2, 31, 0),
                                    IROperand(IROperandType::CST, 0x1337, 31, 0), IROperand(), 0x300));
            sym.execute_from(0x0);
            nb += _assert(irctx->get(0)->eq(e1), "SymbolicEngine: failed to execute constant-condition JCC ");
            nb += _assert(irctx->get(2)->eq(exprcst(32, 0x1337)), "SymbolicEngine: failed to execute constant-condition JCC ");
            nb += _assert(irctx->get(1)->eq(e1), "SymbolicEngine: failed to execute constant-condition JCC ");
            
            /* 2) Const jump false */
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            block = new IRBlock("at_0x500", 0x500, 0x5ff);
            irm->add(block);
            bblkid = block->new_bblock();
            block->add_instr(bblkid, IRInstruction(IROperation::JCC, IROperand(IROperandType::CST, 0, 31, 0),
                                    IROperand(IROperandType::CST, 0x100, 31, 0), IROperand(IROperandType::CST, 0x200, 31, 0), 0x500));
            sym.execute_from(0x500);
            nb += _assert(irctx->get(0)->eq(e2), "SymbolicEngine: failed to execute constant-condition JCC ");
            nb += _assert(irctx->get(2)->eq(exprcst(32, 0x1337)), "SymbolicEngine: failed to execute constant-condition JCC ");
            nb += _assert(irctx->get(1)->eq(e1), "SymbolicEngine: failed to execute constant-condition JCC ");
            
            /* Var jump true */
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            block = new IRBlock("at_0x600", 0x600, 0x6ff);
            irm->add(block);
            bblkid = block->new_bblock();
            block->add_instr(bblkid, IRInstruction(IROperation::DIV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::CST, 6789, 31, 0), IROperand(IROperandType::CST, 78, 31, 0), 0x600));
            block->add_instr(bblkid, IRInstruction(IROperation::JCC, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::CST, 0x100, 31, 0), IROperand(IROperandType::CST, 0x200, 31, 0)));
            sym.execute_from(0x600);
            nb += _assert(irctx->get(0)->eq(e1), "SymbolicEngine: failed to execute constant-condition JCC ");
            nb += _assert(irctx->get(2)->eq(exprcst(32, 0x1337)), "SymbolicEngine: failed to execute constant-condition JCC ");
            nb += _assert(irctx->get(1)->eq(e1), "SymbolicEngine: failed to execute constant-condition JCC ");
            
            /* Var jump false */
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            block = new IRBlock("at_0x700", 0x700, 0x7ff);
            irm->add(block);
            bblkid = block->new_bblock();
            block->add_instr(bblkid, IRInstruction(IROperation::DIV, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::CST, 6789, 31, 0), IROperand(IROperandType::CST, 789088, 31, 0), 0x700));
            block->add_instr(bblkid, IRInstruction(IROperation::JCC, IROperand(IROperandType::VAR, 0, 31, 0),
                                    IROperand(IROperandType::CST, 0x100, 31, 0), IROperand(IROperandType::CST, 0x200, 31, 0)));
            sym.execute_from(0x700);
            nb += _assert(irctx->get(0)->eq(e2), "SymbolicEngine: failed to execute constant-condition JCC ");
            nb += _assert(irctx->get(2)->eq(exprcst(32, 0x1337)), "SymbolicEngine: failed to execute constant-condition JCC ");
            nb += _assert(irctx->get(1)->eq(e1), "SymbolicEngine: failed to execute constant-condition JCC ");
            return nb;
        }
        
        unsigned int enter_inside_block(){
            unsigned int nb = 0;
            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30);
            Arch* arch = new ArchX86();
            Expr    e0 = exprcst(32, 0xff),
                    e1 = exprcst(32, 0xff), 
                    e2 = exprcst(32, 0xff),
                    e3 = exprcst(32, 0xff);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            
            // Create basic block 
            IRBlock* block = new IRBlock("at_0x0", 0, 100);
            IRBasicBlockId bblkid = block->new_bblock();
            
            block->add_instr(bblkid, ir_mov(ir_var(0, 31, 0), ir_cst(0, 31, 0), 0x0));
            block->add_instr(bblkid, ir_mov(ir_var(1, 31, 0), ir_cst(1, 31, 0), 0x1));
            block->add_instr(bblkid, ir_mov(ir_var(2, 31, 0), ir_cst(2, 31, 0), 0x2));
            block->add_instr(bblkid, ir_mov(ir_var(3, 31, 0), ir_cst(3, 31, 0), 0x3));
            irm->add(block);
            
            // Execute from second instruction
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            sym.execute_from(0x1);
            nb += _assert( irctx->get(0)->eq(e0), "SymbolicEngine: failed to start from an instruction inside a basic block");
            nb += _assert( irctx->get(1)->eq(exprcst(32, 1)), "SymbolicEngine: failed to start from an instruction inside a basic block");
            nb += _assert( irctx->get(2)->eq(exprcst(32, 2)), "SymbolicEngine: failed to start from an instruction inside a basic block");
            nb += _assert( irctx->get(3)->eq(exprcst(32, 3)), "SymbolicEngine: failed to start from an instruction inside a basic block");
            
            // Execute from third instruction
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            sym.execute_from(0x2);
            nb += _assert( irctx->get(0)->eq(e0), "SymbolicEngine: failed to start from an instruction inside a basic block");
            nb += _assert( irctx->get(1)->eq(e1), "SymbolicEngine: failed to start from an instruction inside a basic block");
            nb += _assert( irctx->get(2)->eq(exprcst(32, 2)), "SymbolicEngine: failed to start from an instruction inside a basic block");
            nb += _assert( irctx->get(3)->eq(exprcst(32, 3)), "SymbolicEngine: failed to start from an instruction inside a basic block");
            
            // Execute from fourth instruction
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            sym.execute_from(0x3);
            nb += _assert( irctx->get(0)->eq(e0), "SymbolicEngine: failed to start from an instruction inside a basic block");
            nb += _assert( irctx->get(1)->eq(e1), "SymbolicEngine: failed to start from an instruction inside a basic block");
            nb += _assert( irctx->get(2)->eq(e2), "SymbolicEngine: failed to start from an instruction inside a basic block");
            nb += _assert( irctx->get(3)->eq(exprcst(32, 3)), "SymbolicEngine: failed to start from an instruction inside a basic block");
            
            return nb;                    
        }
        
        unsigned int breakpoint(){
            unsigned int nb = 0;
            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30, varctx);
            Arch* arch = new ArchX86();
            Expr    e0 = exprcst(32, 0xf0),
                    e1 = exprcst(32, 0xf1), 
                    e2 = exprcst(32, 0xf2),
                    e3 = exprcst(32, 0xf3);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            mem->new_segment(0x60000, 0x700000);
            mem->new_segment(0x0, 0x2000);
            
            // Break on register write
            IRBlock* block = new IRBlock("at_0x0", 0, 100);
            IRBasicBlockId bblkid = block->new_bblock();
            
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            block->add_instr(bblkid, ir_mov(ir_var(0, 31, 0), ir_cst(0, 31, 0), 0x0));
            block->add_instr(bblkid, ir_mov(ir_var(1, 31, 0), ir_cst(1, 31, 0), 0x1));
            block->add_instr(bblkid, ir_mov(ir_var(2, 31, 0), ir_cst(2, 31, 0), 0x2));
            block->add_instr(bblkid, ir_mov(ir_var(3, 31, 0), ir_cst(3, 31, 0), 0x3));
            irm->add(block);
            
            sym.breakpoint.add(BreakpointType::REGISTER_W, "reg_w", 1);
            sym.execute_from(0);
            
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(0) == 0, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(1) == 0xf1, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "reg_w", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 1, "SymbolicEngine: breakpoint failed");
            
            // Break on register read
            block = new IRBlock("at_0x100", 0x100, 0x200);
            bblkid = block->new_bblock();
            
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            block->add_instr(bblkid, ir_mov(ir_var(0, 31, 0), ir_cst(0, 31, 0), 0x100));
            block->add_instr(bblkid, ir_mov(ir_var(3, 31, 0), ir_var(2, 31, 0), 0x101));
            block->add_instr(bblkid, ir_mov(ir_var(1, 31, 0), ir_cst(2, 31, 0), 0x102));
            irm->add(block);
            
            sym.breakpoint.add(BreakpointType::REGISTER_R, "reg_r", 2);
            sym.execute_from(0x100);
            
            nb += _assert(sym.regs->concretize(0) == 0, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->get(3)->eq(e3), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "reg_r", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x101, "SymbolicEngine: breakpoint failed");
            
            // Break on register read/write
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            
            sym.breakpoint.remove("reg_r");
            sym.breakpoint.remove("reg_w");
            sym.breakpoint.add(BreakpointType::REGISTER_RW, "reg_rw", 1);
            
            sym.execute_from(0x0);
            nb += _assert(sym.regs->concretize(0) == 0, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->get(1)->eq(e1), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "reg_rw", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x1, "SymbolicEngine: breakpoint failed");
            
            sym.execute_from(0x100);
            nb += _assert(sym.regs->concretize(0) == 0, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->get(3)->eq(e2), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "reg_rw", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x102, "SymbolicEngine: breakpoint failed");
            
            /* Break on memory read */
            block = new IRBlock("at_0x200", 0x200, 0x2ff);
            bblkid = block->new_bblock();
            block->add_instr(bblkid, ir_ldm(ir_var(2, 31, 0), ir_var(0, 31, 0), 0x200));
            block->add_instr(bblkid, ir_stm(ir_var(1, 31, 0), ir_var(3, 31, 0), 0x201));
            block->add_instr(bblkid, ir_stm(ir_var(0, 31, 0), ir_cst(2, 31, 0), 0x202));
            irm->add(block);
            sym.mem->write(0x60000, exprcst(32, 0xaaaabbbb), sym.vars);
            
            irctx->set(0, exprcst(32, 0x60000));
            irctx->set(1, exprcst(32, 0x61000));
            irctx->set(2, e2);
            irctx->set(3, e3);
            sym.breakpoint.remove_all();
            sym.breakpoint.add(BreakpointType::MEMORY_R, "mem_r", 0x60000);
            sym.execute_from(0x200);
            nb += _assert(sym.regs->get(2)->eq(e2), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->get(3)->eq(e3), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "mem_r", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x200, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.addr->concretize() == 0x60000, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.size == 4, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.value->eq(exprcst(32, 0xaaaabbbb)), "SymbolicEngine: breakpoint failed");
            
            /* Break on memory write */
            irctx->set(0, exprcst(32, 0x60000));
            irctx->set(1, exprcst(32, 0x61000));
            irctx->set(2, e2);
            irctx->set(3, e3);
            sym.breakpoint.remove("mem_r");
            sym.breakpoint.add(BreakpointType::MEMORY_W, "mem_w", 0x61002, 0x61003);
            sym.execute_from(0x200);
            nb += _assert((uint32_t)sym.regs->concretize(2) == 0xaaaabbbb, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->get(3)->eq(e3), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "mem_w", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x201, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.addr->concretize() == 0x61000, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.size == 4, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.value->eq(e3), "SymbolicEngine: breakpoint failed");
            
            /* Break on memory read/write */
            irctx->set(0, exprcst(32, 0x60000));
            irctx->set(1, exprcst(32, 0x61000));
            irctx->set(2, e2);
            irctx->set(3, e3);
            sym.breakpoint.remove("mem_w");
            sym.breakpoint.add(BreakpointType::MEMORY_RW, "mem_rw", 0x60002);
            
            sym.execute_from(0x200);
            nb += _assert(sym.regs->get(2)->eq(e2), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->get(3)->eq(e3), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "mem_rw", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x200, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.addr->concretize() == 0x60000, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.size == 4, "SymbolicEngine: breakpoint failed");
            
            sym.execute_from(0x201);
            nb += _assert(sym.regs->get(3)->eq(e3), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "mem_rw", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x202, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.addr->concretize() == 0x60000, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.mem_access.size == 4, "SymbolicEngine: breakpoint failed");
            
            /* Break on a specific address */
            sym.breakpoint.remove_all();
            sym.breakpoint.add(BreakpointType::ADDR, "addr", 0x201);
            
            /* Break on branch */
            block = new IRBlock("at_0x300", 0x300, 0x3ff);
            bblkid = block->new_bblock();
            block->add_instr(bblkid, ir_add(ir_var(2, 31, 0), ir_var(0, 31, 0), ir_var(0, 31, 0), 0x300));
            block->add_instr(bblkid, ir_sub(ir_var(1, 31, 0), ir_var(3, 31, 0), ir_var(3, 31, 0), 0x301));
            block->add_instr(bblkid, ir_jcc(ir_var(1, 31, 0), ir_cst(0x8000000012345678, 31, 0), ir_none(), 0x301));
            irm->add(block);
            
            sym.breakpoint.remove_all();
            sym.breakpoint.add(BreakpointType::BRANCH, "branch");
            sym.execute_from(0x300);
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "branch", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x301, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.branch->concretize(sym.vars) == 0x12345678, "SymbolicEngine: breakpoint failed");
            
            /* Break on multibranch */
            block = new IRBlock("at_0x400", 0x400, 0x4ff);
            bblkid = block->new_bblock();
            block->add_instr(bblkid, ir_add(ir_var(2, 31, 0), ir_var(0, 31, 0), ir_var(0, 31, 0), 0x400));
            block->add_instr(bblkid, ir_sub(ir_var(1, 31, 0), ir_var(3, 31, 0), ir_var(3, 31, 0), 0x401));
            block->add_instr(bblkid, ir_jcc(ir_var(1, 31, 0), ir_cst(0x8000000012345678, 31, 0), ir_cst(0x1337b4b3, 31, 0), 0x402));
            irm->add(block);
            
            sym.breakpoint.add(BreakpointType::MULTIBRANCH, "multibranch");
            sym.execute_from(0x400);
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "multibranch", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x402, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.multibranch.cond->eq(sym.regs->get(1)), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.multibranch.if_not_null->concretize(sym.vars) == 0x12345678, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.multibranch.if_null->concretize(sym.vars) == 0x1337b4b3, "SymbolicEngine: breakpoint failed");
            
            /* Break on tainted pc */
            block = new IRBlock("at_0x500", 0x500, 0x5ff);
            bblkid = block->new_bblock();
            block->add_instr(bblkid, ir_jcc(ir_cst(1, 31, 0), ir_var(0, 31, 0), ir_none(), 0x500));
            irm->add(block);
            
            sym.breakpoint.remove_all();
            sym.breakpoint.add(BreakpointType::TAINTED_PC, "tainted");
            sym.regs->set(0, exprcst(32, 0x540, Taint::TAINTED));
            sym.mem->write(0x540, (code_t)string("\xeb\x0e", 2).c_str(), 2); // To avoid failing disassembly
            sym.execute_from(0x500);
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "tainted", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x540, "SymbolicEngine: breakpoint failed");
            
            /* Break on tainted code */
            // Do the test on X86 because we need disassembly
            SymbolicEngine symX86 = SymbolicEngine(ArchType::X86);
            symX86.mem->new_segment(0, 0x1000);
            
            Expr jmp = exprcst(16, 0x2eeb, Taint::TAINTED);// jmp 0x30 is "\xeb\x2e"
            symX86.breakpoint.remove_all();
            symX86.breakpoint.add(BreakpointType::TAINTED_CODE, "tainted_code");
            symX86.mem->write(0x550, jmp);
            symX86.execute_from(0x550);
            nb += _assert(symX86.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(symX86.info.breakpoint == "tainted_code", "SymbolicEngine: breakpoint failed");
            nb += _assert(symX86.info.addr == 0x550, "SymbolicEngine: breakpoint failed");
            
            return nb;
        }
        
        unsigned int breakpoint_advanced(){
            unsigned int nb = 0;
            bool threw;
            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30, varctx);
            Arch* arch = new ArchX86();
            Expr    e0 = exprcst(32, 0xf0),
                    e1 = exprcst(32, 0xf1), 
                    e2 = exprcst(32, 0xf2),
                    e3 = exprcst(32, 0xf3);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            mem->new_segment(0x60000, 0x700000);
            
            IRBlock* block = new IRBlock("at_0x0", 0, 0x100);
            IRBasicBlockId bblkid = block->new_bblock();
            
            block->add_instr(bblkid, ir_mov(ir_var(0, 31, 0), ir_var(0, 31, 0), 0x0));
            block->add_instr(bblkid, ir_mov(ir_var(0, 31, 0), ir_cst(1, 31, 0), 0x0));
            block->add_instr(bblkid, ir_mov(ir_var(arch->pc(), 31, 0), ir_cst(1, 31, 0), 0x0));
            block->add_instr(bblkid, ir_mov(ir_var(2, 31, 0), ir_cst(2, 31, 0), 0x1));
            block->add_instr(bblkid, ir_mov(ir_var(3, 31, 0), ir_cst(3, 31, 0), 0x1));
            block->add_instr(bblkid, ir_mov(ir_var(arch->pc(), 31, 0), ir_cst(2, 31, 0), 0x1));
            block->add_instr(bblkid, ir_mov(ir_var(1, 31, 0), ir_var(3, 31, 0), 0x2));
            irm->add(block);
            
            
            /* Different breakoints on same instruction */
            sym.breakpoint.add(BreakpointType::REGISTER_R, "reg_r", 0);
            sym.breakpoint.add(BreakpointType::ADDR, "addr_0", 0);
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            
            sym.execute_from(0);
            nb += _assert(sym.regs->get(0)->eq(e0), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "reg_r", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0, "SymbolicEngine: breakpoint failed");
            
            sym.execute();
            nb += _assert(sym.regs->get(0)->eq(e0), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "addr_0", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0, "SymbolicEngine: breakpoint failed");
            
            sym.execute();
            nb += _assert(sym.regs->concretize(0) == 1, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::NONE, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(2) == 2, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(3) == 3, "SymbolicEngine: breakpoint failed");
            
            /* Same breakpoint on two consecutive instructions */
            sym.breakpoint.remove_all();
            sym.breakpoint.add(BreakpointType::REGISTER_RW, "rw", 3);
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            
            sym.execute_from(0);
            nb += _assert(sym.regs->get(3)->eq(e3), "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "rw", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 1, "SymbolicEngine: breakpoint failed");
            
            sym.execute();
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(3) == 3, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "rw", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 2, "SymbolicEngine: breakpoint failed");
            
            sym.execute();
            nb += _assert(sym.regs->concretize(0) == 1, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.stop == StopInfo::NONE, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(2) == 2, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(3) == 3, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(1) == 3, "SymbolicEngine: breakpoint failed");
            
            /* SOme breakpoint types must be unique breakpoint allowed */
            sym.breakpoint.add(BreakpointType::BRANCH, "branch");
            threw = false;
            try{
                sym.breakpoint.add(BreakpointType::BRANCH, "branch2");
            }catch( breakpoint_exception){
                threw = true;
            }
            nb += _assert(threw, "SymbolicEngine: should not be able to add two BRANCH breakpoints");
            
            sym.breakpoint.add(BreakpointType::MULTIBRANCH, "multi");
            threw = false;
            try{
                sym.breakpoint.add(BreakpointType::MULTIBRANCH, "multi2trololo");
            }catch( breakpoint_exception){
                threw = true;
            }
            nb += _assert(threw, "SymbolicEngine: should not be able to add two MULTIBRANCH breakpoints");
            
            sym.breakpoint.add(BreakpointType::TAINTED_PC, "tainted");
            threw = false;
            try{
                sym.breakpoint.add(BreakpointType::TAINTED_PC, "tainted2");
            }catch( breakpoint_exception){
                threw = true;
            }
            nb += _assert(threw, "SymbolicEngine: should not be able to add two TAINTED_PC breakpoints");
            
            sym.breakpoint.add(BreakpointType::TAINTED_CODE, "tainted_code");
            threw = false;
            try{
                sym.breakpoint.add(BreakpointType::TAINTED_CODE, "tainted_code2");
            }catch( breakpoint_exception){
                threw = true;
            }
            nb += _assert(threw, "SymbolicEngine: should not be able to add two TAINTED_CODE breakpoints");
            
            return nb;
        }
        
        unsigned int max_instr_limit(){
            unsigned int nb = 0;
            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30, varctx);
            Arch* arch = new ArchX86();
            Expr    e0 = exprcst(32, 0xf0),
                    e1 = exprcst(32, 0xf1), 
                    e2 = exprcst(32, 0xf2),
                    e3 = exprcst(32, 0xf3);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            mem->new_segment(0x60000, 0x700000);
            
            IRBlock* block = new IRBlock("at_0x0", 0, 0x100);
            IRBasicBlockId bblkid = block->new_bblock();
            
            block->add_instr(bblkid, ir_mov(ir_var(0, 31, 0), ir_var(0, 31, 0), 0x0));
            block->add_instr(bblkid, ir_mov(ir_var(0, 31, 0), ir_cst(1, 31, 0), 0x0));
            block->add_instr(bblkid, ir_mov(ir_var(arch->pc(), 31, 0), ir_cst(1, 31, 0), 0x0));
            block->add_instr(bblkid, ir_mov(ir_var(2, 31, 0), ir_cst(2, 31, 0), 0x1));
            block->add_instr(bblkid, ir_mov(ir_var(3, 31, 0), ir_cst(3, 31, 0), 0x1));
            block->add_instr(bblkid, ir_mov(ir_var(arch->pc(), 31, 0), ir_cst(2, 31, 0), 0x1));
            block->add_instr(bblkid, ir_mov(ir_var(1, 31, 0), ir_var(3, 31, 0), 0x2));
            irm->add(block);
            
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            sym.execute_from(0, 1);
            nb += _assert(sym.regs->concretize(X86_EIP) == 1, "SymbolicEngine: execute() with max_instr failed");
            nb += _assert(sym.regs->concretize(0) == 1, "SymbolicEngine: execute() with max_instr failed");
            
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            sym.execute_from(0, 2);
            nb += _assert(sym.regs->concretize(X86_EIP) == 2, "SymbolicEngine: execute() with max_instr failed");
            nb += _assert(sym.regs->concretize(0) == 1, "SymbolicEngine: execute() with max_instr failed");
            nb += _assert(sym.regs->concretize(2) == 2, "SymbolicEngine: execute() with max_instr failed");
            nb += _assert(sym.regs->concretize(3) == 3, "SymbolicEngine: execute() with max_instr failed");
            
            irctx->set(0, e0);
            irctx->set(1, e1);
            irctx->set(2, e2);
            irctx->set(3, e3);
            sym.execute_from(0, 1);
            sym.execute(1);
            nb += _assert(sym.regs->concretize(X86_EIP) == 2, "SymbolicEngine: execute() with max_instr failed");
            nb += _assert(sym.regs->concretize(0) == 1, "SymbolicEngine: execute() with max_instr failed");
            nb += _assert(sym.regs->concretize(2) == 2, "SymbolicEngine: execute() with max_instr failed");
            nb += _assert(sym.regs->concretize(3) == 3, "SymbolicEngine: execute() with max_instr failed");

            return nb;
        }
        
        void _callback1(SymbolicEngine& sym){
                sym.regs->set(3, exprcst(32, 0x12345678));
                return;
        }
        
        unsigned int breakpoint_callbacks(){
            unsigned int nb = 0;

            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30, varctx);
            Arch* arch = new ArchX86();
            Expr    e0 = exprcst(32, 0xf0),
                    e1 = exprcst(32, 0xf1), 
                    e2 = exprcst(32, 0xf2),
                    e3 = exprcst(32, 0xf3);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            mem->new_segment(0x0, 0x2000);
            
            IRBlock* block = new IRBlock("at_0x300", 0x300, 0x3ff);
            IRBasicBlockId bblkid = block->new_bblock();
        
            /* On standard breakpoints without resume */
            block->add_instr(bblkid, ir_add(ir_var(0, 31, 0), ir_var(0, 31, 0), ir_var(0, 31, 0), 0x300));
            block->add_instr(bblkid, ir_sub(ir_var(1, 31, 0), ir_var(3, 31, 0), ir_var(3, 31, 0), 0x301));
            block->add_instr(bblkid, ir_mul(ir_var(2, 31, 0), ir_var(0, 31, 0), ir_var(0, 31, 0), 0x301));
            block->add_instr(bblkid, ir_jcc(ir_cst(1, 31, 0), ir_cst(0x100, 31, 0), ir_none(), 0x301));
            irm->add(block);
            
            sym.mem->write(0x100, (code_t)string("\xeb\x0e", 2).c_str(), 2); // To avoid failing disassembly
            
            sym.regs->set(0, e0);
            sym.regs->set(1, e1);
            sym.regs->set(2, e2);
            sym.regs->set(3, e3);
            sym.breakpoint.remove_all();
            sym.breakpoint.add(BreakpointType::REGISTER_W, "w", 2, &_callback1, false);
            sym.breakpoint.add(BreakpointType::ADDR, "end", 0x100);
            sym.execute_from(0x300);
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "w", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x301, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(3) == 0x12345678, "SymbolicEngine: breakpoint failed");
        
            /* Same but with resume */
            sym.regs->set(0, e0);
            sym.regs->set(1, e1);
            sym.regs->set(2, e2);
            sym.regs->set(3, e3);
            sym.breakpoint.remove("w");
            sym.breakpoint.add(BreakpointType::REGISTER_W, "w2", 2, &_callback1); // resume=true by default
            sym.execute_from(0x300);
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "end", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x100, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(3) == 0x12345678, "SymbolicEngine: breakpoint failed");
            
            /* On tainted pc without resume */
            block = new IRBlock("at_0x480", 0x480, 0x3003);
            bblkid = block->new_bblock();
            
            sym.regs->set(0, exprcst(32, 0x502, Taint::TAINTED));
            block->add_instr(bblkid, ir_mov(ir_var(1, 31, 0), ir_cst(89, 31, 0), 0x500));
            block->add_instr(bblkid, ir_mov(ir_var(X86_EIP, 31, 0), ir_var(0, 31, 0), 0x501)); // var0 = 0x502 tainted
            block->add_instr(bblkid, ir_mov(ir_var(1, 31, 0), ir_var(0, 31, 0), 0x501));
            block->add_instr(bblkid, ir_jcc(ir_cst(1, 31, 0), ir_cst(0x540, 31, 0), ir_none(), 0x502));
            irm->add(block);
            
            sym.breakpoint.remove_all();
            sym.breakpoint.add(BreakpointType::TAINTED_PC, "tainted", 0, &_callback1, false);
            sym.breakpoint.add(BreakpointType::ADDR, "end", 0x540);
            sym.mem->write(0x540, (code_t)string("\xeb\x0e", 2).c_str(), 2); // To avoid failing disassembly
            sym.execute_from(0x500);
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "tainted", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x502, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(3) == 0x12345678, "SymbolicEngine: breakpoint failed");
            
            /* With resume */
            sym.regs->set(0, exprcst(32, 0x502, Taint::TAINTED));
            sym.regs->set(1, e1);
            sym.regs->set(2, e2);
            sym.regs->set(3, e3);
            sym.breakpoint.remove("tainted");
            sym.breakpoint.add(BreakpointType::TAINTED_PC, "tainted2", 0, &_callback1); // resume=true by default
            sym.execute_from(0x500);
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "end", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x540, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(3) == 0x12345678, "SymbolicEngine: breakpoint failed");
            
            
            return nb;
        }
        
        unsigned int automodifying_code(){
            unsigned int nb = 0;

            MemEngine *mem = new MemEngine();
            VarContext *varctx = new VarContext(30);
            IRContext* irctx = new IRContext(30, varctx);
            Arch* arch = new ArchX86();
            Expr    e0 = exprcst(32, 0xf0),
                    e1 = exprcst(32, 0xf1), 
                    e2 = exprcst(32, 0xf2),
                    e3 = exprcst(32, 0xf3);
            IRManager *irm = new IRManager();
            SymbolicEngine sym = SymbolicEngine(arch, irm, varctx, irctx, mem);
            mem->new_segment(0x0, 0x2000, MEM_FLAG_RWX);
            
            /* Modyfing another basic block */
            
            IRBlock* block1 = new IRBlock("at_0x300", 0x300, 0x3ff);
            IRBlock* block2 = new IRBlock("at_0x500", 0x500, 0x5ff);
            
            IRBasicBlockId bblkid = block1->new_bblock();
            block1->add_instr(bblkid, ir_mov(ir_var(0, 31, 0), ir_var(1, 31, 0), 0x300));
            block1->add_instr(bblkid, ir_stm(ir_cst(0x501, 31, 0), ir_var(1, 31, 0), 0x301));
            block1->add_instr(bblkid, ir_xor(ir_var(2, 31, 0), ir_var(1, 31, 0), ir_var(0, 31, 0), 0x301));
            bblkid = block2->new_bblock();
            block2->add_instr(bblkid, ir_mov(ir_var(0, 31, 0), ir_var(1, 31, 0), 0x500));
            block2->add_instr(bblkid, ir_mov(ir_var(1, 31, 0), ir_cst(0x1234, 31, 0), 0x501));
            
            irm->add(block1);
            irm->add(block2);
            
            sym.regs->set(0, e0);
            sym.regs->set(1, e1);
            sym.regs->set(2, e2);
            sym.regs->set(3, e3);
            
            sym.execute_from(0x300, 2);
            
            nb += _assert( irm->contains_addr(0x500).empty(), "SymbolicEngine: failed to handle automodifying code");
            
            /* Basic Block Modifying itself */
            /* mov bx, 0x1234  = "\x66\xbb\x34\x12"
             * 
             * mov ax, 0x40a; (4)
             * mov DWORD PTR [eax], 0x1234bb66 (6)
             * mov bx, 0xaaaa (4)
             * jmp...
             * */
            string code = string("\x66\xb8\x0a\x04\xc7\x00\x66\xbb\x34\x12\x66\xbb\xaa\xaa\xeb\x0e", 16); 
            sym.mem->write(0x400, (code_t)code.c_str(), code.size()); 
            
            sym.regs->set(X86_EAX, exprcst(32, 0));
            sym.regs->set(X86_EBX, exprcst(32, 0));
            sym.breakpoint.add(BreakpointType::ADDR, "modif", 0x40a);
            sym.breakpoint.add(BreakpointType::ADDR, "end", 0x40e);
            
            sym.execute_from(0x400);
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "modif", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x40a, "SymbolicEngine: breakpoint failed");
            
            sym.execute();
            nb += _assert(sym.info.stop == StopInfo::BREAKPOINT, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.breakpoint == "end", "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.info.addr == 0x40e, "SymbolicEngine: breakpoint failed");
            nb += _assert(sym.regs->concretize(X86_EBX) == 0x1234, "SymbolicEngine: breakpoint failed");
            
            return nb;
        }
        
        unsigned int symbolic_code(){
            unsigned int nb = 0;
            
            /* Stop exec on symbolic code */
            // Do the test on X86 because we need disassembly
            SymbolicEngine symX86 = SymbolicEngine(ArchType::X86);
            symX86.disable(SymbolicEngineOption::PRINT_ERRORS); // To avoid printing the error
            symX86.mem->new_segment(0, 0x1000);
            
            Expr e = exprvar(16, "var");
            symX86.mem->write(0x550, e);
            symX86.execute_from(0x550);
            nb += _assert(symX86.info.stop == StopInfo::SYMBOLIC_CODE, "SymbolicEngine: failed to stop on symbolic code");
            nb += _assert(symX86.info.addr == 0x550, "SymbolicEngine: failed to stop on symbolic code");
            
            return nb;
        }
        
    }
}

using namespace test::symbolic; 
// All unit tests 
void test_symbolic(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing symbolic engine... " << std::flush;  
    total += snapshot();
    total += snapshot_X86();
    total += assignment_operations_64bits();
    total += assignment_operations_32bits();
    total += rw_operations();
    total += bcc_operation();
    total += jcc_operation();
    total += enter_inside_block();
    total += breakpoint();
    total += breakpoint_advanced();
    total += breakpoint_callbacks();
    total += max_instr_limit();
    total += automodifying_code();
    total += symbolic_code();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
