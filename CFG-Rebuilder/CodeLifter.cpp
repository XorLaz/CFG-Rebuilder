#include "CodeLifter.h"
#include <cstdio>
#include <cstdlib>
#include <algorithm>

namespace {
     constexpr size_t ARENA_RESERVE_SIZE = 1ULL * 1024 * 1024 * 1024;  // 1GB
     constexpr size_t COMMIT_CHUNK_SIZE = 16 * 1024 * 1024;            // 16MB
     constexpr size_t MAX_FUNCTION_SIZE = 65536;
}


// 构造 / 析构
CodeLifter::CodeLifter(uint32_t targetPid)
     : m_mem(targetPid)
     , m_resolver(m_mem)
     , m_arena(ARENA_RESERVE_SIZE, COMMIT_CHUNK_SIZE)
     , m_scanner(m_mem)
{
     if (!m_resolver.LoadModules()) {
          printf("[!] Failed to load target modules\n");
     }
     else {
          printf("[+] Loaded %zu target modules\n", m_resolver.GetModuleCount());
     }

     m_fixer = std::make_unique<Fixer>(
          m_mem, m_resolver,
          m_liftedFunctions, m_mirrorVariables, m_indirectCallSlots,
          m_scanner.GetDecoder()
     );
}

CodeLifter::~CodeLifter()
{
     for (auto& kv : m_mirrorVariables)   _aligned_free(kv.second);
     for (auto& kv : m_indirectCallSlots) free(kv.second);
}


// 主入口
bool CodeLifter::CollectFunction(uintptr_t targetFuncAddr, size_t hintSize)
{
     if (hintSize > 0) {
          printf("[+] Using manual size hint: %zu bytes\n", hintSize);
          CollectOneWithSize(targetFuncAddr, hintSize, 0);
     }
     else {
          m_workQueue.push({ targetFuncAddr, 0 });
          m_enqueuedAddresses[targetFuncAddr] = true;
     }

     ProcessWorkQueue();

     bool success = m_liftedFunctions.count(targetFuncAddr) > 0;

     if (success) {
          m_fixer->FixupAll(m_arena.GetBase(), m_arena.GetUsed());
     }

     return success;
}

void CodeLifter::ProcessWorkQueue()
{
     size_t processed = 0;
     while (!m_workQueue.empty()) {
          WorkItem item = m_workQueue.front();
          m_workQueue.pop();

          CollectOne(item.addr, item.depth);

          processed++;
          if (processed % 100 == 0) {
               printf("[*] Processed %zu items, queue=%zu\n",
                    processed, m_workQueue.size());
          }
     }
     printf("[*] Total processed: %zu functions\n", processed);
}

void CodeLifter::EnqueueIfNeeded(uintptr_t addr, int depth)
{
     if (addr == 0) return;
     if (m_liftedFunctions.count(addr)) return;
     if (m_enqueuedAddresses.count(addr)) return;

     m_workQueue.push({ addr, depth });
     m_enqueuedAddresses[addr] = true;
}


// 搬运一个函数（自动识别大小）
void CodeLifter::CollectOne(uintptr_t addr, int depth)
{
     if (m_liftedFunctions.count(addr)) return;

     MEMORY_BASIC_INFORMATION mbi = {};
     if (!m_mem.Query(addr, &mbi) || mbi.State != MEM_COMMIT) {
          printf("[!] Address 0x%llx not committed\n", (unsigned long long)addr);
          return;
     }

     const DWORD EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ |
          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
     if ((mbi.Protect & EXEC_MASK) == 0) {
          printf("[!] Address 0x%llx not executable\n", (unsigned long long)addr);
          return;
     }

     uintptr_t funcEnd = m_scanner.FindFunctionEnd(addr);
     if (funcEnd <= addr) return;

     size_t funcSize = funcEnd - addr;
     if (funcSize > MAX_FUNCTION_SIZE) {
          printf("[!] Function too large at 0x%llx (size=%zu)\n",
               (unsigned long long)addr, funcSize);
          return;
     }

     void* localCode = m_arena.Allocate(funcSize);
     if (!localCode) return;

     if (!m_mem.Read(addr, localCode, funcSize)) {
          printf("[!] Failed to read at 0x%llx\n", (unsigned long long)addr);
          return;
     }

     m_liftedFunctions[addr] = { localCode, funcSize };

     printf("[+] Collected 0x%llx -> %p (size=%zu, depth=%d)\n",
          (unsigned long long)addr, localCode, funcSize, depth);

     ScanInstructions(addr, localCode, funcSize, depth);
}


// 搬运一个函数（手动指定大小）
void CodeLifter::CollectOneWithSize(uintptr_t addr, size_t funcSize, int depth)
{
     if (m_liftedFunctions.count(addr)) return;

     MEMORY_BASIC_INFORMATION mbi = {};
     if (!m_mem.Query(addr, &mbi) || mbi.State != MEM_COMMIT) {
          printf("[!] Address 0x%llx not committed\n", (unsigned long long)addr);
          return;
     }

     const DWORD EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ |
          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
     if ((mbi.Protect & EXEC_MASK) == 0) {
          printf("[!] Address 0x%llx not executable\n", (unsigned long long)addr);
          return;
     }

     void* localCode = m_arena.Allocate(funcSize);
     if (!localCode) return;

     if (!m_mem.Read(addr, localCode, funcSize)) {
          printf("[!] Failed to read at 0x%llx\n", (unsigned long long)addr);
          return;
     }

     m_liftedFunctions[addr] = { localCode, funcSize };

     printf("[+] Collected (manual) 0x%llx -> %p (size=%zu, depth=%d)\n",
          (unsigned long long)addr, localCode, funcSize, depth);

     ScanInstructions(addr, localCode, funcSize, depth);
}


// 扫描指令收集依赖
void CodeLifter::ScanInstructions(uintptr_t origAddr, void* localCode,
     size_t funcSize, int depth)
{
     uint8_t* code = (uint8_t*)localCode;
     size_t offset = 0;

     ZydisDecodedInstruction insn;
     ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

     while (offset < funcSize) {
          ZyanStatus status = ZydisDecoderDecodeFull(
               &m_scanner.GetDecoder(),
               code + offset, funcSize - offset,
               &insn, operands);

          if (!ZYAN_SUCCESS(status)) {
               offset += 1;
               continue;
          }

          uintptr_t nextRipOrig = origAddr + offset + insn.length;

          // RIP 相对引用
          for (int i = 0; i < insn.operand_count_visible; i++) {
               const auto& op = operands[i];

               if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    op.mem.base == ZYDIS_REGISTER_RIP) {

                    uintptr_t target = nextRipOrig + op.mem.disp.value;

                    bool isIndirectBranch =
                         (insn.mnemonic == ZYDIS_MNEMONIC_CALL) ||
                         (insn.mnemonic == ZYDIS_MNEMONIC_JMP);

                    if (isIndirectBranch) {
                         EnsureIndirectCallSlot(target, depth);
                    }
                    else {
                         size_t accessSize = op.size / 8;
                         EnsureMirrorVariable(target, accessSize);
                    }
               }
          }

          // 直接控制流
          bool isControlFlow =
               (insn.mnemonic == ZYDIS_MNEMONIC_CALL) ||
               (insn.mnemonic == ZYDIS_MNEMONIC_JMP) ||
               (insn.mnemonic >= ZYDIS_MNEMONIC_JB &&
                    insn.mnemonic <= ZYDIS_MNEMONIC_JZ);

          if (isControlFlow) {
               for (int i = 0; i < insn.operand_count_visible; i++) {
                    const auto& op = operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                         op.imm.is_relative) {
                         uintptr_t target = op.imm.is_signed ? nextRipOrig + op.imm.value.s : nextRipOrig + op.imm.value.u;
                         HandleControlFlowTarget(target, origAddr, funcSize, depth);
                         break;
                    }
               }
          }

          offset += insn.length;
     }
}

void CodeLifter::EnsureMirrorVariable(uintptr_t targetAddr, size_t accessSize)
{
     if (m_mirrorVariables.count(targetAddr)) return;

     size_t allocSize = std::max<size_t>(accessSize, 32);
     allocSize = (allocSize + 31) & ~size_t(31);

     void* mirror = _aligned_malloc(allocSize, 32);
     if (!mirror) return;

     memset(mirror, 0, allocSize);
     m_mem.Read(targetAddr, mirror, allocSize);

     m_mirrorVariables[targetAddr] = mirror;
}

void CodeLifter::EnsureIndirectCallSlot(uintptr_t targetPtrAddr, int depth)
{
     uintptr_t actualFuncAddr = 0;
     m_mem.Read(targetPtrAddr, &actualFuncAddr, sizeof(uintptr_t));

     if (actualFuncAddr != 0 && !m_resolver.IsSharedWithLocal(actualFuncAddr)) {
          MEMORY_BASIC_INFORMATION mbi = {};
          if (m_mem.Query(actualFuncAddr, &mbi)) {
               const DWORD EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
               if (mbi.State == MEM_COMMIT && (mbi.Protect & EXEC_MASK)) {
                    EnqueueIfNeeded(actualFuncAddr, depth + 1);
               }
          }
     }

     if (!m_indirectCallSlots.count(targetPtrAddr)) {
          void* slot = malloc(sizeof(uintptr_t));
          if (slot) {
               *(uintptr_t*)slot = 0;
               m_indirectCallSlots[targetPtrAddr] = slot;
          }
     }
}

void CodeLifter::HandleControlFlowTarget(uintptr_t target,
     uintptr_t funcStart,
     size_t funcSize,
     int depth)
{
     if (target >= funcStart && target <= funcStart + funcSize) return;
     if (m_resolver.IsSharedWithLocal(target)) return;

     MEMORY_BASIC_INFORMATION mbi = {};
     if (!m_mem.Query(target, &mbi)) return;
     if (mbi.State != MEM_COMMIT) return;

     const DWORD EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ |
          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
     if ((mbi.Protect & EXEC_MASK) == 0) return;

     EnqueueIfNeeded(target, depth + 1);
}


// 运行时操作
void CodeLifter::SyncMirrors()
{
     for (auto& kv : m_mirrorVariables) {
          m_mem.Read(kv.first, kv.second, 32);
     }
}

void CodeLifter::SyncIndirectSlots()
{
     for (auto& kv : m_indirectCallSlots) {
          m_fixer->FillIndirectSlot(kv.first, kv.second);
     }
}

void* CodeLifter::GetLocalFunction(uintptr_t origAddr) const
{
     auto it = m_liftedFunctions.find(origAddr);
     if (it == m_liftedFunctions.end()) return nullptr;
     return it->second.localAddress;
}


// 打印结果
void CodeLifter::DumpResult() const
{
     printf("\n========== Phase 1 Result ==========\n");
     printf("Lifted functions: %zu\n", m_liftedFunctions.size());

     size_t count = 0;
     for (const auto& kv : m_liftedFunctions) {
          if (count >= 20) {
               printf("  ... and %zu more\n", m_liftedFunctions.size() - 20);
               break;
          }
          printf("  0x%llx -> %p (size=%zu)\n",
               (unsigned long long)kv.first,
               kv.second.localAddress,
               kv.second.size);
          count++;
     }

     printf("\nMirror variables: %zu\n", m_mirrorVariables.size());
     printf("Indirect call slots: %zu\n", m_indirectCallSlots.size());
     printf("\nArena: %zu used, %zu MB committed, %zu MB reserved\n",
          m_arena.GetUsed(),
          m_arena.GetCommitted() / (1024 * 1024),
          m_arena.GetCapacity() / (1024 * 1024));
     printf("====================================\n");
}