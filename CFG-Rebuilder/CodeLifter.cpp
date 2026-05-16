#include "CodeLifter.h"
#include <cstdio>
#include <cstdlib>
#include <algorithm>

#pragma comment(lib, "Psapi.lib")

namespace {
     constexpr size_t ARENA_RESERVE_SIZE = 1ULL * 1024 * 1024 * 1024;  // 1GB
     constexpr size_t COMMIT_CHUNK_SIZE = 16 * 1024 * 1024;            // 16MB
     constexpr int    MAX_RECURSION = 100000;                      // 不再用，但保留
     constexpr size_t MAX_FUNCTION_SIZE = 65536;
     constexpr size_t SCAN_BUF_SIZE = 65536;
     constexpr size_t MIN_FUNC_SIZE = 8;

     const char* TRUSTED_SHARED_MODULES[] = {
         "ntdll.dll",
         "kernel32.dll",
         "kernelbase.dll",
         "user32.dll",
         "gdi32.dll",
         "advapi32.dll",
         "ws2_32.dll",
         "ole32.dll",
         "oleaut32.dll",
         "shell32.dll",
         "rpcrt4.dll",
         "sechost.dll",
         "win32u.dll",
         "combase.dll",
     };

     std::string ToLowerString(const char* s) {
          std::string r(s);
          std::transform(r.begin(), r.end(), r.begin(),
               [](unsigned char c) { return (char)std::tolower(c); });
          return r;
     }

     std::string ExtractFileName(const char* path) {
          const char* p = strrchr(path, '\\');
          return ToLowerString(p ? (p + 1) : path);
     }
}


// 构造 / 析构
CodeLifter::CodeLifter(HANDLE hTargetProcess)
     : m_hTargetProcess(hTargetProcess)
     , m_codeArenaCapacity(ARENA_RESERVE_SIZE)
     , m_codeArenaUsed(0)
     , m_codeArenaCommitted(0)
{
     // Reserve 1GB 地址空间
     m_codeArenaBase = (uint8_t*)VirtualAlloc(
          nullptr,
          ARENA_RESERVE_SIZE,
          MEM_RESERVE,
          PAGE_EXECUTE_READWRITE
     );
     if (!m_codeArenaBase) {
          printf("[!] Failed to reserve arena: %lu\n", GetLastError());
          return;
     }

     // Commit 初始 16MB
     if (!VirtualAlloc(m_codeArenaBase, COMMIT_CHUNK_SIZE,
          MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
          printf("[!] Failed to commit initial chunk: %lu\n", GetLastError());
          return;
     }
     m_codeArenaCommitted = COMMIT_CHUNK_SIZE;

     printf("[+] Reserved %zu MB, committed initial %zu MB\n",
          ARENA_RESERVE_SIZE / (1024 * 1024),
          COMMIT_CHUNK_SIZE / (1024 * 1024));

     ZydisDecoderInit(&m_decoder,
          ZYDIS_MACHINE_MODE_LONG_64,
          ZYDIS_STACK_WIDTH_64);

     if (!LoadTargetModules()) {
          printf("[!] Failed to load target modules\n");
     }
     else {
          printf("[+] Loaded %zu target modules\n", m_targetModules.size());
     }
}

CodeLifter::~CodeLifter()
{
     for (auto& kv : m_mirrorVariables)   _aligned_free(kv.second);
     for (auto& kv : m_indirectCallSlots) free(kv.second);
     if (m_codeArenaBase) {
          VirtualFree(m_codeArenaBase, 0, MEM_RELEASE);
     }
}


// 加载目标进程模块列表
bool CodeLifter::LoadTargetModules()
{
     DWORD pid = GetProcessId(m_hTargetProcess);
     if (pid == 0) return false;

     HANDLE hSnap = CreateToolhelp32Snapshot(
          TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
     if (hSnap == INVALID_HANDLE_VALUE) {
          HMODULE mods[1024];
          DWORD needed = 0;
          if (!EnumProcessModulesEx(m_hTargetProcess, mods, sizeof(mods),
               &needed, LIST_MODULES_ALL)) {
               return false;
          }
          size_t count = needed / sizeof(HMODULE);
          for (size_t i = 0; i < count; i++) {
               MODULEINFO mi = {};
               char name[MAX_PATH] = { 0 };
               if (GetModuleInformation(m_hTargetProcess, mods[i],
                    &mi, sizeof(mi)) &&
                    GetModuleFileNameExA(m_hTargetProcess, mods[i],
                         name, sizeof(name))) {
                    TargetModule m;
                    m.name = ExtractFileName(name);
                    m.base = (uintptr_t)mi.lpBaseOfDll;
                    m.size = mi.SizeOfImage;
                    m_targetModules.push_back(m);
               }
          }
          return !m_targetModules.empty();
     }

     MODULEENTRY32W me = { sizeof(me) };
     if (Module32FirstW(hSnap, &me)) {
          do {
               char buf[MAX_PATH] = { 0 };
               WideCharToMultiByte(CP_ACP, 0, me.szModule, -1,
                    buf, MAX_PATH, nullptr, nullptr);
               TargetModule m;
               m.name = ToLowerString(buf);
               m.base = (uintptr_t)me.modBaseAddr;
               m.size = me.modBaseSize;
               m_targetModules.push_back(m);
          } while (Module32NextW(hSnap, &me));
     }

     CloseHandle(hSnap);
     return !m_targetModules.empty();
}

const CodeLifter::TargetModule* CodeLifter::FindTargetModule(uintptr_t addr) const
{
     for (auto& m : m_targetModules) {
          if (addr >= m.base && addr < m.base + m.size) {
               return &m;
          }
     }
     return nullptr;
}


// 共享判断
bool CodeLifter::IsAddressSharedWithLocal(uintptr_t addrInTarget)
{
     if (addrInTarget == 0) return false;

     const TargetModule* mod = FindTargetModule(addrInTarget);
     if (!mod) return false;

     bool trusted = false;
     for (const char* t : TRUSTED_SHARED_MODULES) {
          if (mod->name == t) {
               trusted = true;
               break;
          }
     }
     if (!trusted) return false;

     HMODULE hLocal = GetModuleHandleA(mod->name.c_str());
     if (!hLocal) return false;
     if ((uintptr_t)hLocal != mod->base) return false;

     return true;
}

bool CodeLifter::IsExecutableInTarget(uintptr_t addr)
{
     if (addr == 0) return false;

     MEMORY_BASIC_INFORMATION mbi = {};
     if (!VirtualQueryEx(m_hTargetProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
          return false;
     }
     if (mbi.State != MEM_COMMIT) return false;

     const DWORD EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ |
          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
     return (mbi.Protect & EXEC_MASK) != 0;
}


// 代码区分配（自动 commit 更多）
void* CodeLifter::AllocateInArena(size_t size)
{
     size_t aligned = (size + 15) & ~size_t(15);

     if (m_codeArenaUsed + aligned > m_codeArenaCapacity) {
          printf("[!] Code arena exhausted (1GB limit reached!)\n");
          return nullptr;
     }

     while (m_codeArenaUsed + aligned > m_codeArenaCommitted) {
          size_t commitTo = std::min<size_t>(
               m_codeArenaCommitted + COMMIT_CHUNK_SIZE,
               m_codeArenaCapacity
          );
          size_t toCommit = commitTo - m_codeArenaCommitted;

          if (!VirtualAlloc(m_codeArenaBase + m_codeArenaCommitted,
               toCommit,
               MEM_COMMIT,
               PAGE_EXECUTE_READWRITE)) {
               printf("[!] Failed to commit more memory: %lu\n", GetLastError());
               return nullptr;
          }
          m_codeArenaCommitted = commitTo;
          printf("[+] Committed more, total now %zu MB\n",
               m_codeArenaCommitted / (1024 * 1024));
     }

     void* result = m_codeArenaBase + m_codeArenaUsed;
     m_codeArenaUsed += aligned;
     return result;
}


// 找函数边界
uintptr_t CodeLifter::FindFunctionEnd(uintptr_t funcStart)
{
     if (!funcStart) return funcStart;

     MEMORY_BASIC_INFORMATION mbi = {};
     if (!VirtualQueryEx(m_hTargetProcess, (LPCVOID)funcStart, &mbi, sizeof(mbi))) {
          return funcStart + 1;
     }

     const DWORD EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ |
          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
     if (mbi.State != MEM_COMMIT || (mbi.Protect & EXEC_MASK) == 0) {
          return funcStart + 1;
     }

     uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
     size_t maxScan = std::min<size_t>(SCAN_BUF_SIZE, regionEnd - funcStart);
     if (maxScan < MIN_FUNC_SIZE) return funcStart + 1;

     uint8_t* buffer = (uint8_t*)malloc(maxScan);
     if (!buffer) return funcStart + 1;

     ReadProcessMemory(m_hTargetProcess, (LPCVOID)funcStart, buffer, maxScan, nullptr);

     auto isPadding = [&](size_t i) -> bool {
          return i < maxScan && (buffer[i] == 0xCC || buffer[i] == 0x90);
          };

     auto countPadding = [&](size_t i) -> size_t {
          size_t pad = 0;
          while (i + pad < maxScan && isPadding(i + pad)) pad++;
          return pad;
          };

     auto looksLikeFunctionStart = [&](size_t i) -> bool {
          if (i + 4 >= maxScan) return false;
          uint8_t b0 = buffer[i], b1 = buffer[i + 1], b2 = buffer[i + 2], b3 = buffer[i + 3];

          if (b0 == 0x53 || b0 == 0x55 || b0 == 0x56 || b0 == 0x57) return true;
          if (b0 == 0x40 && (b1 == 0x53 || b1 == 0x55 || b1 == 0x56 || b1 == 0x57)) return true;
          if (b0 == 0x41 && b1 >= 0x50 && b1 <= 0x57) return true;
          if (b0 == 0x48 && b1 == 0x89 && b3 == 0x24 &&
               (b2 == 0x5C || b2 == 0x4C || b2 == 0x54 || b2 == 0x74 || b2 == 0x7C)) return true;
          if (b0 == 0x4C && b1 == 0x89 && b3 == 0x24 &&
               b2 >= 0x44 && b2 <= 0x7C && (b2 & 0x7) == 0x4) return true;
          if (b0 == 0x48 && (b1 == 0x83 || b1 == 0x81) && b2 == 0xEC) return true;
          if (b0 == 0x48 && b1 == 0x8B && (b2 & 0xC7) == 0x05) return true;
          if (b0 == 0x48 && b1 == 0x8D && b2 == 0x0D) return true;

          return false;
          };

     auto retHasEpilogue = [&](size_t retPos) -> bool {
          if (retPos < 1) return false;
          uint8_t prev = buffer[retPos - 1];
          if (prev >= 0x58 && prev <= 0x5F) return true;
          if (retPos >= 2 && buffer[retPos - 2] == 0x41 &&
               prev >= 0x58 && prev <= 0x5F) return true;
          return false;
          };

     auto getJmpLen = [&](size_t i) -> size_t {
          if (i >= maxScan) return 0;
          uint8_t b = buffer[i];

          if (b == 0xE9) return 5;
          if (b == 0xEB) return 2;

          if (b == 0xFF && i + 1 < maxScan) {
               uint8_t modrm = buffer[i + 1];
               if (((modrm >> 3) & 0x7) != 4) return 0;
               uint8_t mod = (modrm >> 6) & 0x3;
               uint8_t rm = modrm & 0x7;
               if (mod == 3) return 2;
               if (mod == 0 && rm == 5) return 6;
               return 0;
          }

          if (b == 0x48 && i + 2 < maxScan && buffer[i + 1] == 0xFF) {
               uint8_t modrm = buffer[i + 2];
               if (((modrm >> 3) & 0x7) != 4) return 0;
               uint8_t mod = (modrm >> 6) & 0x3;
               uint8_t rm = modrm & 0x7;
               if (mod == 3) return 3;
               if (mod == 0 && rm == 5) return 7;
               return 0;
          }

          return 0;
          };

     uintptr_t funcEnd = funcStart + maxScan;

     for (size_t i = MIN_FUNC_SIZE; i + 8 < maxScan; i++) {
          uintptr_t scanAddr = funcStart + i;
          uint8_t b = buffer[i];

          // 信号 1
          if ((scanAddr & 0xF) == 0 && i >= 1 &&
               isPadding(i - 1) && looksLikeFunctionStart(i)) {
               funcEnd = scanAddr;
               break;
          }

          // 信号 2
          if (isPadding(i) && isPadding(i + 1)) {
               size_t pad = countPadding(i);
               if (i + pad < maxScan && looksLikeFunctionStart(i + pad)) {
                    funcEnd = funcStart + i;
                    break;
               }
          }

          // 信号 3a
          if (b == 0xC3 || b == 0xC2) {
               size_t retLen = (b == 0xC3) ? 1 : 3;
               size_t afterRet = i + retLen;

               if (isPadding(afterRet) || retHasEpilogue(i)) {
                    funcEnd = funcStart + afterRet;
                    break;
               }
          }

          // 信号 3b
          size_t jmpLen = getJmpLen(i);
          if (jmpLen > 0) {
               size_t afterJmp = i + jmpLen;
               if (isPadding(afterJmp) && countPadding(afterJmp) >= 8) {
                    funcEnd = funcStart + afterJmp;
                    break;
               }
          }
     }

     free(buffer);
     return funcEnd;
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
               printf("[*] Processed %zu items, queue size=%zu\n",
                    processed, m_workQueue.size());
          }
     }
     printf("[*] Total processed: %zu functions\n", processed);
}


// 检查并入队（防止重复入队）
void CodeLifter::EnqueueIfNeeded(uintptr_t addr, int depth)
{
     if (addr == 0) return;
     if (m_liftedFunctions.count(addr)) return;
     if (m_enqueuedAddresses.count(addr)) return;

     m_workQueue.push({ addr, depth });
     m_enqueuedAddresses[addr] = true;
}


// 搬运一个函数（不再递归）
void CodeLifter::CollectOne(uintptr_t addr, int depth)
{
     // 不再有递归深度限制
     if (m_liftedFunctions.count(addr)) return;

     if (!IsExecutableInTarget(addr)) {
          printf("[!] Address 0x%llx not executable in target\n",
               (unsigned long long)addr);
          return;
     }

     uintptr_t funcEnd = FindFunctionEnd(addr);
     if (funcEnd <= addr) return;

     size_t funcSize = funcEnd - addr;
     if (funcSize > MAX_FUNCTION_SIZE) {
          printf("[!] Function too large at 0x%llx (size=%zu)\n",
               (unsigned long long)addr, funcSize);
          return;
     }

     void* localCode = AllocateInArena(funcSize);
     if (!localCode) return;

     SIZE_T bytesRead = 0;
     if (!ReadProcessMemory(m_hTargetProcess, (LPCVOID)addr,
          localCode, funcSize, &bytesRead)
          || bytesRead != funcSize) {
          printf("[!] RPM failed at 0x%llx\n", (unsigned long long)addr);
          return;
     }

     m_liftedFunctions[addr] = { localCode, funcSize };

     printf("[+] Collected 0x%llx -> %p (size=%zu, depth=%d)\n",
          (unsigned long long)addr, localCode, funcSize, depth);

     ScanInstructions(addr, localCode, funcSize, depth);
}


// 扫描指令收集依赖（不递归，往队列里塞）
void CodeLifter::ScanInstructions(uintptr_t origAddr, void* localCode,size_t funcSize, int depth)
{
     uint8_t* code = (uint8_t*)localCode;
     size_t offset = 0;

     ZydisDecodedInstruction insn;
     ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

     while (offset < funcSize) {
          ZyanStatus status = ZydisDecoderDecodeFull(
               &m_decoder,
               code + offset,
               funcSize - offset,
               &insn,
               operands
          );

          if (!ZYAN_SUCCESS(status)) {
               offset += 1;
               continue;
          }

          uintptr_t nextRipOrig = origAddr + offset + insn.length;

          // RIP 相对引用
          for (int i = 0; i < insn.operand_count; i++) {
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
               for (int i = 0; i < insn.operand_count; i++) {
                    const auto& op = operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                         op.imm.is_relative) {
                         uintptr_t target = op.imm.is_signed
                              ? nextRipOrig + op.imm.value.s
                              : nextRipOrig + op.imm.value.u;
                         HandleControlFlowTarget(target, origAddr, funcSize, depth);
                         break;
                    }
               }
          }

          offset += insn.length;
     }
}


// 建/取镜像变量
void CodeLifter::EnsureMirrorVariable(uintptr_t targetAddr, size_t accessSize)
{
     if (m_mirrorVariables.count(targetAddr)) return;

     size_t allocSize = std::max<size_t>(accessSize, 32);
     allocSize = (allocSize + 31) & ~size_t(31);

     void* mirror = _aligned_malloc(allocSize, 32);
     if (!mirror) return;

     memset(mirror, 0, allocSize);
     ReadProcessMemory(m_hTargetProcess, (LPCVOID)targetAddr,
          mirror, allocSize, nullptr);

     m_mirrorVariables[targetAddr] = mirror;
}


// 建/取间接调用槽（不递归，往队列里塞）
void CodeLifter::EnsureIndirectCallSlot(uintptr_t targetPtrAddr, int depth)
{
     uintptr_t actualFuncAddr = 0;
     ReadProcessMemory(m_hTargetProcess, (LPCVOID)targetPtrAddr,
          &actualFuncAddr, sizeof(uintptr_t), nullptr);

     if (actualFuncAddr != 0 && !IsAddressSharedWithLocal(actualFuncAddr)) {
          if (IsExecutableInTarget(actualFuncAddr)) {
               // 往队列里塞，不递归
               EnqueueIfNeeded(actualFuncAddr, depth + 1);
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


// 处理直接控制流目标（不递归，往队列里塞）
void CodeLifter::HandleControlFlowTarget(uintptr_t target,
     uintptr_t funcStart,
     size_t funcSize,
     int depth)
{
     if (target >= funcStart && target < funcStart + funcSize) return;
     if (IsAddressSharedWithLocal(target)) return;
     if (!IsExecutableInTarget(target)) return;

     // 往队列里塞，不递归
     EnqueueIfNeeded(target, depth + 1);
}



// 阶段 2：修复所有偏移
void CodeLifter::FixupAll()
{
     printf("\n========== Phase 2: Fixup ==========\n");

     // 第一步：填充所有间接调用槽
     size_t filledSlots = 0;
     for (auto& kv : m_indirectCallSlots) {
          FillIndirectSlot(kv.first, kv.second);
          filledSlots++;
     }
     printf("[+] Filled %zu indirect call slots\n", filledSlots);

     // 第二步：修复每个搬过来的函数
     size_t fixedFuncs = 0;
     for (auto& kv : m_liftedFunctions) {
          FixupOneFunction(kv.first, kv.second);
          fixedFuncs++;
          if (fixedFuncs % 100 == 0) {
               printf("[*] Fixed %zu functions\n", fixedFuncs);
          }
     }
     printf("[+] Total fixed: %zu functions\n", fixedFuncs);

     // 第三步：刷新指令缓存
     FlushInstructionCache(GetCurrentProcess(),
          m_codeArenaBase, m_codeArenaUsed);
     printf("[+] Flushed instruction cache\n");

     printf("====================================\n");
}

// 把"游戏地址"翻译成"本地地址"
uintptr_t CodeLifter::ResolveTarget(uintptr_t origAddr)
{
     // 查已搬函数
     auto it1 = m_liftedFunctions.find(origAddr);
     if (it1 != m_liftedFunctions.end()) {
          return (uintptr_t)it1->second.localAddress;
     }

     // 查镜像变量
     auto it2 = m_mirrorVariables.find(origAddr);
     if (it2 != m_mirrorVariables.end()) {
          return (uintptr_t)it2->second;
     }

     // 查间接调用槽
     auto it3 = m_indirectCallSlots.find(origAddr);
     if (it3 != m_indirectCallSlots.end()) {
          return (uintptr_t)it3->second;
     }

     // 共享系统 DLL：本地地址跟游戏地址相同
     if (IsAddressSharedWithLocal(origAddr)) {
          return origAddr;
     }

     return 0;  // 找不到
}


// 填充本地指针槽
void CodeLifter::FillIndirectSlot(uintptr_t origPtrAddr, void* localSlot)
{
     // 读出目标进程指针槽里的函数地址
     uintptr_t origFuncAddr = 0;
     ReadProcessMemory(m_hTargetProcess, (LPCVOID)origPtrAddr,
          &origFuncAddr, sizeof(uintptr_t), nullptr);

     if (origFuncAddr == 0) {
          *(uintptr_t*)localSlot = 0;
          return;
     }

     // 转换成本地地址
     uintptr_t localFuncAddr = ResolveTarget(origFuncAddr);

     if (localFuncAddr == 0) {
          printf("[!] Slot 0x%llx: unresolved target 0x%llx\n",
               (unsigned long long)origPtrAddr,
               (unsigned long long)origFuncAddr);
          *(uintptr_t*)localSlot = 0;
     }
     else {
          *(uintptr_t*)localSlot = localFuncAddr;
     }
}


// 修复一个函数里的所有偏移
void CodeLifter::FixupOneFunction(uintptr_t origAddr, const LiftedFunction& fn)
{
     uint8_t* code = (uint8_t*)fn.localAddress;
     size_t   offset = 0;

     ZydisDecodedInstruction insn;
     ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

     while (offset < fn.size) {
          ZyanStatus status = ZydisDecoderDecodeFull(
               &m_decoder,
               code + offset,
               fn.size - offset,
               &insn,
               operands
          );

          if (!ZYAN_SUCCESS(status)) {
               offset += 1;
               continue;
          }

          // 计算本地下一条指令地址（用于算新偏移）
          uintptr_t localNextRip = (uintptr_t)(code + offset + insn.length);
          // 游戏中下一条指令地址（用于算原始目标）
          uintptr_t origNextRip = origAddr + offset + insn.length;

          // -----------------------------------------------------------------
          // 处理 RIP 相对内存访问 (mov / lea / cmp 等)
          // -----------------------------------------------------------------
          for (int i = 0; i < insn.operand_count; i++) {
               const auto& op = operands[i];

               if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
               if (op.mem.base != ZYDIS_REGISTER_RIP) continue;

               // 算原始目标地址
               uintptr_t origTarget = origNextRip + op.mem.disp.value;

               // 翻译成本地地址
               uintptr_t localTarget = ResolveTarget(origTarget);

               if (localTarget == 0) {
                    printf("[!] Unresolved RIP target 0x%llx in func 0x%llx+0x%zx\n",
                         (unsigned long long)origTarget,
                         (unsigned long long)origAddr, offset);
                    continue;
               }

               // 算新 disp32
               int64_t diff = (int64_t)localTarget - (int64_t)localNextRip;
               if (diff < INT32_MIN || diff > INT32_MAX) {
                    printf("[!] RIP target out of 2GB range at 0x%llx+0x%zx\n",
                         (unsigned long long)origAddr, offset);
                    continue;
               }

               int32_t newDisp = (int32_t)diff;
               size_t dispOffset = insn.raw.disp.offset;
               memcpy(code + offset + dispOffset, &newDisp, 4);
          }

          // -----------------------------------------------------------------
          // 处理 rel8 / rel32 控制流跳转
          // -----------------------------------------------------------------
          bool isControlFlow =
               (insn.mnemonic == ZYDIS_MNEMONIC_CALL) ||
               (insn.mnemonic == ZYDIS_MNEMONIC_JMP) ||
               (insn.mnemonic >= ZYDIS_MNEMONIC_JB &&
                    insn.mnemonic <= ZYDIS_MNEMONIC_JZ);

          if (!isControlFlow) {
               offset += insn.length;
               continue;
          }

          for (int i = 0; i < insn.operand_count; i++) {
               const auto& op = operands[i];

               if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;
               if (!op.imm.is_relative) continue;

               // 算原始目标地址
               uintptr_t origTarget = op.imm.is_signed
                    ? origNextRip + op.imm.value.s
                    : origNextRip + op.imm.value.u;

               // 函数内跳转：不修，相对偏移天然正确
               if (origTarget >= origAddr && origTarget < origAddr + fn.size) {
                    break;
               }

               // 翻译成本地地址
               uintptr_t localTarget = ResolveTarget(origTarget);
               if (localTarget == 0) {
                    printf("[!] Unresolved branch target 0x%llx in func 0x%llx+0x%zx\n",
                         (unsigned long long)origTarget,
                         (unsigned long long)origAddr, offset);
                    break;
               }

               // 算新偏移
               int64_t diff = (int64_t)localTarget - (int64_t)localNextRip;

               // 拿到立即数在指令中的位置和大小
               size_t immOffset = insn.raw.imm[0].offset;
               size_t immSize = insn.raw.imm[0].size / 8;

               if (immSize == 1) {
                    // rel8
                    if (diff < -128 || diff > 127) {
                         printf("[!] rel8 out of range at 0x%llx+0x%zx (diff=%lld)\n",
                              (unsigned long long)origAddr, offset, (long long)diff);
                         break;
                    }
                    code[offset + immOffset] = (uint8_t)(int8_t)diff;
               }
               else if (immSize == 4) {
                    // rel32
                    if (diff < INT32_MIN || diff > INT32_MAX) {
                         printf("[!] rel32 out of range at 0x%llx+0x%zx (diff=%lld, "
                              "需要 trampoline 但未实现)\n",
                              (unsigned long long)origAddr, offset, (long long)diff);
                         break;
                    }
                    int32_t newRel = (int32_t)diff;
                    memcpy(code + offset + immOffset, &newRel, 4);
               }
               else {
                    printf("[!] Unknown imm size %zu at 0x%llx+0x%zx\n",
                         immSize,
                         (unsigned long long)origAddr, offset);
               }

               break;  // 一条指令只处理一个相对立即数
          }

          offset += insn.length;
     }
}



// 阶段 1 主入口（不再递归，改成工作队列）
bool CodeLifter::CollectFunction(uintptr_t targetFuncAddr)
{
     // 把入口函数放进队列
     m_workQueue.push({ targetFuncAddr, 0 });
     m_enqueuedAddresses[targetFuncAddr] = true;

     // 处理队列直到空
     ProcessWorkQueue();

     bool success = m_liftedFunctions.count(targetFuncAddr) > 0;

     // 阶段 2：修复
     if (success) {
          FixupAll();
     }

     return m_liftedFunctions.count(targetFuncAddr) > 0;
}



// 打印结果
void CodeLifter::DumpResult() const
{
     printf("\n========== Phase 1 Result ==========\n");

     printf("Lifted functions: %zu\n", m_liftedFunctions.size());

     // 只打印前 20 个，避免输出太多
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

     printf("\nCode arena: %zu used, %zu MB committed, %zu MB reserved\n",
          m_codeArenaUsed,
          m_codeArenaCommitted / (1024 * 1024),
          m_codeArenaCapacity / (1024 * 1024));
     printf("====================================\n");
}