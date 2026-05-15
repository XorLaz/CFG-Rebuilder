// CodeLifter.cpp
#include "CodeLifter.h"
#include <cstdio>
#include <cstdlib>
#include <algorithm>

#pragma comment(lib, "Psapi.lib")

namespace {
     constexpr size_t ARENA_SIZE = 16 * 1024 * 1024;
     constexpr int    MAX_RECURSION = 600;
     constexpr size_t MAX_FUNCTION_SIZE = 65536;
     constexpr size_t SCAN_BUF_SIZE = 65536;
     constexpr size_t MIN_FUNC_SIZE = 8;

     // 跨进程地址共享可信的系统核心 DLL
     // 这些 DLL 在所有进程基址相同
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

     // 转小写
     std::string ToLowerString(const char* s) {
          std::string r(s);
          std::transform(r.begin(), r.end(), r.begin(),
               [](unsigned char c) { return (char)std::tolower(c); });
          return r;
     }

     // 提取路径中的文件名
     std::string ExtractFileName(const char* path) {
          const char* p = strrchr(path, '\\');
          return ToLowerString(p ? (p + 1) : path);
     }
}


// 构造 / 析构
CodeLifter::CodeLifter(HANDLE hTargetProcess)
     : m_hTargetProcess(hTargetProcess)
     , m_codeArenaCapacity(ARENA_SIZE)
     , m_codeArenaUsed(0)
{
     m_codeArenaBase = (uint8_t*)VirtualAlloc(
          nullptr, m_codeArenaCapacity,
          MEM_COMMIT | MEM_RESERVE,
          PAGE_EXECUTE_READWRITE
     );
     if (!m_codeArenaBase) {
          printf("[!] Failed to allocate code arena: %lu\n", GetLastError());
     }

     ZydisDecoderInit(&m_decoder,
          ZYDIS_MACHINE_MODE_LONG_64,
          ZYDIS_STACK_WIDTH_64);

     // 加载目标进程模块列表
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


// 加载目标进程的模块列表
bool CodeLifter::LoadTargetModules()
{
     DWORD pid = GetProcessId(m_hTargetProcess);
     if (pid == 0) return false;

     HANDLE hSnap = CreateToolhelp32Snapshot(
          TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
     if (hSnap == INVALID_HANDLE_VALUE) {
          // Toolhelp 拿不到时，备用方案：EnumProcessModulesEx
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


// 判断：目标进程的某个地址，在本地是否可以直接调用
//   条件：地址在目标进程里属于可信系统 DLL，且本地也加载了相同基址的同名 DLL
bool CodeLifter::IsAddressSharedWithLocal(uintptr_t addrInTarget)
{
     if (addrInTarget == 0) return false;

     const TargetModule* mod = FindTargetModule(addrInTarget);
     if (!mod) return false;

     // 检查是否在白名单
     bool trusted = false;
     for (const char* t : TRUSTED_SHARED_MODULES) {
          if (mod->name == t) {
               trusted = true;
               break;
          }
     }
     if (!trusted) return false;

     // 本地必须也加载了这个 DLL，且基址必须相同
     HMODULE hLocal = GetModuleHandleA(mod->name.c_str());
     if (!hLocal) return false;
     if ((uintptr_t)hLocal != mod->base) return false;

     return true;
}


// 判断：目标进程的某个地址是否可执行（跨进程 VirtualQuery）
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


// 分配本地代码区空间
void* CodeLifter::AllocateInArena(size_t size)
{
     size_t aligned = (size + 15) & ~size_t(15);

     if (m_codeArenaUsed + aligned > m_codeArenaCapacity) {
          printf("[!] Code arena exhausted\n");
          return nullptr;
     }

     void* result = m_codeArenaBase + m_codeArenaUsed;
     m_codeArenaUsed += aligned;
     return result;
}


// 找函数边界
uintptr_t CodeLifter::FindFunctionEnd(uintptr_t funcStart)
{
     if (!funcStart) return funcStart;


     // 用 VirtualQueryEx 获取目标进程可执行区域的硬上限
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


     // 工具函数
     auto isPadding = [&](size_t i) -> bool {
          return i < maxScan && (buffer[i] == 0xCC || buffer[i] == 0x90);
          };

     // 数从 i 开始的连续 padding 数量
     auto countPadding = [&](size_t i) -> size_t {
          size_t pad = 0;
          while (i + pad < maxScan && isPadding(i + pad)) pad++;
          return pad;
          };

     // 函数 prologue / thunk 模式
     auto looksLikeFunctionStart = [&](size_t i) -> bool {
          if (i + 4 >= maxScan) return false;
          uint8_t b0 = buffer[i], b1 = buffer[i + 1], b2 = buffer[i + 2], b3 = buffer[i + 3];

          // push reg: 53/55/56/57
          if (b0 == 0x53 || b0 == 0x55 || b0 == 0x56 || b0 == 0x57) return true;
          // REX + push rbp/rbx/rsi/rdi: 40 53/55/56/57
          if (b0 == 0x40 && (b1 == 0x53 || b1 == 0x55 || b1 == 0x56 || b1 == 0x57)) return true;
          // REX.B + push r8~r15: 41 50~57
          if (b0 == 0x41 && b1 >= 0x50 && b1 <= 0x57) return true;
          // mov [rsp+X], reg: 48 89 5C/4C/54/74/7C 24
          if (b0 == 0x48 && b1 == 0x89 && b3 == 0x24 &&
               (b2 == 0x5C || b2 == 0x4C || b2 == 0x54 || b2 == 0x74 || b2 == 0x7C)) return true;
          // mov [rsp+X], r8~r15: 4C 89 44/4C/54/5C/64/6C/74/7C 24
          if (b0 == 0x4C && b1 == 0x89 && b3 == 0x24 &&
               b2 >= 0x44 && b2 <= 0x7C && (b2 & 0x7) == 0x4) return true;
          // sub rsp, X: 48 83 EC / 48 81 EC
          if (b0 == 0x48 && (b1 == 0x83 || b1 == 0x81) && b2 == 0xEC) return true;
          // mov reg, [rip+disp]: 48 8B 05/0D/15/1D/25/2D/35/3D
          if (b0 == 0x48 && b1 == 0x8B && (b2 & 0xC7) == 0x05) return true;
          // thunk: lea rcx, [...]: 48 8D 0D
          if (b0 == 0x48 && b1 == 0x8D && b2 == 0x0D) return true;

          return false;
          };

     // ret 前面是不是 pop 序列（epilogue 标志）
     auto retHasEpilogue = [&](size_t retPos) -> bool {
          if (retPos < 1) return false;
          uint8_t prev = buffer[retPos - 1];
          // 单字节 pop reg: 58~5F
          if (prev >= 0x58 && prev <= 0x5F) return true;
          // 多字节 pop r8~r15: 41 58~5F
          if (retPos >= 2 && buffer[retPos - 2] == 0x41 &&
               prev >= 0x58 && prev <= 0x5F) return true;
          return false;
          };

     // 计算 jmp 指令的长度（用于跳过它找 padding 起始位置）
     // 返回 0 表示不是 jmp
     auto getJmpLen = [&](size_t i) -> size_t {
          if (i >= maxScan) return 0;
          uint8_t b = buffer[i];

          // jmp rel32: E9 + 4 字节
          if (b == 0xE9) return 5;
          // jmp rel8: EB + 1 字节
          if (b == 0xEB) return 2;

          // FF /4: 间接 jmp
          if (b == 0xFF && i + 1 < maxScan) {
               uint8_t modrm = buffer[i + 1];
               if (((modrm >> 3) & 0x7) != 4) return 0;
               uint8_t mod = (modrm >> 6) & 0x3;
               uint8_t rm = modrm & 0x7;
               if (mod == 3) return 2;                      // jmp reg
               if (mod == 0 && rm == 5) return 6;           // jmp [rip+disp32]
               return 0;
          }

          // 48 FF /4: 带 REX 的间接 jmp
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


     // 主扫描循环
     // 默认 funcEnd = 可执行区域末尾（兜底，宁可多搬不少拷）
     uintptr_t funcEnd = funcStart + maxScan;

     for (size_t i = MIN_FUNC_SIZE; i + 8 < maxScan; i++) {
          uintptr_t scanAddr = funcStart + i;
          uint8_t b = buffer[i];

          // -------- 信号 1：16 字节对齐 + 紧邻 padding + 标准入口 --------
          if ((scanAddr & 0xF) == 0 && i >= 1 &&
               isPadding(i - 1) && looksLikeFunctionStart(i)) {
               funcEnd = scanAddr;
               break;
          }

          // -------- 信号 2：连续 padding(≥2) + 合法入口 --------
          if (isPadding(i) && isPadding(i + 1)) {
               size_t pad = countPadding(i);
               if (i + pad < maxScan && looksLikeFunctionStart(i + pad)) {
                    funcEnd = funcStart + i;
                    break;
               }
          }

          // -------- 信号 3a：ret + (后面是 padding 或前面是 epilogue) --------
          if (b == 0xC3 || b == 0xC2) {
               size_t retLen = (b == 0xC3) ? 1 : 3;
               size_t afterRet = i + retLen;

               if (isPadding(afterRet) || retHasEpilogue(i)) {
                    funcEnd = funcStart + afterRet;
                    break;
               }
          }

          // -------- 信号 3b：jmp + 大量 padding(≥8) --------
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


// 阶段 1 入口
bool CodeLifter::CollectFunction(uintptr_t targetFuncAddr)
{
     CollectRecursive(targetFuncAddr, 0);
     return m_liftedFunctions.count(targetFuncAddr) > 0;
}


// 递归搬运
void CodeLifter::CollectRecursive(uintptr_t addr, int depth)
{
     if (depth > MAX_RECURSION) {
          printf("[!] Max recursion depth at 0x%llx\n", (unsigned long long)addr);
          return;
     }

     if (m_liftedFunctions.count(addr)) return;

     if (!IsExecutableInTarget(addr)) {
          printf("[!] Address 0x%llx is not executable in target\n",
               (unsigned long long)addr);
          return;
     }

     uintptr_t funcEnd = FindFunctionEnd(addr);
     if (funcEnd <= addr) return;

     size_t funcSize = funcEnd - addr;
     if (funcSize > MAX_FUNCTION_SIZE) {
          printf("[!] Function too large at 0x%llx\n", (unsigned long long)addr);
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

     // 合并后的注册
     m_liftedFunctions[addr] = { localCode, funcSize };

     printf("[+] Collected 0x%llx -> %p (size=%zu, depth=%d)\n",
          (unsigned long long)addr, localCode, funcSize, depth);

     ScanInstructions(addr, localCode, funcSize, depth);
}


// 扫描指令收集依赖
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
                         // 用操作数大小决定镜像变量大小
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


// 建/取镜像变量（按访问大小，最少 32 字节，覆盖 AVX-256）
void CodeLifter::EnsureMirrorVariable(uintptr_t targetAddr, size_t accessSize)
{
     if (m_mirrorVariables.count(targetAddr)) return;

     // 至少 32 字节（AVX-256），按 32 字节向上对齐分配
     size_t allocSize = std::max<size_t>(accessSize, 32);
     allocSize = (allocSize + 31) & ~size_t(31);

     void* mirror = _aligned_malloc(allocSize, 32);
     if (!mirror) return;

     memset(mirror, 0, allocSize);
     ReadProcessMemory(m_hTargetProcess, (LPCVOID)targetAddr,
          mirror, allocSize, nullptr);

     m_mirrorVariables[targetAddr] = mirror;
}


// 建/取间接调用槽，按需递归搬目标函数
void CodeLifter::EnsureIndirectCallSlot(uintptr_t targetPtrAddr, int depth)
{
     uintptr_t actualFuncAddr = 0;
     ReadProcessMemory(m_hTargetProcess, (LPCVOID)targetPtrAddr,
          &actualFuncAddr, sizeof(uintptr_t), nullptr);

     // 用 IsAddressSharedWithLocal 判断（不是 IsLocallyCallable）
     if (actualFuncAddr != 0 && !IsAddressSharedWithLocal(actualFuncAddr)) {
          // 不是共享系统 DLL，必须搬过来
          // 但只在目标地址确实可执行时才搬
          if (IsExecutableInTarget(actualFuncAddr)) {
               CollectRecursive(actualFuncAddr, depth + 1);
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


// 处理直接控制流目标
void CodeLifter::HandleControlFlowTarget(uintptr_t target,uintptr_t funcStart,size_t funcSize,int depth)
{
     // 函数内跳转
     if (target >= funcStart && target < funcStart + funcSize) return;

     // 共享系统 DLL
     if (IsAddressSharedWithLocal(target)) return;

     // 目标必须在目标进程里可执行
     if (!IsExecutableInTarget(target)) return;

     // 递归搬
     CollectRecursive(target, depth + 1);
}


// 打印结果
void CodeLifter::DumpResult() const
{
     printf("\n========== Phase 1 Result ==========\n");

     printf("Lifted functions: %zu\n", m_liftedFunctions.size());
     for (const auto& kv : m_liftedFunctions) {
          printf("  0x%llx -> %p (size=%zu)\n",
               (unsigned long long)kv.first,
               kv.second.localAddress,
               kv.second.size);
     }

     printf("\nMirror variables: %zu\n", m_mirrorVariables.size());
     for (const auto& kv : m_mirrorVariables) {
          printf("  0x%llx -> %p (first8=0x%llx)\n",
               (unsigned long long)kv.first, kv.second,
               (unsigned long long) * (uint64_t*)kv.second);
     }

     printf("\nIndirect call slots: %zu\n", m_indirectCallSlots.size());
     for (const auto& kv : m_indirectCallSlots) {
          uintptr_t actualFunc = 0;
          ReadProcessMemory(m_hTargetProcess, (LPCVOID)kv.first,
               &actualFunc, sizeof(uintptr_t), nullptr);

          const char* status = "?";
          const char* moduleName = "?";

          for (const auto& mod : m_targetModules) {
               if (actualFunc >= mod.base && actualFunc < mod.base + mod.size) {
                    moduleName = mod.name.c_str();
                    break;
               }
          }

          if (actualFunc != 0) {
               bool shared = false;
               for (const char* t : TRUSTED_SHARED_MODULES) {
                    if (moduleName == std::string(t)) {
                         HMODULE h = GetModuleHandleA(t);
                         auto* foundMod = FindTargetModule(actualFunc);
                         if (h && foundMod && (uintptr_t)h == foundMod->base) {
                              shared = true;
                         }
                         break;
                    }
               }
               status = shared ? "shared" : "lifted";
          }

          printf("  slot 0x%llx -> local %p, actualFunc=0x%llx [%s, %s]\n",
               (unsigned long long)kv.first, kv.second,
               (unsigned long long)actualFunc, status, moduleName);
     }

     printf("\nCode arena: %zu / %zu bytes used\n",
          m_codeArenaUsed, m_codeArenaCapacity);
     printf("====================================\n");
}