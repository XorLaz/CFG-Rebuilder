#include "FunctionScanner.h"
#include "MemoryAccess.h"
#include "PdataResolver.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace {
     // 启发式扫描的相关常量
     constexpr size_t SCAN_BUF_SIZE = 65536;
     constexpr size_t MIN_FUNC_SIZE = 8;
     constexpr size_t MIN_PADDING_COUNT = 3;
}

FunctionScanner::FunctionScanner(MemoryAccess& mem, PdataResolver& pdataResolver)
     : m_mem(mem)
     , m_pdata(pdataResolver)
{
     ZydisDecoderInit(&m_decoder,
          ZYDIS_MACHINE_MODE_LONG_64,
          ZYDIS_STACK_WIDTH_64);
}

uintptr_t FunctionScanner::FindFunctionEnd(uintptr_t funcStart, bool stopAtFirstRet)
{
     // 优先用 .pdata 精确查询
     size_t pdataSize = m_pdata.GetFunctionSize(funcStart);
     if (pdataSize > 0) {
          return funcStart + pdataSize;
     }

     // 查不到，回退到启发式扫描
     return FindFunctionEndHeuristic(funcStart, stopAtFirstRet);
}

uintptr_t FunctionScanner::FindFunctionEndHeuristic(uintptr_t funcStart, bool stopAtFirstRet)
{
     if (!funcStart) return funcStart;

     // 用 VirtualQueryEx 拿到可执行区域的上界，作为扫描硬上限
     MEMORY_BASIC_INFORMATION mbi = {};
     if (!m_mem.Query(funcStart, &mbi)) {
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

     // 读取函数所在的内存到本地 buffer
     uint8_t* buffer = (uint8_t*)malloc(maxScan);
     if (!buffer) return funcStart + 1;

     m_mem.Read(funcStart, buffer, maxScan);

     // 工具函数：从某位置开始数连续的 padding（CC 或 90）
     auto countPadding = [&](size_t pos) -> size_t {
          size_t n = 0;
          while (pos + n < maxScan &&
               (buffer[pos + n] == 0xCC || buffer[pos + n] == 0x90)) {
               n++;
          }
          return n;
          };

     // 特殊优化：thunk 函数（入口就是 jmp，后面紧跟另一条 jmp 或 padding）
     // 这种函数本身只有一条跳板指令
     if (maxScan >= 8) {
          uint8_t b0 = buffer[0];

          // E9 rel32 形式的直接 jmp（5 字节）
          if (b0 == 0xE9) {
               uint8_t b5 = buffer[5];
               if (b5 == 0xE9 || b5 == 0xEB || b5 == 0xC3 || b5 == 0xFF ||
                    b5 == 0xCC || b5 == 0x90) {
                    free(buffer);
                    return funcStart + 5;
               }
          }

          // FF 25 disp32 形式的间接 jmp（6 字节）
          if (b0 == 0xFF && buffer[1] == 0x25) {
               uint8_t b6 = buffer[6];
               if (b6 == 0xE9 || b6 == 0xEB || b6 == 0xC3 || b6 == 0xFF ||
                    b6 == 0x48 || b6 == 0xCC || b6 == 0x90) {
                    free(buffer);
                    return funcStart + 6;
               }
          }

          // 48 FF 25 disp32 形式的间接 jmp（7 字节，带 REX 前缀）
          if (b0 == 0x48 && buffer[1] == 0xFF && buffer[2] == 0x25) {
               uint8_t b7 = buffer[7];
               if (b7 == 0xE9 || b7 == 0xEB || b7 == 0xC3 || b7 == 0xFF ||
                    b7 == 0x48 || b7 == 0xCC || b7 == 0x90) {
                    free(buffer);
                    return funcStart + 7;
               }
          }
     }

     // 普通函数：用 Zydis 逐条解码，找 ret + 至少 3 个 padding
     size_t lastRetEnd = 0;
     size_t offset = 0;

     ZydisDecodedInstruction insn;
     ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

     while (offset < maxScan) {
          ZyanStatus status = ZydisDecoderDecodeFull(
               &m_decoder, buffer + offset, maxScan - offset,
               &insn, operands);

          // 解码失败往后跳一字节继续
          if (!ZYAN_SUCCESS(status)) {
               offset += 1;
               continue;
          }

          if (insn.mnemonic == ZYDIS_MNEMONIC_RET) {
               size_t afterRet = offset + insn.length;
               lastRetEnd = afterRet;

               // 激进模式：第一个 ret 就停（用于减少依赖）
               if (stopAtFirstRet) {
                    free(buffer);
                    return funcStart + afterRet;
               }

               // 100% 确定边界：ret 后紧跟 ≥3 个 padding
               // 函数中间的 ret + 单个 CC 不会触发，避免误判 cold path
               if (countPadding(afterRet) >= MIN_PADDING_COUNT) {
                    free(buffer);
                    return funcStart + afterRet;
               }
          }

          offset += insn.length;
     }

     free(buffer);

     // 没找到 ret + padding 的明确边界
     // 用最后一个 ret + 16 字节缓冲（宁可多搬，不少拷）
     if (lastRetEnd > 0) {
          size_t end = lastRetEnd + 16;
          if (end > maxScan) end = maxScan;
          return funcStart + end;
     }

     // 极端情况：整段都没见到 ret，用扫描上限兜底
     return funcStart + maxScan;
}