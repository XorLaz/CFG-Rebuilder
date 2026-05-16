#include "FunctionScanner.h"
#include "MemoryAccess.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace {
     constexpr size_t SCAN_BUF_SIZE = 65536;
     constexpr size_t MIN_FUNC_SIZE = 8;
}

FunctionScanner::FunctionScanner(MemoryAccess& mem)
     : m_mem(mem)
{
     ZydisDecoderInit(&m_decoder,
          ZYDIS_MACHINE_MODE_LONG_64,
          ZYDIS_STACK_WIDTH_64);
}

uintptr_t FunctionScanner::FindFunctionEnd(uintptr_t funcStart)
{
     if (!funcStart) return funcStart;

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

     uint8_t* buffer = (uint8_t*)malloc(maxScan);
     if (!buffer) return funcStart + 1;

     m_mem.Read(funcStart, buffer, maxScan);


     // 策略：
     //   100% 确定函数结束：ret 后紧跟 padding(CC/90) → 立即停
     //   不确定：记录最后一个 ret，扫完后用 ret + 16 字节缓冲


     size_t lastRetEnd = 0;
     size_t offset = 0;

     ZydisDecodedInstruction insn;
     ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

     while (offset < maxScan) {
          ZyanStatus status = ZydisDecoderDecodeFull(
               &m_decoder, buffer + offset, maxScan - offset,
               &insn, operands);

          if (!ZYAN_SUCCESS(status)) {
               offset += 1;
               continue;
          }

          if (insn.mnemonic == ZYDIS_MNEMONIC_RET) {
               size_t afterRet = offset + insn.length;
               lastRetEnd = afterRet;

               // 100% 确定边界：ret 后紧跟 padding
               if (afterRet < maxScan &&
                    (buffer[afterRet] == 0xCC || buffer[afterRet] == 0x90)) {
                    free(buffer);
                    return funcStart + afterRet;
               }
          }

          offset += insn.length;
     }

     free(buffer);

     // 没找到确定边界，用最后一个 ret + 16 字节缓冲
     if (lastRetEnd > 0) {
          size_t end = lastRetEnd + 16;
          if (end > maxScan) end = maxScan;
          return funcStart + end;
     }

     return funcStart + maxScan;
}