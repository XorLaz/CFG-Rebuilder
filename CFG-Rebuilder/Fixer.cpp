#include "Fixer.h"
#include "MemoryAccess.h"
#include "ModuleResolver.h"
#include "CodeLifter.h"
#include <cstdio>
#include <cstring>

Fixer::Fixer(MemoryAccess& mem,
     ModuleResolver& resolver,
     std::unordered_map<uintptr_t, LiftedFunction>& liftedFunctions,
     std::unordered_map<uintptr_t, void*>& mirrorVariables,
     std::unordered_map<uintptr_t, void*>& indirectCallSlots,
     ZydisDecoder& decoder)
     : m_mem(mem)
     , m_resolver(resolver)
     , m_liftedFunctions(liftedFunctions)
     , m_mirrorVariables(mirrorVariables)
     , m_indirectCallSlots(indirectCallSlots)
     , m_decoder(decoder)
{}

void Fixer::FixupAll(uint8_t* arenaBase, size_t arenaUsed)
{

     size_t filledSlots = 0;
     for (auto& kv : m_indirectCallSlots) {
          FillIndirectSlot(kv.first, kv.second);
          filledSlots++;
     }
     printf("[+] Filled %zu indirect call slots\n", filledSlots);

     size_t fixedFuncs = 0;
     for (auto& kv : m_liftedFunctions) {
          FixupOneFunction(kv.first, kv.second);
          fixedFuncs++;
          if (fixedFuncs % 100 == 0) {
               printf("[*] Fixed %zu functions\n", fixedFuncs);
          }
     }
     printf("[+] Total fixed: %zu functions\n", fixedFuncs);

     PatchMirrorPointers();

     FlushInstructionCache(GetCurrentProcess(), arenaBase, arenaUsed);

}
uintptr_t Fixer::ResolveTarget(uintptr_t origAddr)
{
     auto it1 = m_liftedFunctions.find(origAddr);
     if (it1 != m_liftedFunctions.end()) {
          return (uintptr_t)it1->second.localAddress;
     }

     auto it2 = m_mirrorVariables.find(origAddr);
     if (it2 != m_mirrorVariables.end()) {
          return (uintptr_t)it2->second;
     }

     auto it3 = m_indirectCallSlots.find(origAddr);
     if (it3 != m_indirectCallSlots.end()) {
          return (uintptr_t)it3->second;
     }

     if (m_resolver.IsSharedWithLocal(origAddr)) {
          return origAddr;
     }

     return 0;
}

void Fixer::FillIndirectSlot(uintptr_t origPtrAddr, void* localSlot)
{
     uintptr_t origFuncAddr = 0;
     m_mem.Read(origPtrAddr, &origFuncAddr, sizeof(uintptr_t));

     if (origFuncAddr == 0) {
          *(uintptr_t*)localSlot = 0;
          return;
     }

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

void Fixer::FixupOneFunction(uintptr_t origAddr, LiftedFunction& fn)
{
     uint8_t* code = (uint8_t*)fn.localAddress;
     size_t offset = 0;

     ZydisDecodedInstruction insn;
     ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

     while (offset < fn.size) {
          ZyanStatus status = ZydisDecoderDecodeFull(
               &m_decoder, code + offset, fn.size - offset,
               &insn, operands);

          if (!ZYAN_SUCCESS(status)) {
               offset += 1;
               continue;
          }

          uintptr_t localNextRip = (uintptr_t)(code + offset + insn.length);
          uintptr_t origNextRip = origAddr + offset + insn.length;

          //RIP 相对内存访问
          bool hasRipMemOperand = false;
          for (int i = 0; i < insn.operand_count_visible; i++) {
               const auto& op = operands[i];
               if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    op.mem.base == ZYDIS_REGISTER_RIP) {
                    hasRipMemOperand = true;
                    break;
               }
          }

          if (hasRipMemOperand && insn.raw.disp.size == 32) {
               for (int i = 0; i < insn.operand_count_visible; i++) {
                    const auto& op = operands[i];
                    if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
                    if (op.mem.base != ZYDIS_REGISTER_RIP) continue;

                    uintptr_t origTarget = origNextRip + op.mem.disp.value;
                    uintptr_t localTarget = ResolveTarget(origTarget);

                    if (localTarget == 0) {
                         printf("[!] Unresolved RIP target 0x%llx in func 0x%llx+0x%zx\n",
                              (unsigned long long)origTarget,
                              (unsigned long long)origAddr, offset);
                         break;
                    }

                    int64_t diff = (int64_t)localTarget - (int64_t)localNextRip;
                    if (diff < INT32_MIN || diff > INT32_MAX) {
                         printf("[!] RIP target out of 2GB range\n");
                         break;
                    }

                    int32_t newDisp = (int32_t)diff;
                    memcpy(code + offset + insn.raw.disp.offset, &newDisp, 4);
                    break;
               }
          }

          // rel8/rel32 直接控制流
          bool isControlFlow =
               (insn.mnemonic == ZYDIS_MNEMONIC_CALL) ||
               (insn.mnemonic == ZYDIS_MNEMONIC_JMP) ||
               (insn.mnemonic >= ZYDIS_MNEMONIC_JB &&
                    insn.mnemonic <= ZYDIS_MNEMONIC_JZ);

          if (isControlFlow) {
               for (int i = 0; i < insn.operand_count_visible; i++) {
                    const auto& op = operands[i];
                    if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;
                    if (!op.imm.is_relative) continue;
                    if (insn.raw.imm[0].size == 0) continue;

                    uintptr_t origTarget = op.imm.is_signed
                         ? origNextRip + op.imm.value.s
                         : origNextRip + op.imm.value.u;

                    if (origTarget >= origAddr && origTarget < origAddr + fn.size) {
                         break;
                    }

                    uintptr_t localTarget = ResolveTarget(origTarget);
                    if (localTarget == 0) {
                         printf("[!] Unresolved branch target 0x%llx\n",
                              (unsigned long long)origTarget);
                         break;
                    }

                    int64_t diff = (int64_t)localTarget - (int64_t)localNextRip;
                    size_t immOffset = insn.raw.imm[0].offset;
                    size_t immSize = insn.raw.imm[0].size / 8;

                    if (immSize == 1) {
                         if (diff < -128 || diff > 127) {
                              // rel8 装不下，在 trampoline 区写一条 jmp rel32 中转
                              if (fn.trampolineUsed + 5 > fn.trampolineCapacity) {
                                   printf("[!] Trampoline exhausted at func 0x%llx+0x%zx\n",
                                        (unsigned long long)origAddr, offset);
                                   break;
                              }

                              uint8_t* tramp = (uint8_t*)fn.trampolineArea + fn.trampolineUsed;
                              uintptr_t trampAddr = (uintptr_t)tramp;

                              // trampoline: E9 rel32 跳到真实目标
                              int64_t trampDiff = (int64_t)localTarget - (int64_t)(trampAddr + 5);
                              if (trampDiff < INT32_MIN || trampDiff > INT32_MAX) {
                                   printf("[!] Trampoline target out of rel32 range\n");
                                   break;
                              }

                              tramp[0] = 0xE9;
                              int32_t trampRel32 = (int32_t)trampDiff;
                              memcpy(tramp + 1, &trampRel32, 4);

                              fn.trampolineUsed += 5;

                              // 把原 jcc 改成跳向 trampoline
                              int64_t newDiff = (int64_t)trampAddr - (int64_t)localNextRip;
                              if (newDiff < -128 || newDiff > 127) {
                                   printf("[!] Even trampoline out of rel8 range at func 0x%llx+0x%zx, "
                                        "newDiff=%lld\n",
                                        (unsigned long long)origAddr, offset, (long long)newDiff);
                                   break;
                              }

                              code[offset + immOffset] = (uint8_t)(int8_t)newDiff;

                              printf("[+] Inserted trampoline at %p for jcc at 0x%llx+0x%zx -> 0x%llx\n",
                                   tramp, (unsigned long long)origAddr, offset,
                                   (unsigned long long)localTarget);
                         }
                         else {
                              code[offset + immOffset] = (uint8_t)(int8_t)diff;
                         }
                    }
                    else if (immSize == 4) {
                         if (diff < INT32_MIN || diff > INT32_MAX) {
                              printf("[!] rel32 out of range\n");
                              break;
                         }
                         int32_t newRel = (int32_t)diff;
                         memcpy(code + offset + immOffset, &newRel, 4);
                    }
                    break;
               }
          }

          // ret 后停止扫描
          if (insn.mnemonic == ZYDIS_MNEMONIC_RET) {
               break;
          }

          offset += insn.length;
     }
}

void Fixer::PatchMirrorPointers()
{
     printf("\n[*] Patching function pointers in mirror variables...\n");

     constexpr size_t SCAN_SIZE = 32;
     size_t patched = 0;

     for (auto& kv : m_mirrorVariables) {
          uintptr_t origAddr = kv.first;
          uint8_t* mirror = (uint8_t*)kv.second;

          for (size_t off = 0; off + 8 <= SCAN_SIZE; off += 8) {
               uintptr_t value = 0;
               memcpy(&value, mirror + off, 8);

               if (value == 0) continue;

               auto it = m_liftedFunctions.find(value);
               if (it != m_liftedFunctions.end()) {
                    uintptr_t localAddr = (uintptr_t)it->second.localAddress;
                    memcpy(mirror + off, &localAddr, 8);

                    printf("[+] Patched mirror at 0x%llx+0x%zx: 0x%llx -> 0x%llx\n",
                         (unsigned long long)origAddr, off,
                         (unsigned long long)value,
                         (unsigned long long)localAddr);
                    patched++;
               }
          }
     }

     printf("[+] Patched %zu function pointers in mirrors\n", patched);
}