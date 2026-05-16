#pragma once
#include <cstdint>
#include <unordered_map>
#include <Zydis/Zydis.h>

class MemoryAccess;
class ModuleResolver;
struct LiftedFunction;

class Fixer {
public:
     Fixer(MemoryAccess& mem,
          ModuleResolver& resolver,
          std::unordered_map<uintptr_t, struct LiftedFunction>& liftedFunctions,
          std::unordered_map<uintptr_t, void*>& mirrorVariables,
          std::unordered_map<uintptr_t, void*>& indirectCallSlots,
          ZydisDecoder& decoder);

     void FixupAll(uint8_t* arenaBase, size_t arenaUsed);
     void FillIndirectSlot(uintptr_t origPtrAddr, void* localSlot);

private:
     void      FixupOneFunction(uintptr_t origAddr, const LiftedFunction& fn);
     uintptr_t ResolveTarget(uintptr_t origAddr);

     MemoryAccess& m_mem;
     ModuleResolver& m_resolver;
     std::unordered_map<uintptr_t, LiftedFunction>& m_liftedFunctions;
     std::unordered_map<uintptr_t, void*>& m_mirrorVariables;
     std::unordered_map<uintptr_t, void*>& m_indirectCallSlots;
     ZydisDecoder& m_decoder;
};