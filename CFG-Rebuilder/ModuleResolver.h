#pragma once
#include <cstdint>
#include <string>
#include <vector>

class MemoryAccess;

class ModuleResolver {
public:
     struct Module {
          std::string name;
          uintptr_t   base;
          size_t      size;
     };

     explicit ModuleResolver(MemoryAccess& mem);

     bool LoadModules();
     const Module* FindModule(uintptr_t addr) const;
     bool IsSharedWithLocal(uintptr_t addrInTarget) const;
     size_t GetModuleCount() const { return m_modules.size(); }

private:
     MemoryAccess& m_mem;
     std::vector<Module> m_modules;
};