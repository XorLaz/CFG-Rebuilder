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
     bool IsSharedWithLocal(uintptr_t addrInTarget) const;
     size_t GetModuleCount() const { return m_localModuleBases.size(); }

private:
     MemoryAccess& m_mem;
     std::vector<uintptr_t> m_localModuleBases;   // 改名为本地模块基址列表

};