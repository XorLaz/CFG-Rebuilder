#include "ModuleResolver.h"
#include "MemoryAccess.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <cstdio>

#pragma comment(lib, "Psapi.lib")

ModuleResolver::ModuleResolver(MemoryAccess& mem)
     : m_mem(mem)
{}

bool ModuleResolver::LoadModules()
{
     // 加载本地进程的所有模块基址
     // 系统 DLL（ntdll/kernel32 等）在所有进程的基址相同，
     // 所以本地基址列表可以用来判断目标进程里的某个地址是不是共享模块
     HMODULE modules[1024];
     DWORD needed = 0;
     if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
          printf("[!] EnumProcessModules failed: %lu\n", GetLastError());
          return false;
     }

     size_t count = needed / sizeof(HMODULE);
     m_localModuleBases.reserve(count);
     for (size_t i = 0; i < count; i++) {
          m_localModuleBases.push_back((uintptr_t)modules[i]);
     }

     printf("[+] Loaded %zu local module bases\n", count);
     return true;
}


bool ModuleResolver::IsSharedWithLocal(uintptr_t addrInTarget) const
{
     if (addrInTarget == 0) return false;

     // 用 VirtualQuery 拿目标地址所属模块的基址
     MEMORY_BASIC_INFORMATION mbi = {};
     if (!m_mem.Query(addrInTarget, &mbi)) return false;

     uintptr_t targetBase = (uintptr_t)mbi.AllocationBase;
     if (targetBase == 0) return false;

     // 在本地模块基址列表里查，找到就是共享模块
     for (uintptr_t localBase : m_localModuleBases) {
          if (localBase == targetBase) {
               return true;
          }
     }

     return false;
}