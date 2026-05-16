#include "ModuleResolver.h"
#include "MemoryAccess.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <cstdio>

#pragma comment(lib, "Psapi.lib")

namespace {
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
         "ucrtbase.dll",
         "vcruntime140.dll",
         "msvcp140.dll",
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

ModuleResolver::ModuleResolver(MemoryAccess& mem)
     : m_mem(mem)
{}

bool ModuleResolver::LoadModules()
{
     HANDLE hSnap = CreateToolhelp32Snapshot(
          TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_mem.GetPid());

     if (hSnap == INVALID_HANDLE_VALUE) {
          printf("[!] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
          return false;
     }

     MODULEENTRY32W me = { sizeof(me) };
     if (Module32FirstW(hSnap, &me)) {
          do {
               char buf[MAX_PATH] = { 0 };
               WideCharToMultiByte(CP_ACP, 0, me.szModule, -1,
                    buf, MAX_PATH, nullptr, nullptr);
               Module m;
               m.name = ToLowerString(buf);
               m.base = (uintptr_t)me.modBaseAddr;
               m.size = me.modBaseSize;
               m_modules.push_back(m);
          } while (Module32NextW(hSnap, &me));
     }

     CloseHandle(hSnap);
     return !m_modules.empty();
}

const ModuleResolver::Module* ModuleResolver::FindModule(uintptr_t addr) const
{
     for (auto& m : m_modules) {
          if (addr >= m.base && addr < m.base + m.size) {
               return &m;
          }
     }
     return nullptr;
}

bool ModuleResolver::IsSharedWithLocal(uintptr_t addrInTarget) const
{
     if (addrInTarget == 0) return false;

     const Module* mod = FindModule(addrInTarget);
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