#include "MemoryAccess.h"
#include <cstdio>
#include <cstring>

MemoryAccess::MemoryAccess(uint32_t targetPid)
     : m_pid(targetPid)
{
     if (!drv.proceint(m_pid)) {
          printf("[!] Driver: failed to set target process %u\n", m_pid);
     }
}

bool MemoryAccess::Read(uintptr_t addr, void* buffer, size_t size)
{
     if (addr == 0 || buffer == nullptr || size == 0) return false;

     uint64_t bytesRead = 0;
     BOOL ok = drv.ReadProcessMemory(
          (ptr)addr,
          (ptr)buffer,
          size,
          0,
          &bytesRead
     );
     return ok && bytesRead == size;
}

bool MemoryAccess::Query(uintptr_t addr, MEMORY_BASIC_INFORMATION* mbi)
{
     if (!mbi) return false;
     memset(mbi, 0, sizeof(*mbi));

     drv.QueryVirtualMemory(m_pid, (ptr)addr, mbi);

     return mbi->BaseAddress != nullptr || mbi->RegionSize != 0;
}