#include "MemoryAccess.h"
#include <cstdio>
#include <cstring>

#ifdef USE_DRIVER
#include "driver.h"
#endif

MemoryAccess::MemoryAccess(uint32_t targetPid, MemoryBackend backend)
     : m_pid(targetPid)
     , m_backend(backend)
     , m_hProcess(nullptr)
{
     if (m_backend == MemoryBackend::API) {
          m_hProcess = OpenProcess(
               PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
               FALSE, m_pid);
          if (!m_hProcess) {
               printf("[!] API: OpenProcess failed for pid %u (error=%lu)\n",
                    m_pid, GetLastError());
          }
     }
#ifdef USE_DRIVER
     else {
          if (!drv.proceint(m_pid)) {
               printf("[!] Driver: failed to set target process %u\n", m_pid);
          }
     }
#endif
}

MemoryAccess::~MemoryAccess()
{
     if (m_hProcess) {
          CloseHandle(m_hProcess);
          m_hProcess = nullptr;
     }
}

bool MemoryAccess::Read(uintptr_t addr, void* buffer, size_t size)
{
     if (addr == 0 || buffer == nullptr || size == 0) return false;

     if (m_backend == MemoryBackend::API) {
          SIZE_T bytesRead = 0;
          BOOL ok = ::ReadProcessMemory(m_hProcess, (LPCVOID)addr, buffer, size, &bytesRead);
          return ok && bytesRead == size;
     }

#ifdef USE_DRIVER
     uint64_t bytesRead = 0;
     BOOL ok = drv.ReadProcessMemory(
          (ptr)addr,
          (ptr)buffer,
          size,
          0,
          &bytesRead
     );
     return ok && bytesRead == size;
#else
     return false;
#endif
}

bool MemoryAccess::Query(uintptr_t addr, MEMORY_BASIC_INFORMATION* mbi)
{
     if (!mbi) return false;
     memset(mbi, 0, sizeof(*mbi));

     if (m_backend == MemoryBackend::API) {
          SIZE_T result = VirtualQueryEx(m_hProcess, (LPCVOID)addr, mbi, sizeof(*mbi));
          return result != 0;
     }

#ifdef USE_DRIVER
     drv.QueryVirtualMemory(m_pid, (ptr)addr, mbi);
     return mbi->BaseAddress != nullptr || mbi->RegionSize != 0;
#else
     return false;
#endif
}
