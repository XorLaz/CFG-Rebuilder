#pragma once
#include <Windows.h>
#include <cstdint>

enum class MemoryBackend {
     API,
     Driver
};

class MemoryAccess {
public:
     explicit MemoryAccess(uint32_t targetPid, MemoryBackend backend = MemoryBackend::API);
     ~MemoryAccess();

     MemoryAccess(const MemoryAccess&) = delete;
     MemoryAccess& operator=(const MemoryAccess&) = delete;

     bool Read(uintptr_t addr, void* buffer, size_t size);
     bool Query(uintptr_t addr, MEMORY_BASIC_INFORMATION* mbi);

     uint32_t GetPid() const { return m_pid; }
     MemoryBackend GetBackend() const { return m_backend; }

private:
     uint32_t m_pid;
     MemoryBackend m_backend;
     HANDLE m_hProcess;
};
