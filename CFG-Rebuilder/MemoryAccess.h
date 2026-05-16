#pragma once
#include <Windows.h>
#include <cstdint>
#include "driver.h"

class MemoryAccess {
public:
	explicit MemoryAccess(uint32_t targetPid);

	bool Read(uintptr_t addr, void* buffer, size_t size);
	bool Query(uintptr_t addr, MEMORY_BASIC_INFORMATION* mbi);

	uint32_t GetPid() const { return m_pid; }

private:
	uint32_t m_pid;
};