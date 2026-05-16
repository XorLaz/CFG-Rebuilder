#pragma once
#include <cstdint>
#include <Zydis/Zydis.h>

class MemoryAccess;

class FunctionScanner {
public:
	explicit FunctionScanner(MemoryAccess& mem);

	uintptr_t FindFunctionEnd(uintptr_t funcStart);

	ZydisDecoder& GetDecoder() { return m_decoder; }

private:
	MemoryAccess& m_mem;
	ZydisDecoder m_decoder;
};