#pragma once
#include <cstdint>
#include <Zydis/Zydis.h>

class MemoryAccess;
class PdataResolver;

// 函数边界识别器
// 优先用 .pdata（精确），查不到再用启发式扫描（兜底）
class FunctionScanner {
public:
	FunctionScanner(MemoryAccess& mem, PdataResolver& pdataResolver);

	// 找函数末尾地址
	// stopAtFirstRet 仅在启发式扫描时生效，遇到第一个 ret 就停
	uintptr_t FindFunctionEnd(uintptr_t funcStart, bool stopAtFirstRet = false);

	ZydisDecoder& GetDecoder() { return m_decoder; }

private:
	// 启发式扫描（没有 .pdata 时的备用方案）
	uintptr_t FindFunctionEndHeuristic(uintptr_t funcStart, bool stopAtFirstRet);

	MemoryAccess& m_mem;
	PdataResolver& m_pdata;
	ZydisDecoder   m_decoder;
};