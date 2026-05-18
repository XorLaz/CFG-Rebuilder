#pragma once
#include <cstdint>
#include <queue>
#include <unordered_map>
#include <memory>

#include "MemoryAccess.h"
#include "ModuleResolver.h"
#include "PdataResolver.h"
#include "ArenaAllocator.h"
#include "FunctionScanner.h"
#include "Fixer.h"

// 已搬运函数的元数据
struct LiftedFunction {
     void* localAddress;
     size_t size;
     void* trampolineArea;       // 紧挨着函数末尾的 trampoline 区
     size_t trampolineUsed;       // 已用 trampoline 字节
     size_t trampolineCapacity;   // 总容量
};

// CodeLifter 主类，协调各组件完成搬运 + 修复
class CodeLifter {
public:
     explicit CodeLifter(uint32_t targetPid);
     ~CodeLifter();

     CodeLifter(const CodeLifter&) = delete;
     CodeLifter& operator=(const CodeLifter&) = delete;

     // 主入口
     // hintSize > 0 时跳过自动识别，用指定大小搬运入口函数
     // stopAtFirstRet 用于启发式扫描的激进模式
     bool CollectFunction(uintptr_t targetFuncAddr,
          size_t hintSize = 0,
          bool stopAtFirstRet = false);

     void DumpResult() const;
     void SyncMirrors();
     void SyncIndirectSlots();
     void* GetLocalFunction(uintptr_t origAddr) const;

public:
     // 工作队列项
     struct WorkItem {
          uintptr_t addr;
          int       depth;
     };

     MemoryAccess    m_mem;
     ModuleResolver  m_resolver;
     PdataResolver   m_pdata;
     ArenaAllocator  m_arena;
     FunctionScanner m_scanner;
     std::unique_ptr<Fixer> m_fixer;

     std::unordered_map<uintptr_t, LiftedFunction> m_liftedFunctions;
     std::unordered_map<uintptr_t, void*> m_mirrorVariables;
     std::unordered_map<uintptr_t, void*> m_indirectCallSlots;

     std::queue<WorkItem> m_workQueue;
     std::unordered_map<uintptr_t, bool> m_enqueuedAddresses;

     bool m_stopAtFirstRet = false;

private:
     void ProcessWorkQueue();
     void CollectOne(uintptr_t addr, int depth);
     void CollectOneWithSize(uintptr_t addr, size_t funcSize, int depth);
     void ScanInstructions(uintptr_t origAddr, void* localCode,
          size_t funcSize, int depth);
     void EnsureMirrorVariable(uintptr_t targetAddr, size_t accessSize);
     void EnsureIndirectCallSlot(uintptr_t targetPtrAddr, int depth);
     void HandleControlFlowTarget(uintptr_t target, uintptr_t funcStart,
          size_t funcSize, int depth);
     void EnqueueIfNeeded(uintptr_t addr, int depth);
};