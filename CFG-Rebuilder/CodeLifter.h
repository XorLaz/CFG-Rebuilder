#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <cstdint>
#include <string>
#include <vector>
#include <queue>
#include <unordered_map>
#include <Zydis/Zydis.h>

class CodeLifter {
public:
     explicit CodeLifter(HANDLE hTargetProcess);
     ~CodeLifter();

     CodeLifter(const CodeLifter&) = delete;
     CodeLifter& operator=(const CodeLifter&) = delete;

     // 阶段 1 主入口
     bool CollectFunction(uintptr_t targetFuncAddr);

     // 打印结果
     void DumpResult() const;

public:
     HANDLE m_hTargetProcess;

     // 本地代码区
     uint8_t* m_codeArenaBase;
     size_t   m_codeArenaCapacity;
     size_t   m_codeArenaUsed;
     size_t   m_codeArenaCommitted;

     // 已搬函数
     struct LiftedFunction {
          void* localAddress;
          size_t size;
     };
     std::unordered_map<uintptr_t, LiftedFunction> m_liftedFunctions;

     // 镜像变量 / 间接调用槽
     std::unordered_map<uintptr_t, void*> m_mirrorVariables;
     std::unordered_map<uintptr_t, void*> m_indirectCallSlots;

     // 目标进程模块列表
     struct TargetModule {
          std::string name;
          uintptr_t   base;
          size_t      size;
     };
     std::vector<TargetModule> m_targetModules;

     // 工作队列：保存待处理的函数地址
     struct WorkItem {
          uintptr_t addr;
          int       depth;
     };
     std::queue<WorkItem> m_workQueue;

     // 已入队的地址集合（防止重复入队）
     std::unordered_map<uintptr_t, bool> m_enqueuedAddresses;

     // Zydis 解码器
     ZydisDecoder m_decoder;

private:
     bool      LoadTargetModules();
     const TargetModule* FindTargetModule(uintptr_t addr) const;
     bool      IsAddressSharedWithLocal(uintptr_t addrInTarget);
     bool      IsExecutableInTarget(uintptr_t addr);

     void      ProcessWorkQueue();
     void      CollectOne(uintptr_t addr, int depth);
     uintptr_t FindFunctionEnd(uintptr_t funcStart);
     void      ScanInstructions(uintptr_t origAddr, void* localCode,
          size_t funcSize, int depth);
     void* AllocateInArena(size_t size);
     void      EnsureMirrorVariable(uintptr_t targetAddr, size_t accessSize);
     void      EnsureIndirectCallSlot(uintptr_t targetPtrAddr, int depth);
     void      HandleControlFlowTarget(uintptr_t target, uintptr_t funcStart,
          size_t funcSize, int depth);
     void      EnqueueIfNeeded(uintptr_t addr, int depth);


     // 阶段 2 接口
     void      FixupAll();
     void      FixupOneFunction(uintptr_t origAddr, const LiftedFunction& fn);
     uintptr_t ResolveTarget(uintptr_t origAddr);
     void      FillIndirectSlot(uintptr_t origPtrAddr, void* localSlot);
};