// CodeLifter.h
#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <cstdint>
#include <string>
#include <vector>
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

     // 已搬函数 / 镜像变量 / 间接调用槽
     std::unordered_map<uintptr_t, void*>  m_liftedFunctions;
     std::unordered_map<uintptr_t, size_t> m_functionSizes;
     std::unordered_map<uintptr_t, void*>  m_mirrorVariables;
     std::unordered_map<uintptr_t, void*>  m_indirectCallSlots;

     // 目标进程模块列表
     struct TargetModule {
          std::string name;       // 小写化的模块文件名
          uintptr_t   base;
          size_t      size;
     };
     std::vector<TargetModule> m_targetModules;

     // Zydis 解码器
     ZydisDecoder m_decoder;

private:
     bool      LoadTargetModules();
     const TargetModule* FindTargetModule(uintptr_t addr) const;
     bool      IsAddressSharedWithLocal(uintptr_t addrInTarget);
     bool      IsExecutableInTarget(uintptr_t addr);

     void      CollectRecursive(uintptr_t addr, int depth);
     uintptr_t FindFunctionEnd(uintptr_t funcStart);
     void      ScanInstructions(uintptr_t origAddr, void* localCode,
          size_t funcSize, int depth);
     void* AllocateInArena(size_t size);
     void      EnsureMirrorVariable(uintptr_t targetAddr, size_t accessSize);
     void      EnsureIndirectCallSlot(uintptr_t targetPtrAddr, int depth);
     void      HandleControlFlowTarget(uintptr_t target, uintptr_t funcStart,
          size_t funcSize, int depth);
};