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

// �Ѱ��˺�����Ԫ����
struct LiftedFunction {
     void* localAddress;
     size_t size;
     void* trampolineArea;       // �����ź���ĩβ�� trampoline ��
     size_t trampolineUsed;       // ���� trampoline �ֽ�
     size_t trampolineCapacity;   // ������
};

// CodeLifter ���࣬Э���������ɰ��� + �޸�
class CodeLifter {
public:
     explicit CodeLifter(uint32_t targetPid, MemoryBackend backend = MemoryBackend::API);
     ~CodeLifter();

     CodeLifter(const CodeLifter&) = delete;
     CodeLifter& operator=(const CodeLifter&) = delete;

     // �����
     // hintSize > 0 ʱ�����Զ�ʶ����ָ����С������ں���
     // stopAtFirstRet ��������ʽɨ��ļ���ģʽ
     bool CollectFunction(uintptr_t targetFuncAddr,
          size_t hintSize = 0,
          bool stopAtFirstRet = false);

     void DumpResult() const;
     void SyncMirrors();
     void SyncIndirectSlots();
     void* GetLocalFunction(uintptr_t origAddr) const;

public:
     // ����������
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