#include "PdataResolver.h"
#include "MemoryAccess.h"
#include <Windows.h>
#include <cstdio>

PdataResolver::PdataResolver(MemoryAccess& mem)
     : m_mem(mem)
{}

size_t PdataResolver::GetFunctionSize(uintptr_t addr)
{
     if (addr == 0) return 0;

     // 用 VirtualQuery 拿到这个地址所在虚拟内存区域的分配基址
     // 对于 PE 模块来说，AllocationBase 就是模块基址
     MEMORY_BASIC_INFORMATION mbi = {};
     if (!m_mem.Query(addr, &mbi)) return 0;

     uintptr_t moduleBase = (uintptr_t)mbi.AllocationBase;
     if (moduleBase == 0) return 0;

     // 拿到（或加载）这个模块的 .pdata 表
     const ModulePdata* pdata = GetOrLoadPdata(moduleBase);
     if (!pdata || pdata->entries.empty()) return 0;

     // 计算目标 RVA
     uint32_t targetRVA = (uint32_t)(addr - moduleBase);

     // 二分查找：找到 beginRVA <= targetRVA < endRVA 的条目
     // .pdata 表本身按 beginRVA 升序排列
     const auto& entries = pdata->entries;
     size_t lo = 0, hi = entries.size();

     while (lo < hi) {
          size_t mid = lo + (hi - lo) / 2;
          const auto& e = entries[mid];

          if (e.beginRVA <= targetRVA) {
               // 在区间内，找到了
               if (targetRVA < e.endRVA) {
                    return e.endRVA - e.beginRVA;
               }
               // 中点的函数在 targetRVA 左边，往右找
               lo = mid + 1;
          }
          else {
               // 中点的函数在 targetRVA 右边，往左找
               hi = mid;
          }
     }

     // 没找到对应记录（地址不在任何函数范围内）
     return 0;
}

const PdataResolver::ModulePdata* PdataResolver::GetOrLoadPdata(uintptr_t moduleBase)
{
     // 缓存命中直接返回
     auto it = m_cache.find(moduleBase);
     if (it != m_cache.end()) {
          return &it->second;
     }

     // 加载新模块的 .pdata
     ModulePdata pdata;
     LoadPdataFromTarget(moduleBase, pdata);

     // 无论是否加载成功都缓存，避免反复尝试
     auto result = m_cache.insert({ moduleBase, std::move(pdata) });
     return &result.first->second;
}

bool PdataResolver::LoadPdataFromTarget(uintptr_t moduleBase, ModulePdata& outPdata)
{
     // 读 DOS 头，验证 MZ 签名
     IMAGE_DOS_HEADER dosHeader = {};
     if (!m_mem.Read(moduleBase, &dosHeader, sizeof(dosHeader))) {
          return false;
     }
     if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
          return false;
     }

     // 读 NT 头，验证 PE 签名
     IMAGE_NT_HEADERS64 ntHeaders = {};
     if (!m_mem.Read(moduleBase + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders))) {
          return false;
     }
     if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
          return false;
     }
     if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
          return false;
     }

     // 取异常表的位置（数据目录的第 3 项就是 .pdata）
     const auto& exDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
     if (exDir.VirtualAddress == 0 || exDir.Size == 0) {
          printf("[!] PdataResolver: module 0x%llx has no .pdata\n",
               (unsigned long long)moduleBase);
          return false;
     }

     // 计算条目数，一次性把整个表读到本地内存
     size_t count = exDir.Size / sizeof(RuntimeFunction);
     if (count == 0) return false;

     outPdata.entries.resize(count);
     if (!m_mem.Read(moduleBase + exDir.VirtualAddress,
          outPdata.entries.data(),
          count * sizeof(RuntimeFunction))) {
          outPdata.entries.clear();
          return false;
     }

     printf("[+] PdataResolver: loaded %zu entries from module 0x%llx\n",
          count, (unsigned long long)moduleBase);
     return true;
}