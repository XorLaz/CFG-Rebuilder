#pragma once
#include <cstdint>
#include <vector>
#include <unordered_map>

class MemoryAccess;

// 通过解析目标进程 PE 文件的 .pdata 段，提供精确的函数大小查询
// .pdata 是 Windows x64 PE 文件里存储函数边界信息的段，编译器自动生成
// 不依赖模块枚举，直接从地址定位所属模块
class PdataResolver {
public:
     explicit PdataResolver(MemoryAccess& mem);

     // 查询某个地址所在函数的精确大小
     // 返回 0 表示该地址没有 .pdata 记录（少见，比如手写汇编或被擦除）
     size_t GetFunctionSize(uintptr_t addr);

private:
     // x64 PE 文件里 .pdata 段的每个条目结构
     struct RuntimeFunction {
          uint32_t beginRVA;
          uint32_t endRVA;
          uint32_t unwindInfoRVA;
     };

     // 单个模块的 .pdata 缓存
     struct ModulePdata {
          std::vector<RuntimeFunction> entries;
     };

     // 加载某个模块的 .pdata 表到本地内存（带缓存）
     const ModulePdata* GetOrLoadPdata(uintptr_t moduleBase);

     // 从目标进程读取 PE 头，提取 .pdata 段内容
     bool LoadPdataFromTarget(uintptr_t moduleBase, ModulePdata& outPdata);

     MemoryAccess& m_mem;

     // 缓存：模块基址 -> 该模块的 .pdata 表
     std::unordered_map<uintptr_t, ModulePdata> m_cache;
};