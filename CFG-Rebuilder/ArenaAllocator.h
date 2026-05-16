#pragma once
#include <Windows.h>
#include <cstdint>


// 本地代码区分配器 reserve 1GB 地址空间，按需 commit 物理内存
class ArenaAllocator {
public:
	ArenaAllocator(size_t reserveSize, size_t commitChunkSize);
	~ArenaAllocator();

	ArenaAllocator(const ArenaAllocator&) = delete;
	ArenaAllocator& operator=(const ArenaAllocator&) = delete;

	// 分配可执行内存
	void* Allocate(size_t size);

	uint8_t* GetBase() const { return m_base; }
	size_t   GetUsed() const { return m_used; }
	size_t   GetCommitted() const { return m_committed; }
	size_t   GetCapacity() const { return m_capacity; }

private:
	uint8_t* m_base;
	size_t   m_capacity;        // reserve 总大小
	size_t   m_used;             // 已分配字节
	size_t   m_committed;        // 已 commit 字节
	size_t   m_commitChunkSize;  // 每次 commit 多少
};