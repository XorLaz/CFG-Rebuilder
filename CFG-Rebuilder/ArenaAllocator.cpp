#include "ArenaAllocator.h"
#include <algorithm>
#include <cstdio>

ArenaAllocator::ArenaAllocator(size_t reserveSize, size_t commitChunkSize)
     : m_base(nullptr)
     , m_capacity(reserveSize)
     , m_used(0)
     , m_committed(0)
     , m_commitChunkSize(commitChunkSize)
{
     m_base = (uint8_t*)VirtualAlloc(
          nullptr, reserveSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
     if (!m_base) {
          printf("[!] Failed to reserve arena: %lu\n", GetLastError());
          return;
     }

     if (!VirtualAlloc(m_base, commitChunkSize,
          MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
          printf("[!] Failed to commit initial chunk: %lu\n", GetLastError());
          return;
     }
     m_committed = commitChunkSize;

     printf("[+] Arena: reserved %zu MB, committed %zu MB\n",
          m_capacity / (1024 * 1024),
          m_committed / (1024 * 1024));
}

ArenaAllocator::~ArenaAllocator()
{
     if (m_base) {
          VirtualFree(m_base, 0, MEM_RELEASE);
     }
}

void* ArenaAllocator::Allocate(size_t size)
{
     size_t aligned = (size + 15) & ~size_t(15);

     if (m_used + aligned > m_capacity) {
          printf("[!] Arena exhausted (%zu MB limit)\n",
               m_capacity / (1024 * 1024));
          return nullptr;
     }

     while (m_used + aligned > m_committed) {
          size_t commitTo = std::min<size_t>(
               m_committed + m_commitChunkSize, m_capacity);
          size_t toCommit = commitTo - m_committed;

          if (!VirtualAlloc(m_base + m_committed, toCommit,
               MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
               printf("[!] Failed to commit more memory: %lu\n", GetLastError());
               return nullptr;
          }
          m_committed = commitTo;
          printf("[+] Committed more, total %zu MB\n",
               m_committed / (1024 * 1024));
     }

     void* result = m_base + m_used;
     m_used += aligned;
     return result;
}