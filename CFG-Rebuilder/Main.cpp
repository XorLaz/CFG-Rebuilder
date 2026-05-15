// main.cpp
#include "CodeLifter.h"
#include <cstdio>


int main() {
     DWORD pid = 0x5070;
     HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
          FALSE, pid);
     if (!h) {
          printf("OpenProcess failed: %lu\n", GetLastError());
          return 1;
     }

     CodeLifter lifter(h);

     uintptr_t sub_EE1_addr = 0x7FF625041BF0;

     if (lifter.CollectFunction(sub_EE1_addr)) {
          lifter.DumpResult();
     }

     CloseHandle(h);

     system("pause");
     return 0;
}