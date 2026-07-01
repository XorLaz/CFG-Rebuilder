#include "CodeLifter.h"
#include <cstdio>
#include <cstring>

#ifdef USE_DRIVER
#include "driver.h"
#endif

int main(int argc, char* argv[])
{
     MemoryBackend backend = MemoryBackend::API;

#ifdef USE_DRIVER
     for (int i = 1; i < argc; i++) {
          if (_stricmp(argv[i], "--driver") == 0) {
               backend = MemoryBackend::Driver;
               break;
          }
     }

     if (backend == MemoryBackend::Driver) {
          if (!drv.Loaddriver("AXDL0GN47EAR73GT1KKPIL")) {
               printf("Driver load failed\n");
               return 1;
          }
          printf("[+] Using driver backend\n");
     }
     else {
          printf("[+] Using API backend\n");
     }
#else
     printf("[+] Using API backend\n");
#endif

     uint32_t pid = 0xEB4;
     CodeLifter lifter(pid, backend);

     uintptr_t targetFunc = 0x10FB40EE1;
     size_t hintSize = 0x3DF;

     if (!lifter.CollectFunction(targetFunc, hintSize, true)) {
          printf("Lift failed\n");
#ifdef USE_DRIVER
          if (backend == MemoryBackend::Driver) drv.UnDriver();
#endif
          return 1;
     }

     lifter.DumpResult();

     void* localAddr = lifter.GetLocalFunction(targetFunc);
     if (!localAddr) {
          printf("Function not found\n");
#ifdef USE_DRIVER
          if (backend == MemoryBackend::Driver) drv.UnDriver();
#endif
          return 1;
     }

     using SubFunc = uint64_t(*)(uint64_t, uint64_t);
     SubFunc decrypt = (SubFunc)localAddr;


     lifter.SyncMirrors();
     lifter.SyncIndirectSlots();

     Sleep(12000);

     uint64_t result = decrypt(0x8001000FC875BD5E,0xF000000000000);

     printf("Result: 0x%x\n", result);

#ifdef USE_DRIVER
     if (backend == MemoryBackend::Driver) drv.UnDriver();
#endif
     system("pause");
     return 0;
}
