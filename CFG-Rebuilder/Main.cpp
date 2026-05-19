#include "CodeLifter.h"
#include "driver.h"
#include <cstdio>

int main()
{
     if (!drv.Loaddriver("AXDL0GN47EAR73GT1KKPIL")) {
          printf("Driver load failed\n");
          return 1;
     }

     uint32_t pid = 0xEB4;
     CodeLifter lifter(pid);

     uintptr_t targetFunc = 0x10FB40EE1;
     size_t hintSize = 0x3DF;

     if (!lifter.CollectFunction(targetFunc, hintSize, true)) {
          printf("Lift failed\n");
          drv.UnDriver();
          return 1;
     }

     lifter.DumpResult();

     void* localAddr = lifter.GetLocalFunction(targetFunc);
     if (!localAddr) {
          printf("Function not found\n");
          drv.UnDriver();
          return 1;
     }

     using SubFunc = uint32_t(*)(uint32_t);
     SubFunc decrypt = (SubFunc)localAddr;

     lifter.SyncMirrors();
     lifter.SyncIndirectSlots();

     //uint32_t result = decrypt(0x12345);
     //printf("Result: 0x%x\n", result);

     drv.UnDriver();
     system("pause");
     return 0;
}