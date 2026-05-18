#include "CodeLifter.h"
#include "driver.h"
#include <cstdio>

int main()
{
     if (!drv.Loaddriver("AXEW073O7Z3HJDNUFB4VU0")) {
          printf("Driver load failed\n");
          return 1;
     }

     uint32_t pid = 0x9994;
     CodeLifter lifter(pid);

     uintptr_t targetFunc = 0x7FF7F7340FD0;
     size_t hintSize = 0x71E;

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

     //uint32_t result = decrypt(0xAAAA);
     //printf("Result: 0x%x\n", result);

     drv.UnDriver();
     system("pause");
     return 0;
}