#include "CodeLifter.h"
#include "driver.h"
#include <cstdio>

int main()
{
     if (!drv.Loaddriver("AXEW073O7Z3HJDNUFB4VU0")) {
          printf("Driver load failed\n");
          return 1;
     }

     uint32_t pid = 0x485C;
     CodeLifter lifter(pid);

     uintptr_t targetFunc = 0x7FF73D851100;
     size_t hintSize = 0x51;

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

     Sleep(15000);

     uint32_t result = decrypt(0x12345);
     printf("Result: 0x%x\n", result);

     drv.UnDriver();
     system("pause");
     return 0;
}