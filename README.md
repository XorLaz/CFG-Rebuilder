# CFG-Rebuilder

A lightweight x64 code lifter for dynamic cross-process function extraction, relocation, and native local execution.

## Overview

CFG-Rebuilder enables you to rip arbitrary x64 functions from a live target process and execute them directly in your own process — without recreating the algorithm manually. It traces the full **Control Flow Graph (CFG)** of the target function, copies all reachable code, and patches every RIP-relative reference so the extracted code runs correctly in a completely different address space.

Typical use case: extracting an obfuscated decryption routine from a running process and calling it locally with arbitrary inputs.

## How It Works

```
Target Process                        Local Process
─────────────────                     ─────────────────────────────────
 [Target Function]  ──── copy ──────► [Arena: lifted code]
 [Called Sub A]     ──── copy ──────► [Arena: lifted code]
 [Called Sub B]     ──── copy ──────► [Arena: lifted code]
 [RIP-relative var] ──── mirror ────► [Mirror variable copy]
 [Indirect call ptr] ─── slot ──────► [Indirect call slot → local target]
```

1. **Scan** — `FunctionScanner` determines the byte size of the target function using `.pdata` exception records for accuracy, falling back to heuristic scanning.
2. **Lift** — `CodeLifter` copies the raw bytes into a local RWX arena (`ArenaAllocator`) and recursively enqueues all direct call/jump targets.
3. **Fix** — `Fixer` walks every instruction with [Zydis](https://github.com/zyantific/zydis) and rewrites:
   - RIP-relative `CALL`/`JMP` targets → local lifted addresses
   - RIP-relative memory references → local mirror variable copies
   - Indirect call pointers → local redirect slots
   - Long-range jumps → trampoline stubs appended after each function
4. **Sync** — `SyncMirrors()` refreshes mirror variables from the target process; `SyncIndirectSlots()` updates indirect call slots so they stay current with the target's state.
5. **Execute** — cast the local address to a function pointer and call it directly.

## Architecture

| Component | File | Responsibility |
|---|---|---|
| `CodeLifter` | `CodeLifter.h/cpp` | Orchestrates the full lift pipeline (BFS work queue, arena management) |
| `FunctionScanner` | `FunctionScanner.h/cpp` | Determines function boundaries via `.pdata` or heuristic scan |
| `Fixer` | `Fixer.h/cpp` | Instruction-level fixups for all RIP-relative and control-flow references |
| `MemoryAccess` | `MemoryAccess.h/cpp` | Cross-process read/write (supports Windows API and kernel driver backends) |
| `ModuleResolver` | `ModuleResolver.h/cpp` | Identifies modules shared between target and local process (e.g., ntdll) |
| `PdataResolver` | `PdataResolver.h/cpp` | Parses `.pdata` to get precise function sizes |
| `ArenaAllocator` | `ArenaAllocator.h/cpp` | Allocates a contiguous RWX executable memory region locally |
| `Driver` | `driver.h` | Kernel driver interface for privileged memory operations (optional, requires `USE_DRIVER` macro) |

**Dependencies:** [Zydis](https://github.com/zyantific/zydis) + [Zycore](https://github.com/zyantific/zycore-c) (bundled)

## Requirements

- Windows x64
- Visual Studio 2022 (MSVC, x64, MT runtime)
- **API mode (default):** No additional dependencies — uses Windows native `ReadProcessMemory` / `VirtualQueryEx`. The target process must be accessible with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` (may require running as Administrator).
- **Driver mode (optional):** Requires an external kernel-mode driver library (`2022_MT_x64.lib`) and a valid license key. Enable by defining the `USE_DRIVER` preprocessor macro.

## Usage

### API Mode (Default)

No driver or license key needed — works out of the box:

```cpp
#include "CodeLifter.h"

int main() {
    uint32_t pid = 0xEB4;          // Target process PID
    CodeLifter lifter(pid);        // Uses Windows API by default

    uintptr_t targetFunc = 0x10FB40EE1;  // Address of function to lift
    size_t hintSize = 0x3DF;             // Optional size hint (0 = auto-detect)

    // Lift the function and all reachable callees
    if (!lifter.CollectFunction(targetFunc, hintSize, true)) {
        printf("Lift failed\n");
        return 1;
    }

    lifter.DumpResult();  // Print lifted function map

    // Get the local address of the lifted function
    void* localAddr = lifter.GetLocalFunction(targetFunc);

    // Sync mirrors and indirect slots before calling
    lifter.SyncMirrors();
    lifter.SyncIndirectSlots();

    // Cast and call — runs entirely in local process
    using DecryptFn = uint64_t(*)(uint64_t, uint64_t);
    DecryptFn decrypt = (DecryptFn)localAddr;
    uint64_t result = decrypt(0x8001000FC875BD5E, 0xF000000000000);

    printf("Result: 0x%llx\n", result);
    return 0;
}
```

### Driver Mode (Optional)

To use an external kernel driver for memory access, compile with `USE_DRIVER` defined and pass `--driver` at runtime:

```cpp
#include "CodeLifter.h"
#include "driver.h"

int main() {
    // Load your kernel driver
    if (!drv.Loaddriver("YOUR_DRIVER_KEY")) {
        printf("Driver load failed\n");
        return 1;
    }

    uint32_t pid = 0xEB4;
    CodeLifter lifter(pid, MemoryBackend::Driver);

    // ... same usage as above ...

    drv.UnDriver();
    return 0;
}
```

### Key API

```cpp
// Lift a function and all reachable code recursively
bool CollectFunction(uintptr_t targetFuncAddr,
                     size_t hintSize = 0,
                     bool stopAtFirstRet = false);

// Get the local executable address for an original function address
void* GetLocalFunction(uintptr_t origAddr) const;

// Refresh mirror variables from the target process
void SyncMirrors();

// Refresh indirect call slots from the target process
void SyncIndirectSlots();

// Print a summary of all lifted functions
void DumpResult() const;
```

## Limitations

- **x64 only** — no x86 support
- **LEA-based function pointer calls** — fixup currently only covers the first 32 bytes of each function
- **Shared modules** — calls into DLLs shared between the target and local process (e.g., ntdll) are resolved to the local copy directly and not re-lifted
- **Self-modifying or JIT code** — the lift is a one-time snapshot; dynamically generated code will not be captured
- **API mode limitations** — Windows API mode requires sufficient process access rights; some protected processes may not be readable without a kernel driver

## Build

### API Mode (Default)

Open the Visual Studio solution, select `Release x64`, and build. No additional libraries needed — the Zydis and Zycore sources are included.

### Driver Mode

To enable driver support, add `USE_DRIVER` to the preprocessor definitions in your project settings (Project → Properties → C/C++ → Preprocessor → Preprocessor Definitions), and ensure `2022_MT_x64.lib` is available. Then pass `--driver` as a command-line argument when running.

## Disclaimer

This project is intended for **security research, reverse engineering, and educational purposes only**. Use responsibly and only on systems you own or have explicit authorization to analyze.
