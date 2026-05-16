#pragma once
#include <windows.h>
#include <winternl.h>

#if _WIN64
#pragma comment(lib,"2022_MT_x64.lib")

#define PTRMAXVAL ((PVOID64)0x000F000000000000)
#define pVOID PVOID64

#else
#if _WIN32

#define PTRMAXVAL ((PVOID)0xFFF00000)
#define pVOID PVOID
#endif
#endif
#define IsAddressValid(ptr) (((ptr >= 0x40000) && ((pVOID)ptr < PTRMAXVAL) && ((pVOID)ptr != nullptr)) ? TRUE : FALSE)

#pragma pack(push, 2)

typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;

typedef struct _PHYSICAL_MEMORY_RANGE {
	PHYSICAL_ADDRESS BaseAddress;
	LARGE_INTEGER NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, * PPHYSICAL_MEMORY_RANGE;

typedef struct _SYSTEM_MEMORY_INFO
{
	LARGE_INTEGER CR3;
	LARGE_INTEGER NtBuildNumber;
	LARGE_INTEGER KernBase;
	LARGE_INTEGER KPCR[64];
	LARGE_INTEGER NtBuildNumberAddr;
	LARGE_INTEGER NumberOfRuns;
	PHYSICAL_MEMORY_RANGE Run[20];
} SYSTEM_MEMORY_INFO, * PSYSTEM_MEMORY_INFO;
#pragma pack(pop)
 
typedef unsigned long long u64;
typedef unsigned long u32;

typedef PVOID64 ptr;
typedef PVOID64 p;
typedef u32* dptr;
typedef u64* qptr;

class Driver
{
public:
	Driver();
	~Driver();
public:
    //安装驱动
	BOOL Loaddriver(const char* key);
	//卸载驱动
	void UnDriver();
	//驱动是否安装
	BOOL IsInstall();
	//进程保护隐藏开启 参数1 进程标识  参数2 是否隐藏进程  （支持多个进程同时操作）
	void HideProcessAdd(u32 pid, BOOL ishi);
	//进程保护隐藏恢复 参数1 进程标识  参数2 是否隐藏进程  （支持多个进程同时操作）
	void HideProcessSub(u32 pid, BOOL ishi);
	//鼠标移动
	void Mouse_move(long x, long y);
	//鼠标移动2
	void Mouse_move2(long x, long y);
	//读内存
	BOOL ReadProcessMemory(ptr addr, ptr buffer, u64 size, u64 moshi, u64* lpNumberOfBytesRead);
	//写内存
	BOOL WriteProcessMemory(ptr addr, ptr buffer, u64 nSize, u64 moshi, u64* lpNumberOfBytesWritten);
	//读取内存  模式 0默认 1 MDL  2 物理  3 无附加物理
	BOOL ReadProcessMemory(u64 addr, ptr buffer, u64 size, u32 moshi);
	//写入内存  模式 0默认 1 MDL  2 物理  3 无附加物理
	BOOL WriteProcessMemory(u64 addr, ptr buffer, u64 nSize, u32 moshi);	
	//申请内存
	u64 AllocateVirtualMemory(u32 pid, ptr addr, u32 ZeroBits, u32 Size, u32 AllocationType, u32 Protect);
	//申请MDL映射内存
	u64 AllocateVirtualMemoryA(u32 pid, u32 Size, u32 Protect);
	//释放内存
	void FreeVirtualMemory(u32 pid, ptr addr, u64 Size, u32 FreeType);
	//MDL强写内存
	BOOL WriteProcessMemoryEx(ptr addr, ptr buffer, u64 nSize);
	//远程创建线程
	void CreateThreadEx(u32 pid, ptr start);
	//取模块函数地址
	u64 GetModuleExportAddress(u32 pid, ptr base, CHAR* name);
	//设置进程
	BOOL proceint(u32 pid);
	//取主模块地址
	u64 GetMoudleBase();
	//取模块地址
	u64 GetMoudleEx(CHAR* Ming);
	//取模块大小
	u64 GetMoudleSize(CHAR* Ming);
	//x64无痕注入     0=消息 1=劫持Rip 2=APC插入
	u64   Tracelessinjection(u32 pid, PVOID moudle, u32 Size, u32 InjectType, BOOL ismap);
	//强删文件
	void DeleteFileEx(CHAR* name);
	//锁定文件  支持多个文件
	BOOL LockFileEx(CHAR* name);
	//解锁全部文件
	void ULockFileAll();
	//修改内存属性
	BOOL ProtectVirtualMemory(u32 pid, u64 addr, u32 ProtectSize, u32 NewProtect, u32* OldProtect);
	//查询内存 参数1=进程pid 参数2=查询地址   参数3  PMEMORY_BASIC_INFORMATION
	void QueryVirtualMemory(u32 pid, ptr addr, ptr info);
	//远程汇编
	void RemoteCall(u32 pid, u32 tid, u64 shellcode, u64 len);
	//特征码搜索
	u64 FindProcSignCode(u32 pid, u64 base, CHAR* code, u64 len);
	//防止截图 参数1 窗口句柄 参数2 用17
	u32 Protect_sprite_content(u64 handle, u32 attributes);
	//进程伪装
	BOOL FakeProcess(u32 pid, u32 SrcPid);

	//伪装线程
	void HideThread(u32 tid);
	//恢复挂起进程
	void ResumeProcess(u32 pid);
	//挂起进程
	void SuspendProcess(u32 pid);
	
	//键盘按下
	void KeyDown(USHORT VirtualKey);
	//键盘弹起
	void KeyUp(USHORT VirtualKey);
	//鼠标侧键1（XButton1）按下
	void MouseXButton1Down();
	//鼠标侧键1（XButton1）释放
	void MouseXButton1Up();
	//鼠标侧键2（XButton2）按下
	void MouseXButton2Down();
	//鼠标侧键2（XButton2）释放
	void MouseXButton2Up();
	//鼠标左键按下
	void MouseLeftButtonDown();
	//鼠标左键弹起
	void MouseLeftButtonUp();
	//鼠标右键按下
	void MouseRightButtonDown();
	//鼠标右键弹起
	void MouseRightButtonUp();
	//鼠标中键按下
	void MouseMiddleButtonDown();
	//鼠标中键弹起
	void MouseMiddleButtonUp();
	//鼠标相对移动
	void MouseMoveRELATIVE(LONG dx, LONG dy);
	//鼠标绝对
	void MouseMoveABSOLUTE(LONG dx, LONG dy);
	// 向上滚动垂直滚轮
	void ScrollVerticalUp(USHORT units);
	// 向上滚动垂直滚轮
	void ScrollVerticalDown(USHORT units);	
	//取系统相关信息
	void GetSystemInfo(PSYSTEM_MEMORY_INFO data);
	//初始解密
	void InitializeDecrypt(u64 base);
	//通用解密
	u64 KernelDecrypt(u64 buff);
	
	BOOL ValidPtr(ULONG64 Ptr, ULONG a = 0)
	{

		return (BOOL)!IsAddressValid(Ptr);// (BOOL)(Ptr < 0xFFFF || Ptr > 0x7FFFFFFFFFFF || Ptr % a);
	}

	//绘制矩形
	//void DrawBox(u32 x, u32 y, u32 w, u32 h, u32 thickness, u32 r, u32 g, u32 b);
	template<typename T>
	T RPM(unsigned long long Addr);

	template<typename T>
	T RPM(unsigned long long Addr, unsigned long Size);

	template<typename T>
	bool RPM(unsigned long long Addr, T OuterBuffer, unsigned long Size);

	template<typename T>
	bool WPM(unsigned long long Addr, T value);

	template<typename T>
	bool WPM(unsigned long long Addr, T value, unsigned long Size);

};


template<typename T> inline T Driver::RPM(unsigned long long Addr)
{
	T readBuffer{};
	u64 lpNumberOfBytesRead;
	ReadProcessMemory((ptr)Addr, &readBuffer, sizeof(T),0, &lpNumberOfBytesRead);
	return (T)readBuffer;
}

template<typename T> inline T Driver::RPM(unsigned long long Addr, unsigned long Size)
{
	T readBuffer = {};
	u64 lpNumberOfBytesRead;
	ReadProcessMemory((ptr)Addr, &readBuffer, Size,0, &lpNumberOfBytesRead);
	return (T)readBuffer;
}

template<typename T> inline bool Driver::RPM(unsigned long long Addr, T OuterBuffer, unsigned long Size)
{
	u64 lpNumberOfBytesRead;
	ReadProcessMemory( (ptr)Addr, OuterBuffer, Size,0, &lpNumberOfBytesRead);
	return TRUE;
}

template<typename T> inline bool Driver::WPM(unsigned long long Addr, T value)
{
	u64 lpNumberOfBytesRead;
	WriteProcessMemory((ptr)Addr, &value, sizeof(T),0, &lpNumberOfBytesRead);
	return TRUE;
}

template<typename T> inline bool Driver::WPM(unsigned long long Addr, T value, unsigned long Size)
{
	u64 lpNumberOfBytesRead;
	WriteProcessMemory((ptr)Addr, &value, Size, 0,&lpNumberOfBytesRead);
	return TRUE;
}

//不能更改名字 否则无法编译 或者你可以自己 new 一个
extern Driver drv;

