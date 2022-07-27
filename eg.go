package main

import (
    "syscall"
    "unsafe"
    "unicode/utf16"
)

import "fmt"

type (
    HANDLE uintptr
    BOOL int32
)

var (
    modadvapi32               = syscall.NewLazyDLL("advapi32.dll")
)

const (
    ProcessAllAccess = 0x2035711
)


var (
    modkernel32, _            = syscall.LoadDLL("kernel32.dll")
    procCreateRemoteThread, _ = modkernel32.FindProc("CreateRemoteThread")
    procGetModuleHandleA, _   = modkernel32.FindProc("GetModuleHandleA")
    procCopyMemory, _                 = modkernel32.FindProc("RtlCopyMemory")
    procCloseHandle, _               = modkernel32.FindProc("CloseHandle")
    procConnectNamedPipe, _           = modkernel32.FindProc("ConnectNamedPipe")
    procCreateFileW, _                = modkernel32.FindProc("CreateFileW")
    procCreateNamedPipeW, _           = modkernel32.FindProc("CreateNamedPipeW")
    procCreateProcessA, _             = modkernel32.FindProc("CreateProcessA")
    procCreateProcessW, _             = modkernel32.FindProc("CreateProcessW")
    procCreateToolhelp32Snapshot, _   = modkernel32.FindProc("CreateToolhelp32Snapshot")
    procFindResource, _               = modkernel32.FindProc("FindResourceW")
    procGetConsoleScreenBufferInfo, _ = modkernel32.FindProc("GetConsoleScreenBufferInfo")
    procGetConsoleWindow, _           = modkernel32.FindProc("GetConsoleWindow")
    procGetCurrentThread, _           = modkernel32.FindProc("GetCurrentThread")
    procGetDiskFreeSpaceEx, _         = modkernel32.FindProc("GetDiskFreeSpaceExW")
    procGetExitCodeProcess, _         = modkernel32.FindProc("GetExitCodeProcess")
    procGetLastError , _              = modkernel32.FindProc("GetLastError")
    procGetLogicalDrives, _           = modkernel32.FindProc("GetLogicalDrives")
    procGetModuleHandle , _           = modkernel32.FindProc("GetModuleHandleW")
    procGetProcAddress , _            = modkernel32.FindProc("GetProcAddress")
    procGetProcessTimes, _            = modkernel32.FindProc("GetProcessTimes")
    procGetSystemTime, _              = modkernel32.FindProc("GetSystemTime")
    procGetSystemTimes, _             = modkernel32.FindProc("GetSystemTimes")
    procGetSystemInfo  , _            = modkernel32.FindProc("GetSystemInfo")
    procGetUserDefaultLCID, _         = modkernel32.FindProc("GetUserDefaultLCID")
    procGlobalAlloc, _                = modkernel32.FindProc("GlobalAlloc")
    procGlobalFree , _                = modkernel32.FindProc("GlobalFree")
    procGlobalLock , _                = modkernel32.FindProc("GlobalLock")
    procGlobalUnlock, _               = modkernel32.FindProc("GlobalUnlock")
    procLoadLibraryA, _               = modkernel32.FindProc("LoadLibraryA")
    procLoadResource, _               = modkernel32.FindProc("LoadResource")
    procLockResource, _               = modkernel32.FindProc("LockResource")
    procLstrcpy , _                   = modkernel32.FindProc("lstrcpyW")
    procLstrlen , _                   = modkernel32.FindProc("lstrlenW")
    procProcess32First, _             = modkernel32.FindProc("Process32FirstW")
    procProcess32Next, _              = modkernel32.FindProc("Process32NextW")
    procModule32First, _             = modkernel32.FindProc("Module32FirstW")
    procModule32Next , _              = modkernel32.FindProc("Module32NextW")
    procMoveMemory , _                = modkernel32.FindProc("RtlMoveMemory")
    procMulDiv, _                     = modkernel32.FindProc("MulDiv")
    procOpenProcess  , _              = modkernel32.FindProc("OpenProcess")
    procQueryPerformanceCounter , _   = modkernel32.FindProc("QueryPerformanceCounter")
    procQueryPerformanceFrequency , _ = modkernel32.FindProc("QueryPerformanceFrequency")
    procReadProcessMemory, _          = modkernel32.FindProc("ReadProcessMemory")
    procSetConsoleCtrlHandler, _      = modkernel32.FindProc("SetConsoleCtrlHandler")
    procSetConsoleTextAttribute, _    = modkernel32.FindProc("SetConsoleTextAttribute")
    procSetSystemTime   , _           = modkernel32.FindProc("SetSystemTime")
    procSizeofResource , _            = modkernel32.FindProc("SizeofResource")
    procTerminateProcess, _           = modkernel32.FindProc("TerminateProcess")
    procVirtualAlloc  , _             = modkernel32.FindProc("VirtualAlloc")
    procVirtualAllocEx , _            = modkernel32.FindProc("VirtualAllocEx")
    procVirtualFreeEx , _             = modkernel32.FindProc("VirtualFreeEx")
    procVirtualProtect, _             = modkernel32.FindProc("VirtualProtect")
    procVirtualQuery  , _             = modkernel32.FindProc("VirtualQuery")
    procVirtualQueryEx, _             = modkernel32.FindProc("VirtualQueryEx")
    procWaitForSingleObject, _        = modkernel32.FindProc("WaitForSingleObject")
    procWriteFile    , _              = modkernel32.FindProc("WriteFile")
    procWriteProcessMemory  , _       = modkernel32.FindProc("WriteProcessMemory")

    procResumeThread, _  = modkernel32.FindProc("ResumeThread")
    procSuspendThread, _ = modkernel32.FindProc("SuspendThread")
)

func IsErrSuccess(err error) bool {
    if errno, ok := err.(syscall.Errno); ok {
        if errno == 0 {
            return true
        }
    }
    return false
}

func ReadProcessMemory(hProcess HANDLE, lpBaseAddress uint32, size uint) (data []byte, err error) {
    var numBytesRead uintptr
    data = make([]byte, size)

    _, _, err = procReadProcessMemory.Call(uintptr(hProcess),
        uintptr(lpBaseAddress),
        uintptr(unsafe.Pointer(&data[0])),
        uintptr(size),
        uintptr(unsafe.Pointer(&numBytesRead)))
    if !IsErrSuccess(err) {
        return
    }
    err = nil
    return
}

func UTF16PtrToString(cstr *uint16) string {
    if cstr != nil {
        us := make([]uint16, 0, 256)
        for p := uintptr(unsafe.Pointer(cstr)); ; p += 2 {
            u := *(*uint16)(unsafe.Pointer(p))
            if u == 0 {
                return string(utf16.Decode(us))
            }
            us = append(us, u)
        }
    }

    return ""
}

func GetPrivileges() {
    var token syscall.Token
    handle, _ := syscall.GetCurrentProcess()
    //失败
    if nil != syscall.OpenProcessToken(handle, syscall.TOKEN_ALL_ACCESS, &token) {
        return
    }
    //    syscall.Syscall(procLookupPrivilegeValueW.Addr(),nil,)
}

type Process struct {
    ProcessID int
    Name      string
    Exe       string
}

//获取进程的名字
func GetProcessesByName(exeFile string) (*Process, string) {
    handle, _ := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
    if handle == 0 {
        return nil, "创建Snapshot失败"
    }
    defer syscall.CloseHandle(handle)

    //定义句柄存储
    var entry = syscall.ProcessEntry32{}
    entry.Size = uint32(unsafe.Sizeof(entry))
    var process Process
    //定义一个实体类型
    for true {
        if nil != syscall.Process32Next(handle, &entry) {
            break
        }
        //执行文件的名称
        _exeFile := UTF16PtrToString(&entry.ExeFile[0])
        if exeFile == _exeFile {
            process.Name = _exeFile
            process.ProcessID = int(entry.ProcessID)
            process.Exe = _exeFile
            return &process, ""
        }

    }
    return nil, "未找到进程"
}


func GetModuleHandleA(name string) (r1 uintptr, err error) {
    bytes := []byte(name)
    r1, _, err = procGetModuleHandleA.Call(uintptr(unsafe.Pointer(&bytes[0])))
    err = syscall.GetLastError()
    return
}

func GetLoadLibraryAAddr() (uintptr, error) {
    handle, err := GetModuleHandleA("Kernel32.dll")
    if err != nil {
        return 0, err
    }
    ptr, err := syscall.GetProcAddress(syscall.Handle(handle), "LoadLibraryA")
    err = syscall.GetLastError()
    return ptr, err
}

//分配虚拟内存
func VirtualAllocEx(hwnd syscall.Handle, lpaddress uint32, size uint32, tp uint32, tect uint32) (r1 uintptr, err error) {
    r1, _, _ = procVirtualAllocEx.Call(uintptr(hwnd), uintptr(lpaddress), uintptr(size), uintptr(tp), uintptr(tect), 0)
    err = syscall.GetLastError()
    return
}

func WriteProcessMemory(hwnd syscall.Handle, addr uint32, lpBuffer uintptr, nsize uint32, filewriten uint32) (r1 uintptr, err error) {
    r1, _, err = procWriteProcessMemory.Call(uintptr(hwnd), uintptr(addr), lpBuffer, uintptr(nsize), uintptr(filewriten), 0)
    err = syscall.GetLastError()
    return
}

//执行远程线程调用方法
func CreateRemoteThread(hwnd syscall.Handle, threadAttributes uint32, stackSize uint32, startAddress uintptr, parameter uintptr, creationFlags uint32, threadid uint32) (r1 uintptr, err error) {
    r1, _, err = procCreateRemoteThread.Call(uintptr(hwnd), uintptr(threadAttributes), uintptr(stackSize), uintptr(startAddress), uintptr(parameter), uintptr(creationFlags), uintptr(threadid))
    err = syscall.GetLastError()
    return
}


func Inject(name string, dll string) string {
    //1.获取微信的进程ID
    process, err := GetProcessesByName(name)
    if err != "" {
        return err
    }

    //2.打开进程
    handle, ex := syscall.OpenProcess(uint32(ProcessAllAccess), false, uint32(process.ProcessID))
    if ex != nil {
        return "打开进程失败"
    }
    defer syscall.CloseHandle(handle)
    var dllLength = len(dll) + 1
    //3.分配虚拟内存，写入dll名字路径
    dllMemAddr, ex := VirtualAllocEx(handle, 0, uint32(dllLength), 4096, 4)
    if ex != nil {
        return "分配内存失败"
    }
    bt := []byte(dll)
    //4.写入内存
    _, ex = WriteProcessMemory(handle, uint32(dllMemAddr), uintptr(unsafe.Pointer(&bt[0])), uint32(dllLength), 0)
    if ex != nil {
        return "写入内存失败"
    }

    //5.测试一下读出内存
    bytes, _ := ReadProcessMemory(HANDLE(handle), uint32(dllMemAddr), uint(dllLength))
    fmt.Println("开始加载DLL：", string(bytes[:]))

    //5.远程执行
    loadAddr, ex := GetLoadLibraryAAddr()
    println(loadAddr)
    if ex != nil {
        return "获取内核地址失败"
    }
    pch, ex := CreateRemoteThread(handle, 0, 0, loadAddr, dllMemAddr, 0, 0)
    if ex != nil {
        println(ex)
        return "远程加载DLL失败:"
    }
    defer syscall.CloseHandle(syscall.Handle(pch))

    return "DLL注入成功"
}


func main() {
    dll := "C:\\Users\\Godtoy\\source\\repos\\WechatHookDemo1\\Debug\\GetWxInfo.dll"
    var wx = "WeChat.exe"
    err := Inject(wx, dll)
    println(err)
}
