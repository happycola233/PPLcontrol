# PPLcontrol

## 描述

这个工具允许你列出受保护的进程，获取特定进程的保护级别，或设置任意的保护级别。更多信息，你可以阅读这篇博文：[调试受保护的进程](httpsitm4n.github.iodebugging-protected-processes)。

## 用法

### 1. 下载MSI驱动程序

你可以在这里获取MSI驱动程序`RTCore64.sys`的副本：[PPLKillerdriver](httpsgithub.comRedCursorSecurityConsultingPPLKillertreemasterdriver)。

### 2. 安装MSI驱动程序

__免责声明：__ 不言而喻，你绝不应该在主机上安装此驱动程序。__请使用虚拟机！__

```batch
sc.exe create RTCore64 type= kernel start= auto binPath= CPATHTORTCore64.sys DisplayName= Micro - Star MSI Afterburner
net start RTCore64
```

### 3. 使用PPLcontrol

列出受保护的进程。

```batch
PPLcontrol.exe list
```

获取特定进程的保护级别。

```batch
PPLcontrol.exe get 1234
```

设置任意的保护级别。

```batch
PPLcontrol.exe set 1234 PPL WinTcb
```

使用任意的保护级别保护一个非保护进程。这也会自动相应调整签名级别。

```batch
PPLcontrol.exe protect 1234 PPL WinTcb
```

取消保护一个受保护的进程。此操作会将保护级别设置为`0`（_即_ `None`），并将EXEDLL签名级别设置为`0`（_即_ `Unchecked`）。

```batch
PPLcontrol.exe unprotect 1234
```

### 4. 卸载驱动程序

```batch
net stop RTCore64
sc.exe delete RTCore64
```

## 使用场景

### 使用WinDbg调试受保护的进程

WinDbg只需要打开目标进程，因此你可以使用PPLcontrol在`windbg.exe`进程上设置任意的保护级别。

1. 获取`windbg.exe`进程的PID。
2. 使用PPLcontrol设置任意的保护级别。

```console
CTemptasklist  findstr i windbg
windbg.exe                    1232 Console                    1     24,840 K
CTempPPLcontrol.exe protect 1232 PPL WinTcb
[+] 保护级别 'PPL-WinTcb' 已应用于PID为1232的进程，先前的保护级别为：'None-None'。
[+] 签名级别 'WindowsTcb' 和区段签名级别 'Windows' 已应用于PID为1232的进程。
```

### 使用API Monitor检查受保护的进程

除了打开目标进程外，API Monitor还会向其中注入一个DLL。因此，仅在`apimonitor.exe`进程上设置任意的保护级别是不够的。由于注入的DLL未正确签名用于此目的，目标进程的区段签名标志可能会阻止它加载。不过，你可以临时禁用目标进程的保护，开始监控它，并在完成后恢复保护。

```txt
无法在目标进程中加载模块 - 错误 577，Windows无法验证此文件的数字签名。最近的硬件或软件更改可能安装了签名不正确或损坏的文件，或者这可能是来自未知来源的恶意软件。
```

1. 获取目标进程的PID。
2. 使用PPLcontrol获取目标进程的保护级别。
3. 取消进程保护。
4. 使用API Monitor开始监控进程。
5. 恢复目标进程的保护。

```console
CTemptasklist  findstr i target
target.exe                    1337 Services                   1     14,160 K
CTempPPLcontrol.exe get 1337
[+] PID为1337的进程是一个PPL，其签名类型为'WinTcb' (6)。
CTempPPLcontrol.exe unprotect 1337
[+] PID为1337的进程不再是受保护进程(PP(L))。

CTempPPLcontrol.exe protect 1337 PPL WinTcb
[+] 保护级别 'PPL-WinTcb' 已应用于PID为1337的进程，先前的保护级别为：'None-None'。
[+] 签名级别 'WindowsTcb' 和区段签名级别 'Windows' 已应用于PID为1337的进程。
```

## 构建

1. 在Visual Studio中打开解决方案。
2. 选择`Releasex64`（不支持`x86`，可能永远不会支持）。
3. 构建解决方案。

## 致谢

- 感谢[@aceb0nd](httpstwitter.comaceb0nd)提供工具[PPLKiller](httpsgithub.comRedCursorSecurityConsultingPPLKiller)
- 感谢[@aionescu](httpstwitter.comaionescu)撰写文章[受保护进程第三部分：Windows PKI 内部（签名级别、场景、根密钥、EKU和运行时签名者）](httpswww.alex-ionescu.comp=146)