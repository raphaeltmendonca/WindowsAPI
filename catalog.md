# Windows API

**Accept:** This function is used to listen for incoming connections. This function indicates that the program will listen for incoming connections on a socket. It is mostly used by malware to communicate with their Command and Communication server.

**AdjustTokenPrivileges:** This function is used to enable or disable specific access privileges. In a process injection attack, this function is used by malware to gain additional permissions.

**AttachThreadInput:** This function attaches the input processing from one thread to another so that the second thread receives input events such as keyboard and mouse events. Keyloggers and other spyware use this function.

**Bind:** This function is used to associate a local address to a socket in order to listen for incoming connections.

**BitBlt:** This function is used to copy graphic data from one device to another. Spyware sometimes uses this function to capture screenshots.

**CertOpenSystemStore:** This function is used to access the certificates stored on the local system.

**Connect:** This function is used to connect to a remote socket. Malware often uses low-level functionality to connect to a command-and-control server. It is mostly used by malware to communicate with their Command and Communication server.

**ConnectNamedPipe:** This function is used to create a server pipe for interprocess communication that will wait for a client pipe to connect. Backdoors and reverse shells sometimes use ConnectNamedPipe to simplify connectivity to a command-and-control server.

**ControlService:** This function is used to start, stop, modify, or send a signal to a running service. If malware is using its own malicious service, code needs to be analyzed that implements the service in order to determine the purpose of the call.

**CreateFile:** Creates a new file or opens an existing file.

**CreateFileMapping:** This function is used to create a handle to a file mapping that loads a file into memory and makes it accessible via memory addresses. Launchers, loaders, and injectors use this function to read and modify PE files.

**CreateMutex:** This function creates a mutual exclusion object that can be used by malware to ensure that only a single instance of the malware is running on a system at any given time. Malware often uses fixed names for mutexes, which can be good host-based indicators to detect additional installations of the malware.

**CreateProcess:** This function creates and launches a new process. If malware creates a new process, new process needs to be analyzed as well.

**CreateRemoteThread:** This function is used to start a thread in a remote process. Launchers and stealth malware use CreateRemoteThread to inject code into a different process.

**CreateService:** This function is used to create a service that can be started at boot time. Malware uses CreateService for persistence, stealth, or to load kernel drivers.

**CreateToolhelp32Snapshot:** This function is used to create a snapshot of processes, heaps, threads, and modules. Malware often uses this function as part of code that iterates through processes or threads.

**CryptAcquireContext:** This function is often the first function used by malware to initialize the use of Windows encryption.

**DeviceIoControl:** This function sends a control message from user space to a device driver. Kernel malware that needs to pass information between user space and kernel space often use this function.

**EnableExecuteProtectionSupport:** This function is used to modify the Data Execution Protection (DEP) settings of the host, making it more susceptible to attack.

**EnumProcesses:** This function is used to enumerate through running processes on the system. Malware often enumerates through processes to find a process into which to inject.

**EnumProcessModules:** This function is used to enumerate the loaded modules (executables and DLLs) for a given process. Malware enumerates through modules when doing an injection.

**FindFirstFile/FindNextFile:** This function is used to search through a directory and enumerate the file system. (Ransomware)

**FindResource:** This function is used to find a resource in an executable or loaded DLL. Malware sometimes uses resources to store strings, configuration information, or other malicious files. If this function is used, then check for an .rsrc section in the malware’s PE header.

**FindWindow:** This function is used to search for an open window on the desktop. Sometimes this function is used as an anti-debugging technique to search for OllyDbg windows.

**FtpPutFile:** This function is used to upload a file to remote FTP server.

**GetAdaptersInfo:** This function is used to obtain information about the network adapters on the system. Backdoors sometimes call GetAdaptersInfo in the information-gathering phase to gather information about infected machines. In some cases, it’s used to gather MAC addresses to check for VMware as part of anti-virtual machine techniques.

**GetAsyncKeyState:** This function is used to determine whether a particular key is being pressed. Malware sometimes uses this function to implement a keylogger.

**GetDC:** This function returns a handle to a device context for a window or the whole screen. Spyware that takes screen captures often uses this function.

**GetForegroundWindow:** This function returns a handle to the window currently in the foreground of the desktop. Keyloggers commonly use this function to determine in which window the user is entering his keystrokes.

**Gethostbyname:** This function is used to perform a DNS lookup on a particular hostname prior to making an IP connection to a remote host. Hostnames that serve as command and- control servers often make good network-based signatures.

**Gethostname:** This function is used to retrieve the hostname of the computer. Backdoors sometimes use gethostname in information gathering phase of the victim machine.

**GetKeyState:** This function is used by keyloggers to obtain the status of a particular key on the keyboard.

**GetModuleFilename:** This function returns the filename of a module that is loaded in the current process. Malware can use this function to modify or copy files in the currently running process.

**GetModuleHandle:** This function is used to obtain a handle to an already loaded module. Malware may use GetModuleHandle to locate and modify code in a loaded module or to search for a good location to inject code.

**GetProcAddress:** This function is used to retrieve the address of a function in a DLL loaded into memory. This is used to import functions from other DLLs in addition to the functions imported in the PE file header.

**GetStartupInfo:** This function is used to retrieve a structure containing details about how the current process was configured to run, such as where the standard handles are directed.

**GetSystemDefaultLangId:** This function returns the default language settings for the system. These are used by malwares by specifically designed for region-based attacks.

**GetTempPath:** This function returns the temporary file path. If malware call this function, check whether it reads or writes any files in the temporary file path.

**GetThreadContext:** This function returns the context structure of a given thread. The context for a thread stores all the thread information, such as the register values and current state.

**GetVersionEx:** This function returns information about which version of Windows is currently running. This can be used as part of a victim survey, or to select between different offsets for undocumented structures that have changed between different versions of Windows.

**GetWindowsDirectory:** This function returns the file path to the Windows directory (usually C:\Windows). Malware sometimes uses this call to determine into which directory to install additional malicious programs.

**inet_addr:** This function converts an IP address string like 127.0.0.1 so that it can be used by functions such as connect. The string specified can sometimes be used as a network-based signature.

**InternetOpen:** This function initializes the high-level Internet access functions from WinINet, such as InternetOpenUrl and InternetReadFile. Searching for InternetOpen is a good way to find the start of Internet access functionality. One of the parameters to InternetOpen is the User-Agent, which can sometimes make a good network-based signature.

**InternetOpenUrl:** This function opens a specific URL for a connection using FTP, HTTP, or HTTPS.URLs, if fixed, can often be good network-based signatures.

**InternetReadFile:** This function reads data from a previously opened URL.

**InternetWriteFile:** This function writes data to a previously opened URL.

**IsNTAdmin:** This function checks if the user has administrator privileges.

**IsWoW64Process:** This function is used by a 32-bit process to determine if it is running on a 64-bit operating system.

**LdrLoadDll:** This is a low-level function to load a DLL into a process, just like LoadLibrary. Normal programs use LoadLibrary, and the presence of this import may indicate a program that is attempting to be stealthy.

**LoadResource:** This function loads a resource from a PE file into memory. Malware sometimes uses resources to store strings, configuration information, or other malicious files.

**LsaEnumerateLogonSessions:** This function is used to enumerate through logon sessions on the current system, which can be used as part of a credential stealer.

**MapViewOfFile:** This function is used to map a file into memory and makes the contents of the file accessible via memory addresses. Launchers, loaders, and injectors use this function to read and modify PE files. By using MapViewOfFile, the malware can avoid using WriteFile to modify the contents of a file.

**MapVirtualKey:** This function is used to translate a virtual-key code into a character value. It is often used by keylogging malware.

**Module32First/Module32Next:** This function is used to enumerate through modules loaded into a process. Injectors use this function to determine where to inject code.

**NetScheduleJobAdd:** This function submits a request for a program to be run at a specified date and time. Malware can use NetScheduleJobAdd to run a different program. This is an important indicator to see the program that is scheduled to run at future time.

**NetShareEnum:** This function is used to enumerate network shares.

**NtQueryDirectoryFile:** This function returns information about files in a directory. Rootkits commonly hook this function in order to hide files.

**NtQueryInformationProcess:** This function is used to return various information about a specified process. This function is sometimes used as an anti-debugging technique because it can return the same information as CheckRemoteDebuggerPresent.

**NtSetInformationProcess:** This function is used to change the privilege level of a program or to bypass Data Execution Prevention (DEP).

**OpenMutex:** This function opens a handle to a mutual exclusion object that can be used by malware to ensure that only a single instance of malware is running on a system at any given time. Malware often uses fixed names for mutexes, which can be good host-based indicators.

**OpenProcess:** This function is used to open a handle to another process running on the system. This handle can be used to read and write to the other process memory or to inject code into the other process.

**OutputDebugString:** This function is used to output a string to a debugger if one is attached. This can be used as an anti-debugging technique.

**PeekNamedPipe:** This function is used to copy data from a named pipe without removing data from the pipe. This function is popular with reverse shells.

**Process32First/Process32Next:** This function is used to begin enumerating processes from a previous call to CreateToolhelp32Snapshot. Malware often enumerates through processes to find a process into which to inject.

**QueueUserAPC:** This function is used to execute code for a different thread. Malware sometimes uses QueueUserAPC to inject code into another process.

**ReadProcessMemory:** This function is used to read the memory of a remote process.

**Recv:** This function is used to receive data from a remote machine. Malware often uses this function to receive data from a remote command-and-control server.

**RegisterHotKey:** This function is used to register a handler to be notified anytime a user enters a particular key combination (like CTRL-ALT-J), regardless of which window is active when the user presses the key combination. This function is sometimes used by spyware that remains hidden from the user until the key combination is pressed.

**RegOpenKey:** This function is used to open a handle to a registry key for reading and editing. Registry keys are sometimes written as a way for software to achieve persistence on a host. The registry also contains a whole host of operating system and application setting information.

**ResumeThread:** This function is used to resume a previously suspended thread. ResumeThread is used as part of several injection techniques.

**RtlCreateRegistryKey:** This function is used to create a registry from kernel-mode code.

**RtlWriteRegistryValue:** This function is used to write a value to the registry from kernel-mode code.

**SamIConnect:** This function is used to connect to the Security Account Manager (SAM) in order to make future calls that access credential information. Hash-dumping programs access the SAM database in order to retrieve the hash of users’ login passwords.

**SamIGetPrivateData:** This function is used to query the private information about a specific user from the Security Account Manager (SAM) database. Hash-dumping programs access the SAM database in order to retrieve the hash of users’ login passwords.

**SamQueryInformationUse:** This function is used to query information about a specific user in the Security Account Manager (SAM) database. Hash-dumping programs access the SAM database in order to retrieve the hash of users’ login passwords.

**Send:** This function is used to send data to a remote machine. It is often used by malwares to send data to a remote command-and-control server.

**SetFileTime:** This function is used to modify the creation, access, or last modified time of a file. Malware often uses this function to conceal malicious activity.

**SetThreadContext:** This function is used to modify the context of a given thread. Some injection techniques use SetThreadContext.

**SetWindowsHookEx:** This function is used to set a hook function to be called whenever a certain event is called. Commonly used with keyloggers and spyware, this function also provides an easy way to load a DLL into all GUI processes on the system. This function is sometimes added by the compiler.

**SfcTerminateWatcherThread:** This function is used to disable Windows file protection and modify files that otherwise would be protected.

**ShellExecute:** This function is used to execute another program.

**StartServiceCtrlDispatcher:** This function is used by a service to connect the main thread of the process to the service control manager. Any process that runs as a service must call this function within 30 seconds of startup. Locating this function in malware will tell that the function should be run as a service.

**SuspendThread:** This function is used to suspend a thread so that it stops running. Malware will sometimes suspend a thread in order to modify it by performing code injection.

**System:** This function is used to run another program provided by some C runtime libraries. On Windows, this function serves as a wrapper function to CreateProcess.

**Thread32First/Thread32Next:** This function is used to iterate through the threads of a process. Injectors use these functions to find an appropriate thread into which to inject.

**Toolhelp32ReadProcessMemory:** This function is used to read the memory of a remote process.

**URLDownloadToFile:** This function is used to download a file from a web server and save it to disk. This function is popular with downloaders because it implements all the functionality of a downloader in one function call.

**VirtualAlloc/VirtualAllocEx:** This function is a memory-allocation routine that can allocate memory in a remote process. Malware sometimes uses VirtualAllocEx as part of process injection.

**VirtualProtect/VirtualProtectEx:** This function is used to change the protection on a region of memory. Malware may use this function to change a read-only section of memory to an executable.

**WideCharToMultiByte:** This function is used to convert a Unicode string into an ASCII string.

**WinExec:** This function is used to execute another program.

**WriteProcessMemory:** This function is used to write data to a remote process. Malware uses WriteProcessMemory as part of 
process injection.

**WSAStartup:** This function is used to initialize low-level network functionality. Finding calls to WSAStartup can often be an easy way to locate the start of network related functionality.

**VirtualFree:**

**VirtualLock:**

**ReadFile:** 

**WriteFile:** 

**ReOpenFile:**

**CloseHandle:**

**CreateThread:**

**SwitchToThread:**

**GetCurrentThread:**

**GetProcessIdOfThread:**

**GetThreadIPPendingFlag:**

**OpenThread:**

**WaitForSingleObject:**

**WaitForMultipleObjects:**

**GetProcessTimes:**

**GetThreadTimes:**

**GetEnvironmentVariable:**

**SetEnvironmentVariable:**

**GeneratteConsoleCtrlEvent:**

**TlsAlloc:**

**TlsFree:**

**TlsGetValue:**

**TlsSetValue:**

**InterlockedExchange:**

**EnterCriticalSection:**

**LeaveCriticalSection:**

**DeleteCriticalSection:**

**TryEnterCriticalSection:**

**InitializeCriticalSectionAndSpinCount:**

**InitializeSRWLock:**

**AcquireSRWLockExclusive:**

**ReleaseSRWLockExclusive:**

**AcquireSRWLockShared:**

**ReleaseSRWLockShared:**

**TryEnterSharedSRWLock:**

**TryEnterExclusiveSRWLock:**

**SleepConditionalVariableCS:**

**SleepConditionalVariableSRW:**

**WakeConditionalVariable:**

**WakeAllConditionalVariable:**

**ReleaseMutex:**

**CreateEvent:**

**CreateEventEx:**

**OpenEvent:**

**SetEvent:**

**ResetEvent:**

**PulseEvent:**

**SetFilePointer:**

**SetEndOfFile:**

**GetFileSizeEx:**

**FindClose:**

**GetFileInformationByHandle:**

**GetFullPathName:**

**GetTemFileName:**

**VirtualQuery:**

**ZwMapViewOfSection:** 

**ZwCreateSection:**

**ZwOpenSection:**

**NtQueryInformationToken/ZwQueryInformationToken:**

**GetFileTime:**

**GetFileAttributes:**

**LockFileEx:**

**RegEnumKeyEx:**

**RegCreateKeyEx:**

**RegEnumValue:**

**RegSetValueEx:**

**GetExceptionCode:**

**ExitThread:**

**ExitProcess:**

**OpenSCManagerA:**

**EnumServiceStatusA:**

**EnumDependentServicesA:**

**HeapAlloc:**

**HeapReAlloc:**

**HeapDestroy:**

**HeapFree:**

**HeapSetInformation:**

**HeapQueryInformation:**

**HeapCompact:**

**HeapValidate:**

**HeapWalk:**

**GetProcessHeaps:**

**CreateHeap:**

**HeapAlloc:**

**HeapFree:**

**DestroyHeap:**

**CallWindowProc:**

**StringCchPrintfA:**

**NtReadVirtualMemory:**

**NtWriteVirtualMemory:**


# NETWORKING API

**Socket:**

**Send:**

**Recv:**

**Bind:**

**Listen:**

**Accept:**

**Connect:**

**WSAStartup:**

**URLDownloadToFile:**

**InternetOpen:**

**InternetConnect:**

**InternetOpenUrlA:**

**InternetReadFile:**

**HttpOpenRequestA:**

**HttpSendRequestA:**

**HttpQueryInfoA:**

**InternetGetConnectState:**

# ANTI DEBUGGIND Tricks


**IsDebuggerPresent:** Calls the IsDebuggerPresent() API. This function is part of the Win32 Debugging API and it returns TRUE if a user mode debugger is present. Internally, it simply returns the value of the PEB->BeingDebugged flag.

**CheckRemoteDebuggerPresent:** CheckRemoteDebuggerPresent() is another Win32 Debugging API function; it can be used to check if a remote process is being debugged. However, we can also use this as another method for checking if our own process is being debugged. This API internally calls the NTDLL export NtQueryInformationProcess function with the SYSTEM_INFORMATION_CLASS set to 7 (ProcessDebugPort).

**BeingDebugged:** Checks if the BeingDebugged flag is set in the Process Environment Block (PEB). This is effectively the same code that IsDebuggerPresent() executes internally. The PEB pointer is fetched from DWORD FS:[0x30] on x86_32 and QWORD GS:[0x60] on x86_64.

**NtGlobalFlag:** NtGlobalFlag is a DWORD value inside the process PEB. This value contains many flags set by the OS that affects the way the process runs. When a process is being debugged, the flags FLG_HEAP_ENABLE_TAIL_CHECK (0x10), FLG_HEAP_ENABLE_FREE_CHECK (0x20), and FLG_HEAP_VALIDATE_PARAMETERS(0x40) are set for the process

If the 32-bit executable is being run on a 64-bit system, both the 32-bit and 64-bit PEBs are checked. The WoW64 PEB address is fetched via the WoW64 Thread Environment Block (TEB) at FS:[0x18]-0x2000.

**ProcessHeap (Flags):** Check if the Flags field of the ProcessHeap structure in the PEB has a value greater than 2.

**ProcessHeap (ForceFlags):** Check if the ForceFlags field of the ProcessHeap structure in the PEB has a value greater than 0.

**NtQueryInformationProcess (ProcessDebugPort):** Calls the NtQueryInformationProcess API with ProcessDebugPort (0x07) information class.

The test returns true if the operation succeeds and the returned value is nonzero.

**NtQueryInformationProcess (ProcessDebugObject):** Calls the NtQueryInformationProcess API with ProcessDebugObjectHandle (0x1E) information class.

The test returns true if the operation succeeds and the returned value is nonzero.

**NtQueryInformationProcess (ProcessDebugFlags):** Calls the NtQueryInformationProcess API with ProcessDebugFlags (0x1F) information class.

The test returns true if the operation succeeds and the returned value is nonzero.

**NtSetInformationThread (HideThreadFromDebugger):** Calls the NtSetInformationThread API with the ThreadHideFromDebugger (0x11) information class.

The API is first called with a bogus class length value to catch out hooks that ignore the information data and length - if the call succeeds we know it is hooked. Next it is called with a bogus thread handle - if the call succeeds we know it is hooked. Finally the API is called properly, and on Windows Vista and later the flag is checked using the NtQueryInformationThread API.

**NtQueryObject (ObjectTypeInformation):**


**NtQueryObject (ObjectAllTypesInformation):**

**CloseHanlde (NtClose) Invalide Handle:** One well-known technique for detecting a debugger involves the kernel32 CloseHandle() function. If an invalid handle is passed to the kernel32CloseHandle() function (or directly to the ntdll NtClose() function, or the kernel32FindVolumeMountPointClose() function on Windows 2000and later (which simply calls the kernel32CloseHandle() function)), and a debugger is present,then an EXCEPTION_INVALID_HANDLE (0xC0000008)exception will be raised. This exception can be intercepted by an exception handler, and is an indication that a debugger is running.

**SetHandleInformation (Protected Handle):**

**UnhandledExceptionFilter:** When an exception occurs, and no registered Exception Handlers exist (neither Structured nor Vectored), or if none of the registered handlers handles the exception, then the kernel32 UnhandledExceptionFilter() function will be called as a last resort. If no debugger is present (which is determined by calling the ntdll NtQueryInformationProcess() function with the ProcessDebugPort class), then the handler will be called that was registered by the kernel32 SetUnhandledExceptionFilter() function. If a debugger is present, then that call will not be reached. Instead, the exception will be passed to the debugger. The function determines the presence of a debugger by calling the ntdll NtQueryInformationProcess function with the ProcessDebugPort class. The missing exception can be used to infer the presence of the debugger.

**OutputDebugString (GetLastError()):** The kernel32 OutputDebugString() function can demonstrate different behaviour, depending on the version of Windows, and whether or not a debugger is present. The most obvious difference in be haviourthat the kernel32 GetLastError() function will return zero if a debugger is present, and non-zero if a debugger is not present. However, this applies only to Windows NT/2000/XP. On Windows Vista and later, the error code is unchanged in all cases.

The reason why it worked was that Windows attempted to open a mapping to an object called "DBWIN_BUFFER". When it failed, the error code is set. Following that was a call to the ntdll DbgPrint() function. As noted above, if a debugger is present, the exception might be consumed by the debugger, resulting in the error code being cleared. If no debugger is present, then the exception would be consumed by Windows, and the error code would remain. However, in Windows Vista and later, the error code is restored to the value that it had prior to the kernel32 OutputDebugString() function being called. It is not cleared explicitly,resulting in this detection technique becoming completely unreliable.

The function is perhaps most well-known because of a bug in OllyDbg v1.10 that results from its use.OllyDbg passes user-defined data directly to the msvcrt _vsprintf() function. Those data can contain string-formatting tokens. A specific token in a specific position will cause the function to attempt to access memory using one of the passed parameters. A number of variations of the attack exist, all of which are essentially randomly chosen token combinations that happen to work. However, all that is required is three tokens. The first two tokens are entirely arbitrary. The third token must be a "%s". This is because the _vsprintf() function calls the __vprinter() function, and passes a zero as the fourth parameter. The fourth parameter is accessed by the third token, if the "%s" is used there. The result is a null-pointer access, and a crash. The bug cannot be exploited to execute arbitrary code.

**Hardware Breakpoints (SEH / GetThreadContext):** When an exception occurs, Windows creates a context structure to pass to the exception handler. The structure will contain the values of the general registers, selectors, control registers, and the debug registers. If a debugger is present and passes the exception to the debuggee with hardware breakpoints in use, then the debug registers will contain values that reveal the presence of the debugger.

**Software Breakpoints (INT3 / 0xCC):**

**Memory Breakpoints (PAGE_GUARD):** The kernel32 VirtualProtect() function (or thekernel32 VirtualProtectEx() function, or then ntdll NtProtectVirtualMemory() function) can be used to allocate "guard" pages. Guard pages are pages that trigger an exception the first time that they are accessed. They are commonly placed at the bottom of a stack, to intercept a potential problem before it becomes unrecoverable. Guard pages can also be used to detect a debugger. The two preliminary steps are to register an exception handler, and to allocate the guard page. The order of these steps is not important. Typically, the page is allocated initially as writable and executable, to allow some content to be placed in it, though this is entirely optional. After filling the page, the page protections are altered to convert the page to a guard page. The next step is to attempt to execute something from the guard page. This should result in an EXCEPTION_GUARD_PAGE (0x80000001) exception being received by the exception handler. However,if a debugger is present, then the debugger might intercept the exception and allow the execution to continue. This behaviour is known to occur in OllyDbg.

**Interrupt 0x2d:** The interrupt 0x2D is a special case. When it is executed, Windows uses the current EIP register value as the exception address, and then it increments by one the EIP register value. However, Windows also examines the value in the EAX register to determine how to adjust the exception address. If the EAX register has the value of 1, 3, or 4 on all versions of Windows, or the value 5 on Windows Vista and later,then Windows will increase by one the exception address. Finally, it issues an EXCEPTION_BREAKPOINT(0x80000003) exception if a debugger is present. The interrupt 0x2D behaviour can cause trouble for debuggers. The problem is that some debuggers might use the EIP register value as the address from which to resume, while other debuggers might use the exception address as the address from which to resume.This can result in a single-byte instruction being skipped, or the execution of a completely different instruction because the first byte is missing. These behaviours can be used to infer the presence of the debugger.

**Interrupt 1:**

**Parent Process (Explorer.exe):** Users typically execute applications by clicking on an icon which is displayed by the shell process(Explorer.exe). As a result, the parent process of the executed process will be Explorer.exe. Of course, if the application is executed from the command-line, then the parent process of the executed process will be the command window process.Executing an application by debugging it will cause the parent process of the executed process to be the debugger process.Executing applications from the command-line can cause problems for certain applications, because they expect the parent process to be Explorer.exe. Some applications check the parent process name,expecting it to be "Explorer.exe". Some applications compare the parent process ID against that of Explorer.exe. A mismatch in either case might result in the application thinking that it is being debugged. At this point. The simplest way to obtain the process ID of Explorer.exe is by calling the user32 GetShellWindow() and user32 GetWindowThreadProcessId() functions. That leaves the process ID and name of the parent process of the current process, which can be obtained by calling the ntdll NtQueryInformationProcess() function with the ProcessBasicInformation class.

**SeDebugPrivilege (Csrss.exe):** The kernel32 OpenProcess() function (or the ntdll NtOpenProcess() function) has at times been claimed to detect the presence of a debugger when used on the "csrss.exe" process. This is in correct. While it is true that the function call will succeed in the presence of some debuggers, this is due to aside-effect of the debugger's behaviour(specifically, acquiring the debug privilege), and not due to the debugger itself (this should be obvious since the function call does not succeed when used with certain debuggers). All it reveals is that the user account for the process is a member of the administrators group and it has the debug privilege. The reason is that the success or failure of the function call is limited only by the process privilege level. If the user account of the process is a member of the administrators group and has the debug privilege, then the function call will succeed; if not, then not. It is not sufficient fora standard user to acquire the debug privilege, nor can an administrator call the function successfully without it. The process ID of the csrss.exe process can be acquired by the ntdll CsrGetProcessId() function on Windows XP and later.

**NtYieldExecution / SwitchToThread:**

**TLS callbacks:**

**Process jobs:**

**Memory write watching:**

