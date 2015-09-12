# MyMemory-x64
.NET remote process manipulation library for x64.

# Supported systems
 - Windows 7 x64
 - Windows 7 SP1 x64
 - Windows 8.0 x64
 - Windows 8.1 x64
 - Windows 10 x64

> **Note :** MyMemory is using system call, this mean the application **MUST** be running in x64 mode or it will fail miserably.
> I'm doing that because some games used to hook NtOpenProcess from user-mode and that bypassed it, also because learning how to do syscall manually from C# was fun.

#How to use it

Simple make a new instance of **MyMemory.RemoteProcess** and call **RemoteProcess.Open(int processId)** :

    var process = new MyMemory.RemoteProcess();
    bool processOpened = process.Open(1234); // adjust process id

Reading memory :

    var result = process.Read<int>(new IntPtr(0xDEADBEEF));

Writing memory :

    var writeSuccess = process.Write<int>(new IntPtr(0xDEADBEEF), 1234);

# Credits
- Apoc for it's MarshalCache class and many clean win32 implementation.
- Cypher for being awesome and helped me with many undocumented stuff.
- ZenLulz for good implementation in it's MemorySharp project that gave me many ideas.