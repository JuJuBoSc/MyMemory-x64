using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using MyMemory_x64.Utils;

namespace MyMemory_x64.Natives
{
    /// <summary>
    /// Provide access to system call
    /// Supported windows versions :
    ///     - Windows 7 x64
    ///     - Windows 7 SP1 x64
    ///     - Windows 8.0 x64
    ///     - Windows 8.1 x64
    ///     - Windows 10.0 x64
    /// </summary>
    public static unsafe class Syscall
    {
        
        private struct SyscallsId
        {
            internal int NtOpenProcess;
            internal int NtOpenThread;
            internal int NtReadVirtualMemory;
            internal int NtWriteVirtualMemory;
            internal int NtProtectVirtualMemory;
            internal int NtAllocateVirtualMemory;
            internal int NtFreeVirtualMemory;
            internal int NtClose;
            internal int NtResumeThread;
            internal int NtSuspendThread;
            internal int NtSetEvent;
            internal int NtWaitForSingleObject;
            internal int NtOpenEvent;
            internal int NtSetContextThread;
            internal int NtGetContextThread;
            internal int NtQueryInformationProcess;
            internal int NtQueryVirtualMemory;
            internal int NtQueryInformationThread;
        }

        #region Syscall Dictionnary

        private static readonly Dictionary<OsChecker.EWindowsVersion, SyscallsId> Syscalls = new Dictionary<OsChecker.EWindowsVersion, SyscallsId>()
        {
            {
                OsChecker.EWindowsVersion.Windows10_0,
                new SyscallsId()
                {
                    NtReadVirtualMemory = 0x3F,
                    NtWriteVirtualMemory = 0x3A,
                    NtOpenProcess = 0x26,
                    NtOpenThread = 0x119,
                    NtProtectVirtualMemory = 0x50,
                    NtAllocateVirtualMemory = 0x18,
                    NtFreeVirtualMemory = 0x1E,
                    NtClose = 0xF,
                    NtResumeThread = 0x52,
                    NtSuspendThread = 0x1A0,
                    NtSetEvent = 0xE,
                    NtWaitForSingleObject = 0x4,
                    NtOpenEvent = 0x40,
                    NtSetContextThread = 0x16F,
                    NtGetContextThread = 0xE3,
                    NtQueryInformationProcess = 0x19,
                    NtQueryVirtualMemory = 0x23,
                    NtQueryInformationThread = 0x25,
                }
            },
            {
                OsChecker.EWindowsVersion.Windows8_1,
                new SyscallsId()
                {
                    NtReadVirtualMemory = 0x3E,
                    NtWriteVirtualMemory = 0x39,
                    NtOpenProcess = 0x25,
                    NtProtectVirtualMemory = 0x4F,
                    NtAllocateVirtualMemory = 0x17,
                    NtFreeVirtualMemory = 0x1D,
                    NtClose = 0xE,
                    NtOpenThread = 0x113,
                    NtResumeThread = 0x51,
                    NtSuspendThread = 0x198,
                    NtSetEvent = 0xD,
                    NtWaitForSingleObject = 0x3,
                    NtOpenEvent = 0x3F,
                    NtSetContextThread = 0x168,
                    NtGetContextThread = 0xE0,
                    NtQueryInformationProcess = 0x18,
                    NtQueryVirtualMemory = 0x22,
                    NtQueryInformationThread = 0x24,
                }
            },
            {
                OsChecker.EWindowsVersion.Windows8_0,
                new SyscallsId()
                {
                    NtReadVirtualMemory = 0x3D,
                    NtWriteVirtualMemory = 0x38,
                    NtOpenProcess = 0x24,
                    NtProtectVirtualMemory = 0x4E,
                    NtAllocateVirtualMemory = 0x16,
                    NtFreeVirtualMemory = 0x1C,
                    NtClose = 0xD,
                    NtOpenThread = 0x110,
                    NtResumeThread = 0x50,
                    NtSuspendThread = 0x193,
                    NtSetEvent = 0xC,
                    NtWaitForSingleObject = 0x2,
                    NtOpenEvent = 0x3E,
                    NtSetContextThread = 0x165,
                    NtGetContextThread = 0xDD,
                    NtQueryInformationProcess = 0x17,
                    NtQueryVirtualMemory = 0x21,
                    NtQueryInformationThread = 0x23,
                }
            },
            {
                OsChecker.EWindowsVersion.Windows7_SP1,
                new SyscallsId()
                {
                    NtReadVirtualMemory = 0x3C,
                    NtWriteVirtualMemory = 0x37,
                    NtOpenProcess = 0x23,
                    NtProtectVirtualMemory = 0x4D,
                    NtAllocateVirtualMemory = 0x15,
                    NtFreeVirtualMemory = 0x1B,
                    NtClose = 0xC,
                    NtOpenThread = 0xFE,
                    NtResumeThread = 0x4F,
                    NtSuspendThread = 0x17B,
                    NtSetEvent = 0xB,
                    NtWaitForSingleObject = 1,
                    NtOpenEvent = 0x3D,
                    NtSetContextThread = 0x150,
                    NtGetContextThread = 0xCA,
                    NtQueryInformationProcess = 0x16,
                    NtQueryVirtualMemory = 0x20,
                    NtQueryInformationThread = 0x22,
                }
            },
            {
                OsChecker.EWindowsVersion.Windows7_SP0,
                new SyscallsId()
                {
                    NtReadVirtualMemory = 0x3C,
                    NtWriteVirtualMemory = 0x37,
                    NtOpenProcess = 0x23,
                    NtProtectVirtualMemory = 0x4D,
                    NtAllocateVirtualMemory = 0x15,
                    NtFreeVirtualMemory = 0x1B,
                    NtClose = 0xC,
                    NtOpenThread = 0xFE,
                    NtResumeThread = 0x4F,
                    NtSuspendThread = 0x17B,
                    NtSetEvent = 0xB,
                    NtWaitForSingleObject = 1,
                    NtOpenEvent = 0x3D,
                    NtSetContextThread = 0x150,
                    NtGetContextThread = 0xCA,
                    NtQueryInformationProcess = 0x16,
                    NtQueryVirtualMemory = 0x20,
                    NtQueryInformationThread = 0x22,
                }
            },
        };

        #endregion

        #region Syscall Delegates

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtOpenProcessDelegate(ref IntPtr hProcess, Enumerations.ProcessAccessFlags desiredAccess, ref Structures.OBJECT_ATTRIBUTES objectAttributes, ref Structures.CLIENT_ID clientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtOpenThreadDelegate(ref IntPtr hProcess, Enumerations.ThreadAccessFlags desiredAccess, ref Structures.OBJECT_ATTRIBUTES objectAttributes, ref Structures.CLIENT_ID clientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtReadVirtualMemoryDelegate(IntPtr hProcess, IntPtr lpAddress, void* lpBuffer, int nSize, IntPtr lpBytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtWriteVirtualMemoryDelegate(IntPtr hProcess, IntPtr lpAddress, void* lpBuffer, int nSize, IntPtr lpBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtAllocateVirtualMemoryDelegate(IntPtr hProcess, void* lppAddress, int dwZeroBits, void* dwRegionSize, uint allocationType, uint protectionFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtProtectVirtualMemorDelegate(IntPtr hProcess, void* lppAddress, void* pNumberOfBytesToProtect, Enumerations.MemoryProtectionFlags newAccessProtection, out Enumerations.MemoryProtectionFlags pOldAccessProtection);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtFreeVirtualMemoryDelegate(IntPtr hProcess, void* lppAddress, void* pDwRegionSize, Enumerations.FreeType freeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtCloseDelegate(IntPtr hHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtQueryInformationProcessDelegate(IntPtr hProcess, Enumerations.ProcessInformationClass processInformationClass, ref Structures.PROCESS_BASIC_INFORMATION processBasicInformation, int processInformationLength, void* pReturnLength);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtSuspendThreadDelegate(IntPtr hThread, IntPtr pPreviousSuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.Ntstatus NtResumeThreadDelegate(IntPtr hThread, IntPtr pPreviousSuspendCount);

        private static readonly NtOpenProcessDelegate fNtOpenProcess;
        private static readonly NtReadVirtualMemoryDelegate fNtReadVirtualMemory;
        private static readonly NtWriteVirtualMemoryDelegate fNtWriteVirtualMemory;
        private static readonly NtAllocateVirtualMemoryDelegate fNtAllocateVirtualMemory;
        private static readonly NtProtectVirtualMemorDelegate fNtProtectVirtualMemory;
        private static readonly NtFreeVirtualMemoryDelegate fNtFreeVirtualMemory;
        private static readonly NtCloseDelegate fNtClose;
        private static readonly NtQueryInformationProcessDelegate fNtQueryInformationProcess;
        private static readonly NtOpenThreadDelegate fNtOpenThread;
        private static readonly NtSuspendThreadDelegate fNtSuspendThread;
        private static readonly NtResumeThreadDelegate fNtResumeThread;

        #endregion

        static Syscall()
        {
            
            var windowsVersion = OsChecker.GetWindowsVersion();

            if (windowsVersion == OsChecker.EWindowsVersion.Unknown || !Syscalls.ContainsKey(windowsVersion))
                throw new Exception("Unsupported operating system !");

            fNtOpenProcess = GetDelegateForSyscall<NtOpenProcessDelegate>(Syscalls[windowsVersion].NtOpenProcess);
            fNtReadVirtualMemory = GetDelegateForSyscall<NtReadVirtualMemoryDelegate>(Syscalls[windowsVersion].NtReadVirtualMemory);
            fNtWriteVirtualMemory = GetDelegateForSyscall<NtWriteVirtualMemoryDelegate>(Syscalls[windowsVersion].NtWriteVirtualMemory);
            fNtAllocateVirtualMemory = GetDelegateForSyscall<NtAllocateVirtualMemoryDelegate>(Syscalls[windowsVersion].NtAllocateVirtualMemory);
            fNtProtectVirtualMemory = GetDelegateForSyscall<NtProtectVirtualMemorDelegate>(Syscalls[windowsVersion].NtProtectVirtualMemory);
            fNtFreeVirtualMemory = GetDelegateForSyscall<NtFreeVirtualMemoryDelegate>(Syscalls[windowsVersion].NtFreeVirtualMemory);
            fNtClose = GetDelegateForSyscall<NtCloseDelegate>(Syscalls[windowsVersion].NtClose);
            fNtQueryInformationProcess = GetDelegateForSyscall<NtQueryInformationProcessDelegate>(Syscalls[windowsVersion].NtQueryInformationProcess);
            fNtOpenThread = GetDelegateForSyscall<NtOpenThreadDelegate>(Syscalls[windowsVersion].NtOpenThread);
            fNtSuspendThread = GetDelegateForSyscall<NtSuspendThreadDelegate>(Syscalls[windowsVersion].NtSuspendThread);
            fNtResumeThread = GetDelegateForSyscall<NtResumeThreadDelegate>(Syscalls[windowsVersion].NtResumeThread);

        }

        /// <summary>
        /// Generate a delegate for calling system function
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="syscallId"></param>
        /// <returns></returns>
        private static T GetDelegateForSyscall<T>(int syscallId) where T : class
        {

            if (!typeof(T).IsSubclassOf(typeof(Delegate)))
                throw new InvalidOperationException(typeof(T).Name + " is not a delegate type");

            IntPtr pFunction = Methods.VirtualAlloc(IntPtr.Zero, 1000, Enumerations.AllocationType.Reserve | Enumerations.AllocationType.Commit, Enumerations.MemoryProtectionFlags.ExecuteReadWrite);
            Delegate tDelegate = Marshal.GetDelegateForFunctionPointer(pFunction, typeof(T)); // Dummy delegate

            var returnType = tDelegate.Method.ReturnType;
            var parametersTypes = tDelegate.Method.GetParameters().Select(x => x.ParameterType).ToArray();

            List<byte> bytecodes = new List<byte>();

            bytecodes.AddRange(new byte[] { 0x4C, 0x8B, 0xD1 }); // mov r10, rcx
            bytecodes.Add(0xB8); bytecodes.AddRange(BitConverter.GetBytes(syscallId)); // mov eax, syscallId
            bytecodes.AddRange(new byte[] { 0x0F, 0x05 }); // syscall
            bytecodes.Add(0xC3); // retn

            Marshal.Copy(bytecodes.ToArray(), 0, pFunction, bytecodes.Count);

            var method = new DynamicMethod(string.Empty, returnType, parametersTypes, returnType.Module);
            var gen = method.GetILGenerator();
            for (int i = 0; i < parametersTypes.Length; i++)
            {
                switch (i)
                {
                    case 0:
                        gen.Emit(OpCodes.Ldarg_0);
                        break;
                    case 1:
                        gen.Emit(OpCodes.Ldarg_1);
                        break;
                    case 2:
                        gen.Emit(OpCodes.Ldarg_2);
                        break;
                    case 3:
                        gen.Emit(OpCodes.Ldarg_3);
                        break;
                    default:
                        gen.Emit(OpCodes.Ldarg, i);
                        break;
                }
            }
            gen.Emit(OpCodes.Ldc_I8, pFunction.ToInt64());
            gen.Emit(OpCodes.Conv_I);
            gen.EmitCalli(OpCodes.Calli, CallingConvention.StdCall, returnType, parametersTypes);
            gen.Emit(OpCodes.Ret);

            return method.CreateDelegate(typeof(T)) as T;

        }

        /// <summary>
        /// Open remote process for manipulation, return the process handle if successed
        /// </summary>
        public static IntPtr OpenProcess(Enumerations.ProcessAccessFlags access, uint processId)
        {
            IntPtr hProcess = IntPtr.Zero;
            var oa = new Structures.OBJECT_ATTRIBUTES(null, 0);
            var clientId = new Structures.CLIENT_ID() { UniqueProcess = new IntPtr(processId), UniqueThread = IntPtr.Zero };
            fNtOpenProcess(ref hProcess, access, ref oa, ref clientId);
            oa.Dispose();
            return hProcess;
        }

        /// <summary>
        /// Open thread for manipulation, return the thread handle if successed
        /// </summary>
        public static IntPtr OpenThread(Enumerations.ThreadAccessFlags access, uint threadId)
        {
            IntPtr hProcess = IntPtr.Zero;
            var oa = new Structures.OBJECT_ATTRIBUTES(null, 0);
            var clientId = new Structures.CLIENT_ID() { UniqueProcess = IntPtr.Zero, UniqueThread = new IntPtr(threadId) };
            fNtOpenThread(ref hProcess, access, ref oa, ref clientId);
            oa.Dispose();
            return hProcess;
        }

        /// <summary>
        /// Read memory in the remote process
        /// </summary>
        /// <param name="hProcess"></param>
        /// <param name="lpAddress"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nSize"></param>
        /// <returns></returns>
        public static bool ReadVirtualMemory(IntPtr hProcess, IntPtr lpAddress, void* lpBuffer, int nSize)
        {
            return fNtReadVirtualMemory(hProcess, lpAddress, lpBuffer, nSize, IntPtr.Zero) == Enumerations.Ntstatus.Success;
        }

        /// <summary>
        /// Write memory in the remote process
        /// </summary>
        /// <param name="hProcess"></param>
        /// <param name="lpAddress"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nSize"></param>
        /// <returns></returns>
        public static bool WriteVirtualMemory(IntPtr hProcess, IntPtr lpAddress, void* lpBuffer, int nSize)
        {
            return fNtWriteVirtualMemory(hProcess, lpAddress, lpBuffer, nSize, IntPtr.Zero) == Enumerations.Ntstatus.Success;
        }

        /// <summary>
        /// Allocate memory in the remote process
        /// </summary>
        /// <param name="hProcess"></param>
        /// <param name="dwRegionSize"></param>
        /// <param name="allocationType"></param>
        /// <param name="protectionFlags"></param>
        /// <returns></returns>
        public static IntPtr AllocateVirtualMemory(IntPtr hProcess, int dwRegionSize, Enumerations.AllocationType allocationType, Enumerations.MemoryProtectionFlags protectionFlags)
        {
            IntPtr lpAddress = new IntPtr(0);
            fNtAllocateVirtualMemory(hProcess, &lpAddress, 0, &dwRegionSize, (uint)allocationType, (uint)protectionFlags);
            return lpAddress;
        }

        /// <summary>
        /// Change memory protection in the remote process
        /// </summary>
        /// <param name="hProcess"></param>
        /// <param name="lpAddress"></param>
        /// <param name="numberOfBytesToProtect"></param>
        /// <param name="newAccessProtection"></param>
        /// <param name="oldAccessProtection"></param>
        /// <returns></returns>
        public static bool ProtectVirtualMemory(IntPtr hProcess, IntPtr lpAddress, int numberOfBytesToProtect, Enumerations.MemoryProtectionFlags newAccessProtection, out Enumerations.MemoryProtectionFlags oldAccessProtection)
        {
            return fNtProtectVirtualMemory(hProcess, &lpAddress, &numberOfBytesToProtect, newAccessProtection, out oldAccessProtection) == Enumerations.Ntstatus.Success;
        }
        
        /// <summary>
        /// Free memory in the remote process
        /// </summary>
        /// <param name="hProcess"></param>
        /// <param name="lpAddress"></param>
        /// <param name="dwRegionSize"></param>
        /// <param name="freeType"></param>
        /// <returns></returns>
        public static bool FreeVirtualMemory(IntPtr hProcess, IntPtr lpAddress, int dwRegionSize, Enumerations.FreeType freeType)
        {
            return fNtFreeVirtualMemory(hProcess, &lpAddress, &dwRegionSize, freeType) == Enumerations.Ntstatus.Success;
        }

        /// <summary>
        /// Close the given handle
        /// </summary>
        /// <param name="hHandle"></param>
        /// <returns></returns>
        public static bool CloseHandle(IntPtr hHandle)
        {
            return fNtClose(hHandle) == Enumerations.Ntstatus.Success;
        }

        /// <summary>
        /// Get the basic process information for the given handle
        /// </summary>
        /// <param name="hProcess"></param>
        /// <param name="processBasicInformation"></param>
        /// <returns></returns>
        public static bool QueryInformationProcess(IntPtr hProcess, ref Structures.PROCESS_BASIC_INFORMATION processBasicInformation)
        {
            return fNtQueryInformationProcess(hProcess, Enumerations.ProcessInformationClass.ProcessBasicInformation, ref processBasicInformation, MarshalCache<Structures.PROCESS_BASIC_INFORMATION>.Size, (void*)0) == Enumerations.Ntstatus.Success;
        }

        /// <summary>
        /// Suspend a thread for the given handle
        /// </summary>
        /// <param name="hThread"></param>
        /// <returns></returns>
        public static bool SuspendThread(IntPtr hThread)
        {
            return fNtSuspendThread(hThread, IntPtr.Zero) == Enumerations.Ntstatus.Success;
        }

        /// <summary>
        /// Resumt a thread for the given handle
        /// </summary>
        /// <param name="hThread"></param>
        /// <returns></returns>
        public static bool ResumeThread(IntPtr hThread)
        {
            return fNtResumeThread(hThread, IntPtr.Zero) == Enumerations.Ntstatus.Success;
        }

    }
}
