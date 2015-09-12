using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using MyMemory_x64.Natives;
using MyMemory_x64.Memory;
using MyMemory_x64.Modules;
using MyMemory_x64.Threads;
using MyMemory_x64.Utils;

namespace MyMemory_x64
{
    public unsafe class RemoteProcess : IDisposable
    {

        static RemoteProcess()
        {
            if (IntPtr.Size != 8) throw new Exception("MyMemory-x64 must run in x64 mode !");
            System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(Natives.Syscall).TypeHandle);
        }

        /// <summary>
        /// The base address of the attached process
        /// </summary>
        public IntPtr ImageBase { get; private set; } = IntPtr.Zero;

        /// <summary>
        /// The handle of the attached process
        /// </summary>
        public IntPtr ProcessHandle { get; private set; } = IntPtr.Zero;

        /// <summary>
        /// The process id of the attached process
        /// </summary>
        public uint ProcessId { get; private set; }

        /// <summary>
        /// The process environment block of the attached
        /// </summary>
        public RemoteProcessEnvironmentBlock ProcessEnvironmentBlock { get; private set; }

        /// <summary>
        /// Open process for manipulation
        /// </summary>
        public bool Open(uint processId)
        {
            ProcessHandle = Syscall.OpenProcess(Natives.Enumerations.ProcessAccessFlags.ProcessAllAccess, processId);

            if (ProcessHandle == IntPtr.Zero)
                return false;

            var processInformation = new Structures.PROCESS_BASIC_INFORMATION();
            if (Syscall.QueryInformationProcess(ProcessHandle, ref processInformation))
                ProcessEnvironmentBlock = new RemoteProcessEnvironmentBlock(this, processInformation.PebBaseAddress);
            else
                return false;

            ImageBase = ProcessEnvironmentBlock.ImageBase;

            ProcessId = processId;
            return true;
        }

        /// <summary>
        /// Dispose and close all opened handles
        /// </summary>
        public void Dispose()
        {

            if (ProcessHandle != IntPtr.Zero)
            {
                Syscall.CloseHandle(ProcessHandle);
                ProcessHandle = IntPtr.Zero;
            }

            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Read memory in the remote process
        /// </summary>
        public T Read<T>(IntPtr lpAddress)
        {
            var size = Utils.MarshalCache<T>.Size;
            switch (Utils.MarshalCache<T>.TypeCode)
            {
                case TypeCode.Int32:
                {
                    int ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.UInt32:
                {
                    uint ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.Boolean:
                {
                    bool ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.Byte:
                {
                    byte ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.Char:
                {
                    char ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.Decimal:
                {
                    decimal ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.Double:
                {
                    double ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.Int16:
                {
                    short ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.SByte:
                {
                    sbyte ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.Single:
                {
                    float ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.UInt16:
                {
                    ushort ret;
                    Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, &ret, size);
                    return (T) (object) ret;
                }
                case TypeCode.Object:
                    if (!Utils.MarshalCache<T>.TypeRequiresMarshal)
                    {
                        var o = default(T);
                        Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, Utils.MarshalCache<T>.GetUnsafePtr(ref o), size);
                        return o;
                    }
                    var bBuffer = new byte[size];
                    fixed (void* b = bBuffer)
                    {
                        Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, b, size);
                        return (T) Marshal.PtrToStructure(new IntPtr(b), typeof (T));
                    }
                default:
                    return default(T);
            }
        }

        /// <summary>
        /// Write memory in the remote process
        /// </summary>
        public bool Write<T>(IntPtr lpAddress, T value)
        {
            var size = Utils.MarshalCache<T>.Size;
            using (ProtectMemory(lpAddress, size, Natives.Enumerations.MemoryProtectionFlags.ExecuteReadWrite))
            {
                switch (Utils.MarshalCache<T>.TypeCode)
                {
                    case TypeCode.Int32:
                    {
                        int obj = (int) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.UInt32:
                    {
                        uint obj = (uint) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.Boolean:
                    {
                        bool obj = (bool) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.Byte:
                    {
                        byte obj = (byte) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.Char:
                    {
                        char obj = (char) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.Decimal:
                    {
                        decimal obj = (decimal) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.Double:
                    {
                        double obj = (double) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.Int16:
                    {
                        short obj = (short) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.SByte:
                    {
                        sbyte obj = (sbyte) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.Single:
                    {
                        float obj = (float) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.UInt16:
                    {
                        ushort obj = (ushort) (object) (value);
                        return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, &obj, size);
                    }
                    case TypeCode.Object:
                        if (!Utils.MarshalCache<T>.TypeRequiresMarshal)
                        {
                            return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, Utils.MarshalCache<T>.GetUnsafePtr(ref value), size);
                        }
                        var hObj = Marshal.AllocHGlobal(size);
                        Marshal.StructureToPtr(value, hObj, false);
                        bool writeResult = Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, hObj.ToPointer(), size);
                        Marshal.FreeHGlobal(hObj);
                        return writeResult;
                    default:
                        return false;
                }
            }
        }

        /// <summary>
        /// Read bytes in the remote process
        /// </summary>
        /// <param name="lpAddress"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public byte[] ReadBytes(IntPtr lpAddress, int size)
        {
            var bBuffer = new byte[size];
            fixed (void* b = bBuffer)
            {
                Natives.Syscall.ReadVirtualMemory(ProcessHandle, lpAddress, b, size);
            }
            return bBuffer;
        }

        /// <summary>
        /// Write bytes in the remote process
        /// </summary>
        /// <param name="lpAddress"></param>
        /// <param name="bBuffer"></param>
        /// <returns></returns>
        public bool WriteBytes(IntPtr lpAddress, byte[] bBuffer)
        {
            using (ProtectMemory(lpAddress, bBuffer.Length, Natives.Enumerations.MemoryProtectionFlags.ExecuteReadWrite))
            {
                fixed (void* b = bBuffer)
                {
                    return Natives.Syscall.WriteVirtualMemory(ProcessHandle, lpAddress, b, bBuffer.Length);
                }
            }
        }

        /// <summary>
        ///     Read a string in the remote process
        /// </summary>
        /// <param name="address"></param>
        /// <param name="encoding"></param>
        /// <param name="maxLength"></param>
        /// <returns></returns>
        public string ReadString(IntPtr lpAddress, Encoding encoding = null, int maxLength = 128)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            var buffer = ReadBytes(lpAddress, maxLength * encoding.GetByteCount("a"));
            var ret = encoding.GetString(buffer);

            int nullCharIdx = ret.IndexOf('\0');
            if (nullCharIdx != -1)
                ret = ret.Remove(nullCharIdx);

            return ret;
        }

        /// <summary>
        ///     Write a string in the remote process
        /// </summary>
        /// <param name="address"></param>
        /// <param name="value"></param>
        /// <param name="encoding"></param>
        /// <param name="relative"></param>
        /// <returns></returns>
        public bool WriteString(IntPtr lpAddress, string value, Encoding encoding)
        {
            if (value.Length == 0)
                return true;

            if (value[value.Length - 1] != '\0')
                value += '\0';

            return WriteBytes(lpAddress, encoding.GetBytes(value));
        }

        /// <summary>
        /// Change the memory protection and return a RemoteMemoryProtection object
        /// </summary>
        /// <param name="lpAddress"></param>
        /// <param name="size"></param>
        /// <param name="newProtection"></param>
        /// <returns></returns>
        public RemoteMemoryProtection ProtectMemory(IntPtr lpAddress, int size, Natives.Enumerations.MemoryProtectionFlags newProtection)
        {
            return new RemoteMemoryProtection(this, lpAddress, size, newProtection);
        }

        /// <summary>
        /// Allocate memory and return a RemoteAllocatedMemory object
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public RemoteAllocatedMemory AllocateMemory(int size)
        {
            return new RemoteAllocatedMemory(this, Syscall.AllocateVirtualMemory(ProcessHandle, size, Enumerations.AllocationType.Commit | Enumerations.AllocationType.Reserve, Enumerations.MemoryProtectionFlags.ExecuteReadWrite), size);
        }

        /// <summary>
        /// Get modules loaded in the remote process
        /// </summary>
        public IEnumerable<RemoteModule> Modules => ProcessEnvironmentBlock.GetModules().Select(moduleInfo => new RemoteModule(this, moduleInfo));

        /// <summary>
        /// Get a remote module by it's name
        /// </summary>
        /// <param name="moduleName"></param>
        /// <returns></returns>
        public RemoteModule this[string moduleName] => GetModule(moduleName);

        /// <summary>
        /// Get a remote module by it's name
        /// </summary>
        /// <param name="moduleName"></param>
        /// <returns></returns>
        public RemoteModule GetModule(string moduleName) => new RemoteModule(this, ProcessEnvironmentBlock.GetModule(moduleName));

        /// <summary>
        /// Get threads in the remote process
        /// </summary>
        public IEnumerable<RemoteThread> Threads
        {
            get
            {

                var te = new Structures.THREADENTRY32 { dwSize = MarshalCache<Structures.THREADENTRY32>.SizeU };

                var hSnapshot = Methods.CreateToolhelp32Snapshot(Enumerations.SnapshotFlags.Thread, 0);

                if (hSnapshot == IntPtr.Zero)
                    yield break;
                
                if (Methods.Thread32First(hSnapshot, ref te))
                {
                    do
                    {
                        if (te.th32OwnerProcessID == ProcessId)
                        {
                            yield return new RemoteThread(this, te.th32ThreadID);
                        }
                    }
                    while (Methods.Thread32Next(hSnapshot, out te));
                }

                Syscall.CloseHandle(hSnapshot);

            }
        } 

    }
}
