using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MyMemory_x64.Natives
{
    public static class Structures
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB
        {
            public byte InheritedAddressSpace;
            public byte ReadImageFileExecOptions;
            public byte BeingDebugged;
            public byte SpareBool;
            public IntPtr pMutant;
            public IntPtr ImageBase;
            public IntPtr pLdr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr FLink;
            public IntPtr BLink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_LDR_DATA
        {
            public int Length;
            public byte Initialized;
            public IntPtr SsHandle;
            public LIST_ENTRY InLoadOrderModuleList;
            public LIST_ENTRY InMemoryOrderModuleList;
            public LIST_ENTRY InInitializationOrderModuleList;
            public IntPtr EntryInProgress;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY
        {
            public LIST_ENTRY InLoadOrderModuleList;
            public LIST_ENTRY InMemoryOrderModuleList;
            public LIST_ENTRY InInitializationOrderModuleList;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public int SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
            public uint Flags;
            public short LoadCount;
            public short TlsIndex;
            public IntPtr SectionPointer;
            public uint CheckSum;
            public IntPtr LoadedImports;
            public IntPtr EntryPointActivationContext;
            public IntPtr PatchInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public uint tpBasePri;
            public uint tpDeltaPri;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES : IDisposable
        {
            public int Length;
            public IntPtr RootDirectory;
            private IntPtr objectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

            public OBJECT_ATTRIBUTES(string name, uint attrs)
            {
                Length = 0;
                RootDirectory = IntPtr.Zero;
                objectName = IntPtr.Zero;
                Attributes = attrs;
                SecurityDescriptor = IntPtr.Zero;
                SecurityQualityOfService = IntPtr.Zero;
                Length = Marshal.SizeOf(this);
                if (name != null) ObjectName = new UNICODE_STRING(name);
            }

            public UNICODE_STRING ObjectName
            {
                get
                {
                    return (UNICODE_STRING)Marshal.PtrToStructure(objectName, typeof(UNICODE_STRING));
                }
                set
                {
                    bool fDeleteOld = objectName != IntPtr.Zero;
                    if (!fDeleteOld)  objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                    Marshal.StructureToPtr(value, objectName, fDeleteOld);
                }
            }

            public void Dispose()
            {
                if (objectName != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                    Marshal.FreeHGlobal(objectName);
                    objectName = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public UNICODE_STRING(string s = null)
            {
                if (s != null)
                {
                    Length = (ushort) (s.Length*2);
                    MaximumLength = (ushort) (Length + 2);
                    Buffer = Marshal.StringToHGlobalUni(s);
                }
                else
                {
                    Length = 0;
                    MaximumLength = 0;
                    Buffer = IntPtr.Zero;
                }
            }

            public void Dispose()
            {
                if (Buffer != IntPtr.Zero) Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer) : string.Empty;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }


    }
}
