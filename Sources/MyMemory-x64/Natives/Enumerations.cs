using System;

namespace MyMemory_x64.Natives
{
    public static class Enumerations
    {

        public enum Ntstatus : uint
        {
            Success = 0x0
        }
        
        [Flags]
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            Delete = 0x00010000,
            ReadControl = 0x00020000,
            Synchronize = 0x00100000,
            WriteDac = 0x00040000,
            WriteOwner = 0x00080000,
            ProcessAllAccess = 0x001F0FFF,
            ProcessCreateProcess = 0x0080,
            ProcessCreateThread = 0x0002,
            ProcessDupHandle = 0x0040,
            ProcessQueryInformation = 0x0400,
            ProcessQueryLimitedInformation = 0x1000,
            ProcessSetInformation = 0x0200,
            ProcessSetQuota = 0x0100,
            ProcessSuspendResume = 0x0800,
            ProcessTerminate = 0x0001,
            ProcessVmOperation = 0x0008,
            ProcessVmRead = 0x0010,
            ProcessVmWrite = 0x0020
        }

        [Flags]
        public enum ThreadAccessFlags
        {
            Synchronize = 0x00100000,
            AllAccess = 0x001F0FFF,
            DirectImpersonation = 0x0200,
            GetContext = 0x0008,
            Impersonate = 0x0100,
            QueryInformation = 0x0040,
            QueryLimitedInformation = 0x0800,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            SetLimitedInformation = 0x0400,
            SetThreadToken = 0x0080,
            SuspendResume = 0x0002,
            Terminate = 0x0001
        }

        [Flags]
        public enum AllocationType : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum FreeType
        {
            Decommit = 0x4000,
            Release = 0x8000
        }

        [Flags]
        public enum MemoryProtectionFlags : uint
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        public enum MemoryInformationClass : int
        {
            MemoryBasicInformation = 0
        }

        public enum ProcessInformationClass : int
        {
            ProcessBasicInformation = 0
        }

        public enum ThreadInformationClass : int
        {
            ThreadBasicInformation = 0
        }

    }
}