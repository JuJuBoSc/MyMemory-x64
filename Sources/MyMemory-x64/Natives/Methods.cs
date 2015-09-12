using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MyMemory_x64.Natives
{
    public static class Methods
    {

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, int size, Enumerations.AllocationType flAllocationType, Enumerations.MemoryProtectionFlags flProtect);
        
        [DllImport("kernel32.dll")]
        public static extern bool Thread32First(IntPtr hSnapshot, ref Structures.THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        public static extern bool Thread32Next(IntPtr hSnapshot, out Structures.THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateToolhelp32Snapshot(Enumerations.SnapshotFlags flags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        public static extern uint GetThreadId(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    }
}
