using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyMemory_x64.Memory
{
    public class RemoteMemoryProtection : RemotePointer, IDisposable
    {
        
        /// <summary>
        /// The new protection flags
        /// </summary>
        public Natives.Enumerations.MemoryProtectionFlags NewProtection { get; }

        /// <summary>
        /// The old protection flags
        /// </summary>
        public Natives.Enumerations.MemoryProtectionFlags OldProtection { get; }

        /// <summary>
        /// The size of the memory region affected
        /// </summary>
        public int Size { get; }

        public RemoteMemoryProtection(RemoteProcess process, IntPtr pointer, int size, Natives.Enumerations.MemoryProtectionFlags newProtection) : base(process, pointer)
        {
            NewProtection = newProtection;
            Size = size;
            Natives.Enumerations.MemoryProtectionFlags oldProtection;
            Natives.Syscall.ProtectVirtualMemory(Process.ProcessHandle, Pointer, Size, NewProtection, out oldProtection);
            OldProtection = oldProtection;
        }
        
        /// <summary>
        /// Restore the old memory protection
        /// </summary>
        public void Restore()
        {
            Natives.Enumerations.MemoryProtectionFlags oldProtection;
            Natives.Syscall.ProtectVirtualMemory(Process.ProcessHandle, Pointer, Size, OldProtection, out oldProtection);
        }

        /// <summary>
        /// Dispose and restore memory protection to it's old value
        /// </summary>
        public void Dispose()
        {
            Restore();
            GC.SuppressFinalize(this);
        }

    }
}
