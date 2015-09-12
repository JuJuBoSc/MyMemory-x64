using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MyMemory_x64.Natives;

namespace MyMemory_x64.Memory
{
    public class RemoteAllocatedMemory : RemotePointer
    {

        public int Size { get; }

        public RemoteAllocatedMemory(RemoteProcess memory, IntPtr pointer, int size) : base(memory, pointer)
        {
            Size = size;
        }

        public bool Release()
        {
            return Syscall.FreeVirtualMemory(Process.ProcessHandle, Pointer, Size, Enumerations.FreeType.Release);
        }

        public void Dispose()
        {
            Release();
            GC.SuppressFinalize(this);
        }

    }
}
