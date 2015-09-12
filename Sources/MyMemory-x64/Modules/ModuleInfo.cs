using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyMemory_x64.Modules
{
    public struct ModuleInfo
    {
        public IntPtr BaseAddress;
        public int Size;
        public string FullModuleName;
        public string BaseDllName;
        public uint Flags;
        public int LoadCount;
        public int TlsIndex;

        public override string ToString()
        {
            return BaseDllName;
        }
    }
}
