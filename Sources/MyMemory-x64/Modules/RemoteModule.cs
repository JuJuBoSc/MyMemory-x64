using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MyMemory_x64.Memory;

namespace MyMemory_x64.Modules
{
    public class RemoteModule : RemotePointer
    {

        public ModuleInfo ModuleInfo { get; }

        /// <summary>
        /// Constructor with internal ModuleInfo structure
        /// </summary>
        /// <param name="process"></param>
        /// <param name="moduleInfo"></param>
        public RemoteModule(RemoteProcess process, ModuleInfo moduleInfo) : base(process, moduleInfo.BaseAddress)
        {
            ModuleInfo = moduleInfo;
        }

        /// <summary>
        /// Constructor with module base address
        /// </summary>
        /// <param name="process"></param>
        /// <param name="baseAddress"></param>
        public RemoteModule(RemoteProcess process, IntPtr baseAddress) : base(process, baseAddress)
        {
            ModuleInfo = process.ProcessEnvironmentBlock.GetModule(baseAddress);
        }

        /// <summary>
        /// Return the base address of the module
        /// </summary>
        public IntPtr BaseAddress => Pointer;

        /// <summary>
        /// Return full module path
        /// </summary>
        public string Filename => ModuleInfo.FullModuleName ?? string.Empty;

        /// <summary>
        /// Return base module name
        /// </summary>
        public string ModuleName => ModuleInfo.BaseDllName ?? string.Empty;

        /// <summary>
        /// Return the module size
        /// </summary>
        public int Size => ModuleInfo.Size;

        /// <summary>
        /// ToString override
        /// </summary>
        /// <returns></returns>
        public override string ToString() => string.Format("Module : {0}, BaseAddress : 0x{1}, Size : 0x{2}", ModuleName, BaseAddress.ToString("X"), Size.ToString("X"));
    }
}
