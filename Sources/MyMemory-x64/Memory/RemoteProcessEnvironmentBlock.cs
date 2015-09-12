using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MyMemory_x64.Natives;
using MyMemory_x64.Memory;
using MyMemory_x64.Modules;

namespace MyMemory_x64.Memory
{
    public class RemoteProcessEnvironmentBlock : RemotePointer
    {

        public Structures.PEB NativePeb => Read<Structures.PEB>();

        public Structures.PEB_LDR_DATA NativePebLdrData => Process.Read<Structures.PEB_LDR_DATA>(NativePeb.pLdr);

        public RemoteProcessEnvironmentBlock(RemoteProcess memory, IntPtr pointer) : base(memory, pointer) { }

        /// <summary>
        /// The base address of the process
        /// </summary>
        public IntPtr ImageBase => NativePeb.ImageBase;

        /// <summary>
        /// Return if the process is being debugged
        /// </summary>
        public bool BeingDebugged => NativePeb.BeingDebugged != 0;

        /// <summary>
        /// Return a list of all modules loaded in the process
        /// </summary>
        /// <returns></returns>
        public IEnumerable<ModuleInfo> GetModules() 
        {
            var inLoadOrderModuleList = NativePebLdrData.InLoadOrderModuleList;
            var pModule = inLoadOrderModuleList.FLink;
            while (pModule != inLoadOrderModuleList.BLink)
            {
                var module = Process.Read<Structures.LDR_DATA_TABLE_ENTRY>(pModule);
                yield return new ModuleInfo()
                {
                    BaseAddress = module.DllBase,
                    BaseDllName = Process.ReadString(module.BaseDllName.Buffer, Encoding.Unicode, module.BaseDllName.Length),
                    FullModuleName = Process.ReadString(module.FullDllName.Buffer, Encoding.Unicode, module.FullDllName.Length),
                    Flags = module.Flags,
                    LoadCount = module.LoadCount,
                    Size = module.SizeOfImage,
                    TlsIndex = module.TlsIndex
                };
                pModule = module.InLoadOrderModuleList.FLink;
            }
        }

        /// <summary>
        /// Get a module by it's base address
        /// </summary>
        /// <param name="baseAddress"></param>
        /// <returns></returns>
        public ModuleInfo GetModule(IntPtr baseAddress)
        {
            return GetModules().FirstOrDefault(x => x.BaseAddress == baseAddress);
        }

        /// <summary>
        /// Get a module by it's name
        /// </summary>
        /// <param name="moduleName"></param>
        /// <returns></returns>
        public ModuleInfo GetModule(string moduleName)
        {
            return GetModules().FirstOrDefault(x => string.Equals(x.BaseDllName, moduleName, StringComparison.CurrentCultureIgnoreCase));
        }

    }
}
