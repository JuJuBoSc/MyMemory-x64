using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MyMemory_x64.Natives;

namespace MyMemory_x64.Threads
{
    public class RemoteThread : IDisposable
    {

        public uint ThreadId { get; }
        public IntPtr ThreadHandle { get; private set; }
        public RemoteProcess Process { get; }

        public bool IsValid => ThreadId != 0 && ThreadHandle != IntPtr.Zero;

        public RemoteThread(RemoteProcess process, uint threadId)
        {
            Process = process;
            ThreadId = threadId;
            ThreadHandle = Syscall.OpenThread(Enumerations.ThreadAccessFlags.AllAccess, ThreadId);
        }

        public RemoteThread(RemoteProcess process, IntPtr threadHandle)
        {
            Process = process;
            ThreadHandle = threadHandle;
            ThreadId = Methods.GetThreadId(ThreadHandle);
        }

        /*public bool Suspend()
        {
            return Process.Win32.SuspendThread(ThreadHandle);
        }

        public bool Resume()
        {
            return Process.Win32.ResumeThread(ThreadHandle);
        }*/

        public void Dispose()
        {
            if (ThreadHandle != IntPtr.Zero)
            {
                Syscall.CloseHandle(ThreadHandle);
                ThreadHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

        ~RemoteThread()
        {
            Dispose();
        }

        public void Join(uint waitTime = 0xFFFFFFFF)
        {
            Methods.WaitForSingleObject(ThreadHandle, waitTime);
        }

        public uint GetExitCode()
        {
            uint returnCode;
            Methods.GetExitCodeThread(ThreadHandle, out returnCode);
            return returnCode;;
        }

    }
}
