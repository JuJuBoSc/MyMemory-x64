using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using MyMemory_x64;
using MyMemory_x64.Natives;

namespace Tester
{
    class Program
    {

        private static RemoteProcess process;

        static void Main(string[] args)
        {

            Console.Title = "[MyMemory x64 Tester]";
            Trace.Listeners.Add(new ConsoleTraceListener());

            process = new RemoteProcess();

            var processes = Process.GetProcessesByName("explorer");

            if (processes.Length == 0)
            {
                Console.WriteLine("No explorer.exe found, wtf ?");
                Console.ReadKey();
                return;
            }

            var winProcess = processes.First();

            Console.WriteLine("Using process \"{0}\" with PID {1}", winProcess.ProcessName, winProcess.Id);
            Console.WriteLine("Press any key to start testing ..." + Environment.NewLine);
            Console.ReadKey();

            Console.WriteLine("+ - - - - - - - - - - - - - - - -");
            Console.WriteLine("| Process manipulation");
            Console.WriteLine("+ - - - - - - - - - - - - - - - -");
            Console.WriteLine();

            if (Program.process.Open((uint)winProcess.Id))
            {
                Console.WriteLine("OpenProcess ... [SUCCESS]");
                Console.WriteLine("ProcessHandle : 0x{0}", process.ProcessHandle.ToString("X"));
                Console.WriteLine("ImageBase : 0x{0}", process.ImageBase.ToString("X"));
                Console.WriteLine("ProcessEnvironmentBlock : 0x{0}", process.ProcessEnvironmentBlock.Pointer.ToString("X"));
                BasicMemoryTests();
                BasicThreadsTests();
            }
            else
            {
                Console.WriteLine("OpenProcess ... [FAIL]");
            }
            
            Console.WriteLine(Environment.NewLine + "Press any key to exit");
            Console.ReadKey();

        }

        static void BasicThreadsTests()
        {

            Console.WriteLine();
            Console.WriteLine("+ - - - - - - - - - - - - - - - -");
            Console.WriteLine("| Basic threads tests");
            Console.WriteLine("+ - - - - - - - - - - - - - - - -");
            Console.WriteLine();

            var remoteThreads = process.Threads.ToList();


            Console.Write("Threads enumeration ... ");
            Console.WriteLine(remoteThreads .Count > 0 ? string.Format("[SUCCESS] ({0} threads)", remoteThreads.Count) : "[FAIL]");

        }

        static void BasicMemoryTests()
        {

            Console.WriteLine();
            Console.WriteLine("+ - - - - - - - - - - - - - - - -");
            Console.WriteLine("| Basic memory tests");
            Console.WriteLine("+ - - - - - - - - - - - - - - - -");
            Console.WriteLine();

            var allocatedMemory = process.AllocateMemory(0x1000);
            int memoryWriteTest = Environment.TickCount;

            Console.Write("Memory allocation ... ");
            Console.WriteLine(allocatedMemory.IsValid ? string.Format("[SUCCESS] (BaseAddress : 0x{0})", allocatedMemory.Pointer.ToString("X")) : "[FAIL]");

            Console.Write("Memory write ... ");
            Console.WriteLine(allocatedMemory.Write<int>(0, memoryWriteTest) ? "[SUCCESS]" : "[FAIL]");

            Console.Write("Memory read ... ");
            Console.WriteLine(allocatedMemory.Read<int>() == memoryWriteTest ? "[SUCCESS]" : "[FAIL]");

            Console.Write("Memory release ... ");
            Console.WriteLine(allocatedMemory.Release() ? "[SUCCESS]" : "[FAIL]");
        }

    }
}
