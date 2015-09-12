using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyMemory_x64.Memory
{
    public class RemotePointer
    {

        public RemoteProcess Process { get; }

        public IntPtr Pointer { get; set; }

        public RemotePointer(RemoteProcess process, IntPtr pointer)
        {
            Process = process;
            Pointer = pointer;
        }

        public virtual bool IsValid => Pointer != IntPtr.Zero;

        public override string ToString() => "Pointer 0x" + Pointer.ToString("X");

        public T Read<T>(int offset = 0) where T : struct => Process.Read<T>(Pointer + offset);

        public bool Write<T>(int offset, T value) where T : struct => Process.Write(Pointer + offset, value);

        public string ReadString(int offset = 0, Encoding encoding = null, int maxLength = 512) => Process.ReadString(Pointer + offset, encoding, maxLength);

        public bool WriteString(int offset, string value, Encoding encoding) => Process.WriteString(Pointer + offset, value, encoding);

        public byte[] ReadBytes(int offset, int count) => Process.ReadBytes(Pointer + offset, count);

        public bool WriteBytes(int offset, byte[] bBuffer) => Process.WriteBytes(Pointer + offset, bBuffer);
        
    }
}
