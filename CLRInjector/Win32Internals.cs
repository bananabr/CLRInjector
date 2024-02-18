using System.Runtime.InteropServices;

namespace CLRHeapWalker
{
    internal class Win32Internals
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        public const int MAXIMUM_ALLOWED = 0x2000000;
        public const int PAGE_EXECUTE_READWRITE = 0x40;
        public const int PAGE_READWRITE = 0x04;
        public const int MEM_COMMIT = 0x1000;
        public const int MEM_PRIVATE = 0x20000;

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int nSize,
            out int lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    }
}
