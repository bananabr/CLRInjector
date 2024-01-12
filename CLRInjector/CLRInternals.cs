using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CLRHeapWalker
{
    internal class CLRInternals
    {
        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct CodeHeap
        {
            public ulong hpNext;                        // +0x000
            public ulong pHeap;                         // +0x008
            public ulong startAddress;                  // +0x010
            public ulong endAddress;                    // +0x018
            public ulong mapBase;                       // +0x020
            public ulong pHdrMap;                       // +0x028
            public ulong maxCodeHeapSize;               // +0x030
            public ulong reserveForJumpStubs;           // +0x038
            public ulong CLRPersonalityRoutine;         // +0x040
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct ExplicitControlLoaderHeap
        {
            public ulong m_pFirstBlock;                               // +0x000
            public ulong m_pAllocPtr;                                 // +0x008 (Assuming IntPtr for unsigned char*)
            public ulong m_pPtrToEndOfCommittedRegion;                // +0x010 (Assuming IntPtr for unsigned char*)
            public ulong m_pEndReservedRegion;                        // +0x018 (Assuming IntPtr for unsigned char*)
            public uint m_dwReserveBlockSize;                         // +0x020 (Assuming uint for unsigned long)
            public uint m_dwCommitBlockSize;                          // +0x024 (Assuming uint for unsigned long)
            public ulong m_pRangeList;                                // +0x028
            public ulong m_dwTotalAlloc;                              // +0x030 (Assuming ulong for unsigned __int64)
            public uint m_Options;                                    // +0x038 (Assuming uint for unsigned long)
            public ulong m_pFirstFreeBlock;                           // +0x040
            public LoaderHeapBlock m_reservedBlock;                   // +0x048
            public int m_fExplicitControl;                            // +0x068
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct LoaderHeapBlock
        {
            public ulong pNext;            // +0x000
            public ulong pVirtualAddress;  // +0x008 (Assuming IntPtr for void*)
            public ulong dwVirtualSize;    // +0x010 (Assuming ulong for unsigned __int64)
            public int m_fReleaseMemory;   // +0x018
        }

        public const int mdcHasNonVtableSlot = 0x0008;

        [StructLayout(LayoutKind.Explicit)]
        public struct CoreClrMethodDesc
        {
            [FieldOffset(0)]
            public ushort m_wFlags3AndTokenRemainder;

            [FieldOffset(2)]
            public byte m_chunkIndex;

            [FieldOffset(0x3)]
            public byte m_bFlags2;

            [FieldOffset(0x4)]
            public ushort m_wSlotNumber;

            [FieldOffset(0x6)]
            public ushort m_wFlags;

            [FieldOffset(0x8)]
            public ulong TempEntry;
        }
    }
}
