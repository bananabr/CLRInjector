## Disclaimer

This tool is provided for educational purposes only. Any actions and activities related to the material contained within this repository are solely your responsibility. Misusing this tool can result in criminal charges against the persons in question. The author will not be held responsible if any criminal charges are brought against any individuals misusing the provided tool to break the law.

## What is this?

A proof-of-concept process injection tool that mixes Adam Chester's ([@XPN](https://twitter.com/_xpn_)) "Weird Ways to Run Unmanaged Code in .NET" and Ceri Coburn's ([@_EthicalChaos_](https://twitter.com/_ethicalchaos_)) "Needles Without The Thread: Threadless Process Injection - Ceri Coburn".

## How does it work?

* List target processes
```
CLRInjector.exe --ps
```
* Dump GC heap (similar to SOS.dll !dumpheap)
```
CLRInjector.exe <target pid> --dump-heap
```
* Dump method tables (similar to SOS.dll !dumpmt)
```
CLRInjector.exe <target pid> --dump-mt 0x1122334455667788
```
* Dump method descriptor (similar to SOS.dll !dumpmd)
```
CLRInjector.exe <target pid> --dump-md 0x1122334455667788
```
* Dump code caves (RWX memory segments)
```
CLRInjector.exe <target pid> --dump-caves [cave size]
```
* List Jitted methods native code addresses
```
CLRInjector.exe <target pid> --find-jit
```
* Hook Jitted method and loads shellcode into preexisting RWX segment
```
CLRInjector.exe <target pid> --jit-inject <shellcode_path> <method_native_code_address>
```

### Usage example

![Usage example](images/CLRThreadlessInjection.gif)

## Known issues

* I took a naive approach moving the JIT Manager loader code heap m_pAllocPtr to its m_pEndReservedRegion. This keeps the heap available and forces the JIT Manager to create a new heap for future allocations. There is still a chance of a race condition if m_pAllocPtr is updated before its patched.
* Shellcode must supports being called as a function and properly return, otherwise it may crash the target process. A generic stub that loads the shellcode on its own thread would most likely solve this.

## References

* https://blog.xpnsec.com/weird-ways-to-execute-dotnet/
* https://www.youtube.com/watch?v=z8GIjk0rfbI&t=1388s
* https://learn.microsoft.com/en-us/archive/msdn-magazine/2005/may/net-framework-internals-how-the-clr-creates-runtime-objects
* https://www.codeproject.com/articles/37549/clr-injection-runtime-method-replacer?fid=1542682&df=90&mpp=25&prof=True&sort=Position&view=Normal&spc=Relaxed&fr=26
* https://blog.maartenballiauw.be/post/2017/01/03/exploring-.net-managed-heap-with-clrmd.html
* https://mattwarren.org/2016/09/06/Analysing-.NET-Memory-Dumps-with-CLR-MD/

## Todo

PRs are always welcome!

- [ ] Support to x86 targets
- [ ] Generic shellcode support
- [ ] Migrate p/invoke calls to d/invoke
- [ ] Cleanup code
- [ ] Convert NGEN methods to JIT
- [ ] Generic target method
