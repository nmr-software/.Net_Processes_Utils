using System;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Nmr.Utils.Processes {
    public class ExtendedWin32Exception : Exception {
        public ExtendedWin32Exception(string message) : base($"{message}: {new Win32Exception().Message}") { }
    }

    public class ThreadInjector {

        #region Native Methods and Constants
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint PAGE_READWRITE = 4;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const uint SYNCHRONIZE = 0x00100000;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        #endregion

        // https://learn.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants
        private static Dictionary<ushort, string> _machineTypes = new Dictionary<ushort, string> {
            { 0x014c, "Win32" },
            { 0x8664, "x64" },
            { 0xAA64, "ARM64" }
        };

        private static IntPtr LoadLibraryW = GetFunctionHandle("kernel32.dll", "LoadLibraryW");

        public Exception FindCanaryThreadException;
        private readonly Process _process;
        private string _dllFile;
        private IntPtr _loadLibraryThread;
        private IntPtr _canary;

        public ThreadInjector(Process process) {
            _process = process ?? throw new ArgumentNullException(nameof(process));

            if (!IsWow64Process2(_process.Handle, out ushort wowArch, out ushort nativeArch)) {
                throw new ExtendedWin32Exception("Failed to determine process architecture.");
            }
            var suffix = _machineTypes[wowArch != 0 ? wowArch : nativeArch];
            var dir = new FileInfo(typeof(ThreadInjector).Assembly.Location).Directory;
            var files = dir.GetFiles($"Zombie.{suffix}.dll");
            if (files.Length == 0) {
                throw new FileNotFoundException($"Could not find Zoombie.{suffix}.dll in {dir.FullName}");
            }
            _dllFile = files[0].FullName;
        }

        private static IntPtr GetFunctionHandle(string dllName, string functionName) {
            IntPtr moduleHandle = GetModuleHandle(dllName);
            if (moduleHandle == IntPtr.Zero) {
                throw new ExtendedWin32Exception($"Failed to get handle for {dllName}");
            }

            IntPtr functionHandle = GetProcAddress(moduleHandle, functionName);
            if (functionHandle == IntPtr.Zero) {
                throw new ExtendedWin32Exception($"Failed to get address for {functionName} in {dllName}");
            }

            return functionHandle;
        }

        /// <summary>
        /// Do the injection. The target process will not be able to exit normally if no exception is thrown.
        /// </summary>
        /// <returns>False indicates the canary thread cannot be located (but the Zombie inject is still successful). Details in the FindCanaryThreadError field.</returns>
        public bool Inject() {
            if (_loadLibraryThread != IntPtr.Zero) throw new InvalidOperationException("A thread has already been injected.");

            var bytes = Encoding.Unicode.GetBytes(_dllFile);
            var stringSize = (uint)bytes.Length + 1;
            var allocMemAddress = VirtualAllocEx(_process.Handle, IntPtr.Zero, stringSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (allocMemAddress == IntPtr.Zero) {
                throw new ExtendedWin32Exception("Failed to allocate memory in target process.");
            }
            if (!WriteProcessMemory(_process.Handle, allocMemAddress, bytes, stringSize, out _)) {
                throw new ExtendedWin32Exception("Failed to write memory in target process.");
            }

            _process.Refresh();
            var origIds = _process.Threads.Cast<ProcessThread>().Select(t => t.Id).ToHashSet();

            _loadLibraryThread = CreateRemoteThread(
                _process.Handle,
                lpThreadAttributes: IntPtr.Zero,
                dwStackSize: 0,
                LoadLibraryW,
                allocMemAddress,
                dwCreationFlags: 0,
                out _);

            if (_loadLibraryThread == IntPtr.Zero) {
                throw new ExtendedWin32Exception("Failed to create remote thread.");
            }

            return LocateCanaryThread(origIds);
        }

        protected bool LocateCanaryThread(HashSet<int> origIds) {
            IntPtr threadHandle = IntPtr.Zero;
            try {
                switch (WaitForSingleObject(_loadLibraryThread, 500)) {
                    case 0x00000102:
                        throw new TimeoutException("LoadLibrary thread took too long to exit");
                    case 0xFFFFFFFFu:
                        throw new ExtendedWin32Exception("Can't wait for load library thread");
                }
                CloseHandle(_loadLibraryThread);

                _process.Refresh();
                foreach (ProcessThread t in _process.Threads) {
                    if (origIds.Contains(t.Id) || t.ThreadState != ThreadState.Wait || t.WaitReason != ThreadWaitReason.Suspended) continue;

                    threadHandle = OpenThread(THREAD_SUSPEND_RESUME | SYNCHRONIZE, bInheritHandle: false, (uint)t.Id);
                    if (threadHandle == IntPtr.Zero) {
                        FindCanaryThreadException = new ExtendedWin32Exception("Failed to open candidate thread");
                        continue;
                    }

                    uint result;
                    if ((result = SuspendThread(threadHandle)) == uint.MaxValue) {
                        FindCanaryThreadException = new ExtendedWin32Exception("Failed to get the suspend count of the candidate thread");
                        continue;
                    }

                    if (result > 30) {
                        _canary = threadHandle;
                        threadHandle = IntPtr.Zero;
                        return true;
                    } else {
                        ResumeThread(threadHandle);
                    }
                    CloseHandle(threadHandle);
                }

                throw new Exception("Canary thread not found");
            } catch (Exception ex) {
                CloseHandle(threadHandle);
                FindCanaryThreadException = ex;
                return false;
            }
        }

        public void Uninject() {
            if (_canary == IntPtr.Zero) throw new InvalidOperationException("Must have found the canary thread");
            
            uint result;
            while ((result = ResumeThread(_canary)) != 1) {
                if (result == 0xFFFFFFFF) throw new ExtendedWin32Exception("Failed to resume the canary thread");
            }

            WaitForCanaryThread(1000);
            _canary = IntPtr.Zero;
            _loadLibraryThread = IntPtr.Zero;
        }

        /// <summary>
        /// Wait for the canary thread to exit, which only happens when the target process is terminating
        /// (or if the canary thread is externally killed).
        /// </summary>
        /// <param name="timeout">In ms. -1 means indefinite wait.</param>
        /// <returns>If the thread has actually exited (true) or timeout (false)</returns>
        /// <exception cref="InvalidOperationException"><see cref="Inject"/> returned false</exception>
        /// <exception cref="ExtendedWin32Exception">Implementation bug</exception>
        public bool WaitForCanaryThread(uint timeout) {
            if (_canary == IntPtr.Zero) {
                throw new InvalidOperationException("Canary thread not found", FindCanaryThreadException);
            }
            var result = WaitForSingleObject(_canary, timeout);
            if (result == 0xFFFFFFFF) throw new ExtendedWin32Exception("Failed to wait for canary thread");
            return result == 0x00000000;
        }

        /// <summary>
        /// Allow the process to continue (terminate).
        /// 
        /// <para>Does not work until <see cref="WaitForCanaryThread(uint)"/> has succeeded
        /// or you have otherwise determined the process is actually terminating.</para>
        /// </summary>
        public void Continue() {
            if (_loadLibraryThread == IntPtr.Zero) throw new InvalidOperationException("Please call Inject() first");

            _process.Refresh();
            foreach (ProcessThread t in _process.Threads) {
                if (t.WaitReason == ThreadWaitReason.Suspended) {
                    var threadHandle = OpenThread(THREAD_SUSPEND_RESUME, bInheritHandle: false, (uint)t.Id);
                    if (threadHandle == IntPtr.Zero) {
                        var ex = new ExtendedWin32Exception("Failed to open thread");
                        _process.Refresh();
                        if (!_process.HasExited) throw ex;
                    }
                    if (ResumeThread(threadHandle) == uint.MaxValue) {
                        var ex = new ExtendedWin32Exception("Failed to resume the thread.");
                        _process.Refresh();
                        if (!_process.HasExited) throw ex;
                    }
                    CloseHandle(threadHandle);
                    break;
                }
            }
        }

        protected virtual void Finalize() {
            CloseHandle(_canary);
        }
    }
}
