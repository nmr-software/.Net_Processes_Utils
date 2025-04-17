using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Nmr.Utils.Processes {
    public class ExtendedWin32Exception : Exception {
        public ExtendedWin32Exception(string message) : base($"{message}: {new Win32Exception().Message}") {}
    }

    public class ThreadInjector {

        #region Native Methods and Constants
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint PAGE_READWRITE = 4;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;

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
        #endregion

        // https://learn.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants
        private static Dictionary<ushort, string> _machineTypes = new Dictionary<ushort, string> {
            { 0x014c, "Win32" },
            { 0x8664, "x64" },
            { 0xAA64, "ARM64" }
        };

        private static IntPtr LoadLibraryW;

        private readonly Process _process;
        private uint _threadId = 0;
        private string _dllFile;

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

            if (LoadLibraryW == IntPtr.Zero) {
                IntPtr kernel32Handle = GetModuleHandle("kernel32.dll");
                if (kernel32Handle == IntPtr.Zero) {
                    throw new ExtendedWin32Exception("Failed to get handle for kernel32.dll.");
                }

                LoadLibraryW = GetProcAddress(kernel32Handle, "LoadLibraryW");
                if (LoadLibraryW == IntPtr.Zero) {
                    throw new ExtendedWin32Exception("Failed to get address for LoadLibraryW().");
                }
            }
        }

        public void Inject() {
            if (_threadId != 0) {
                throw new InvalidOperationException("A thread has already been injected.");
            }

            var bytes = Encoding.Unicode.GetBytes(_dllFile);
            var allocMemAddress = VirtualAllocEx(_process.Handle, IntPtr.Zero, (uint) bytes.Length + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (allocMemAddress == IntPtr.Zero) {
                throw new ExtendedWin32Exception("Failed to allocate memory in target process.");
            }
            if (!WriteProcessMemory(_process.Handle, allocMemAddress, bytes, (uint)bytes.Length + 1, out _)) {
                throw new ExtendedWin32Exception("Failed to write memory in target process.");
            }

            var _threadHandle = CreateRemoteThread(
                _process.Handle,
                lpThreadAttributes: IntPtr.Zero,
                dwStackSize: 0,
                LoadLibraryW,
                allocMemAddress,
                dwCreationFlags: 0,
                out _threadId);

            if (_threadHandle == IntPtr.Zero) {
                throw new ExtendedWin32Exception("Failed to create remote thread.");
            }
        }

        public void Continue() {
            if (_threadId == 0) {
                throw new InvalidOperationException("No thread has been injected.");
            }

            _process.Refresh();
            foreach (ProcessThread t in _process.Threads) {
                if (t.WaitReason == ThreadWaitReason.Suspended) {
                    var threadHandle = OpenThread(THREAD_SUSPEND_RESUME, bInheritHandle: false, (uint)t.Id);
                    if (threadHandle == IntPtr.Zero) {
                        throw new ExtendedWin32Exception("Failed to open thread.");
                    }
                    if (ResumeThread(threadHandle) == uint.MaxValue) {
                        throw new ExtendedWin32Exception("Failed to resume the thread.");
                    }
                    break;
                }
            }
        }
    }
}
