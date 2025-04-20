using System;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Xml.Linq;

namespace Nmr.Utils.Processes {
    public class Starter {
        #region Flags
        // https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
        public const int CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
        public const int CREATE_DEFAULT_ERROR_MODE = 0x04000000;
        public const int CREATE_NEW_CONSOLE = 0x00000010;
        public const int CREATE_NEW_PROCESS_GROUP = 0x00000200;
        public const int CREATE_NO_WINDOW = 0x08000000;
        public const int CREATE_PROTECTED_PROCESS = 0x00040000;
        public const int CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000;
        public const int CREATE_SEPARATE_WOW_VDM = 0x00000800;
        public const int CREATE_SHARED_WOW_VDM = 0x00001000;
        public const int CREATE_SUSPENDED = 0x00000004;
        public const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const int DEBUG_ONLY_THIS_PROCESS = 0x00000002;
        public const int DEBUG_PROCESS = 0x00000001;
        public const int DETACHED_PROCESS = 0x00000008;
        public const int EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        public const int INHERIT_PARENT_AFFINITY = 0x00010000;
        #endregion

        private const BindingFlags NonPubInstance = BindingFlags.NonPublic | BindingFlags.Instance;

        public delegate bool CreateProc(ProcessStartInfo psi, int flags);

        protected static DynamicMethod dynMethod = cache();

        public static Process StartWithFlags(ProcessStartInfo info, int flags, bool tolerateShellExecute = false) {
            if (info == null) throw new ArgumentNullException(nameof(info));
            if (info.UseShellExecute) {
                if (tolerateShellExecute) {
                    return Process.Start(info);
                } else {
                    throw new InvalidOperationException("UseShellExecute is not supported");
                }
            }

            var result = new Process();
            result.StartInfo = info;
            var dele = (CreateProc)dynMethod.CreateDelegate(typeof(CreateProc), result);
            return dele(info, flags) ? result : null;
        }

        private static DynamicMethod cache() {
            var target = typeof(Process).GetMethod("StartWithCreateProcess", NonPubInstance);
            if (target.GetParameters().Length != 1 || target.GetParameters()[0].ParameterType != typeof(ProcessStartInfo)) {
                throw new InvalidOperationException("Invalid method signature: " + target);
            }

            // Compared to locating the arguments of Microsoft.Win32.NativeMethods.CreateProcessWithLogonW, using the public property of ProcessStartInfo is much more reliable.
            var anchor = BitConverter.GetBytes(typeof(ProcessStartInfo).GetProperty("CreateNoWindow").GetAccessors()[0].MetadataToken);

            var body = target.GetMethodBody();
            var ils = body.GetILAsByteArray();
            for (int i = 4; i < ils.Length; i++) {
                if (ils[i - 1] == 0x03 & ils[i] == 0x6F && // ldarg0, callvirt
                    (ils[i + 1] == anchor[0] & ils[i + 2] == anchor[1] & ils[i + 3] == anchor[2] & ils[i + 4] == anchor[3])) {

                    if (ils[i - 4] != 0x16 | ils[i - 3] != 0x13) // varX = 0
                        throw new InvalidOperationException("if(CreateNoWindow) not preceded by the initialisation of the flag variable");
                    byte flagVar = ils[i - 2];

                    if (ils[i + 5] != 0x2C | ils[i + 6] != 0x0A // brfalse +10
                        | ils[i + 7] != 0x11 | ils[i + 8] != flagVar // ldloc X
                        | ils[i + 9] != 0x20 | ils[i + 10] != 0x00 | ils[i + 11] != 0x00 | ils[i + 12] != 0x00 | ils[i + 13] != 0x08 // imm 0x8000..
                        | ils[i + 14] != 0x60 | ils[i + 15] != 0x13 | ils[i + 16] != flagVar)
                        throw new InvalidOperationException("if(CreateNoWindow) not followed by flag |= 0x80000000");


                    ils[i - 4] = 0x04; // ldarg.2

                    AssemblyBuilder ab = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("ProcessWrapper"), AssemblyBuilderAccess.Run);
                    ModuleBuilder mb = ab.DefineDynamicModule("ProcessWrapper");
                    mb.SetCustomAttribute(new CustomAttributeBuilder(
                        typeof(System.Security.SecurityCriticalAttribute).GetConstructor(Type.EmptyTypes), new object[] { }));
                    var dynType = mb.DefineType("ProcessWrapper", TypeAttributes.Public | TypeAttributes.Class, typeof(Process)).GetType();

                    Type[] parameters = new Type[] { typeof(Process), typeof(ProcessStartInfo), typeof(int) };
                    var output = new DynamicMethod("CreateProcessWithFlags", typeof(bool), parameters, dynType, true);
                    output.InitLocals = body.InitLocals;

                    var dili = output.GetDynamicILInfo();
                    ILProcessor.TransferTokens(target, dili, ils);
                    dili.SetCode(ils, target.GetMethodBody().MaxStackSize);
                    dili.SetExceptions(GetExceptionBytes(body));
                    byte[] localSignature = typeof(Process).Module.ResolveSignature(body.LocalSignatureMetadataToken);
                    dili.SetLocalSignature(localSignature);

                    return output;
                }
            }
            throw new InvalidOperationException("Failed to locate if(CreateNoWindow) line");
        }

        static unsafe byte[] GetExceptionBytes(MethodBody body) {
            // https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
            // II.25.4
            var clauses = body.ExceptionHandlingClauses;
            var exceptionBytes = new byte[clauses.Count * 24 + 4];

            fixed (byte* basePtr = exceptionBytes) {
                *(int*)basePtr = exceptionBytes.Length;
                *basePtr = 0x41;

                var ptr = basePtr + 4;
                foreach (var clause in clauses) {
                    *(int*)(ptr + 0) = (int)clause.Flags;
                    *(int*)(ptr + 4) = clause.TryOffset;
                    *(int*)(ptr + 8) = clause.TryLength;
                    *(int*)(ptr + 12) = clause.HandlerOffset;
                    *(int*)(ptr + 16) = clause.HandlerLength;
                    switch (clause.Flags) {
                        case ExceptionHandlingClauseOptions.Clause:
                            *(int*)(ptr + 20) = clause.CatchType.MetadataToken;
                            break;
                        case ExceptionHandlingClauseOptions.Filter:
                            *(int*)(ptr + 20) = clause.FilterOffset;
                            break;
                    }
                    ptr += 24;
                }
            }

            return exceptionBytes;
        }

        static System.Collections.ArrayList securityAttributeFinder() {
            var module = typeof(System.Diagnostics.Process).Module;
            var l = new System.Collections.ArrayList();
            foreach (var type in module.GetTypes()) {
                if (type.GetCustomAttribute<System.Security.SecuritySafeCriticalAttribute>() != null) {
                    l.Add(type.FullName);
                }
            }
            l.Sort();
            return l;
        }
    }
}
