using System;
using System.Reflection.Emit;
using System.Reflection;
using ClrTest.Reflection;

namespace Nmr.Utils.Processes {
    internal class ILProcessor {
        static OpCode[] oneByteOpCodes = new OpCode[0x100];
        static OpCode[] twoByteOpCodes = new OpCode[0x100];
        static OpCode EOF = new OpCode() { };
        // https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.operandtype
        static int[] OperandType2Size = new int[] { 4, 4, 4, 8, 4, 0, int.MinValue, 8, int.MinValue, 4, 4, 4, 4, 4, 2, 1, 1, 4, 1 };

        static ILProcessor() {
            foreach (FieldInfo fi in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)) {
                OpCode opCode = (OpCode)fi.GetValue(null);
                ushort value = (ushort)opCode.Value;
                if (value < 0x100) {
                    oneByteOpCodes[value] = opCode;
                } else if ((value & 0xff00) == 0xfe00) {
                    twoByteOpCodes[value & 0xff] = opCode;
                } else {
                    throw new InvalidOperationException("Unsupported OpCode value: " + value);
                }
            }
        }

        public static unsafe void TransferTokens(MethodBase method, DynamicILInfo dili, byte[] code) {
            var resolver = new ModuleScopeTokenResolver(method);

            fixed (byte* basePtr = code) {
                byte* pos = basePtr;
                while (pos < basePtr + code.Length) {
                    OpCode op;
                    if (*pos == 0xfe) {
                        pos++;
                        op = twoByteOpCodes[*pos];
                    } else {
                        op = oneByteOpCodes[*pos];
                    }
                    int* i32 = (int*)(++pos);

                    switch (op.OperandType) {
                        case OperandType.InlineMethod:
                            var m = resolver.AsMethod(*i32);
                            *i32 = dili.GetTokenFor(m.MethodHandle, m.DeclaringType.TypeHandle);
                            break;
                        case OperandType.InlineField:
                            var field = resolver.AsField(*i32);
                            *i32 = dili.GetTokenFor(field.FieldHandle);
                            break;
                        case OperandType.InlineString:
                            var str = resolver.AsString(*i32);
                            *i32 = dili.GetTokenFor(str);
                            break;
                        case OperandType.InlineSig:
                            var sig = resolver.AsSignature(*i32);
                            *i32 = dili.GetTokenFor(sig);
                            break;
                        case OperandType.InlineType:
                            var type = resolver.AsType(*i32);
                            *i32 = dili.GetTokenFor(type.TypeHandle);
                            break;
                        case OperandType.InlineTok:
                            var mi = resolver.AsMember(*i32);
                            switch (mi.MemberType) {
                                case MemberTypes.TypeInfo:
                                case MemberTypes.NestedType:
                                    type = mi as Type;
                                    *i32 = dili.GetTokenFor(type.TypeHandle);
                                    break;
                                case MemberTypes.Method:
                                case MemberTypes.Constructor:
                                    m = mi as MethodBase;
                                    *i32 = dili.GetTokenFor(m.MethodHandle, m.DeclaringType.TypeHandle);
                                    break;
                                case MemberTypes.Field:
                                    FieldInfo f = mi as FieldInfo;
                                    //CLR BUG: token = dili.GetTokenFor(f.FieldHandle, f.DeclaringType.TypeHandle);
                                    *i32 = dili.GetTokenFor(f.FieldHandle);
                                    break;
                                default:
                                    throw new InvalidOperationException("Unsupported MemberType as instructin argument: " + mi.MemberType);
                            }
                            break;
                    }
                    pos += OperandType2Size[(int)op.OperandType];
                }
            }
        }
    }
}
