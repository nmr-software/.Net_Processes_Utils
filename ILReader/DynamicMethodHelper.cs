// 
// A helper class to turn MethodInfo to DynamicMethod, demo'ing how to use DynamicILInfo
// This class depends on the ILReader described at http://blogs.msdn.com/haibo_luo/archive/2006/11/06/system-reflection-based-ilreader.aspx
//
// By Haibo Luo @ http://blogs.msdn.com/haibo_luo
//
// THIS CODE IS PROVIDED "AS IS", WITH NO WARRANTIES INTENDED OR IMPLIED. USE AT YOUR OWN RISK
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Reflection.Emit;
using System.Reflection;

namespace ClrTest.Reflection {
    public class ILInfoGetTokenVisitor : ILInstructionVisitor {
        private DynamicILInfo ilInfo;
        private byte[] code;

        public ILInfoGetTokenVisitor(DynamicILInfo ilinfo, byte[] code) {
            this.ilInfo = ilinfo;
            this.code = code;
        }

        public override void VisitInlineMethodInstruction(InlineMethodInstruction inlineMethodInstruction) {
            OverwriteInt32(ilInfo.GetTokenFor(
                inlineMethodInstruction.Method.MethodHandle,
                inlineMethodInstruction.Method.DeclaringType.TypeHandle),
                inlineMethodInstruction.Offset + inlineMethodInstruction.OpCode.Size);
        }

        public override void VisitInlineSigInstruction(InlineSigInstruction inlineSigInstruction) {
            OverwriteInt32(ilInfo.GetTokenFor(inlineSigInstruction.Signature),
                inlineSigInstruction.Offset + inlineSigInstruction.OpCode.Size);
        }

        public override void VisitInlineFieldInstruction(InlineFieldInstruction inlineFieldInstruction) {
            //CLR BUG: 
            //OverwriteInt32(ilInfo.GetTokenFor(inlineFieldInstruction.Field.FieldHandle, inlineFieldInstruction.Field.DeclaringType.TypeHandle),
            //    inlineFieldInstruction.Offset + inlineFieldInstruction.OpCode.Size);

            OverwriteInt32(ilInfo.GetTokenFor(inlineFieldInstruction.Field.FieldHandle),
                inlineFieldInstruction.Offset + inlineFieldInstruction.OpCode.Size);
        }

        public override void VisitInlineStringInstruction(InlineStringInstruction inlineStringInstruction) {
            OverwriteInt32(ilInfo.GetTokenFor(inlineStringInstruction.String),
               inlineStringInstruction.Offset + inlineStringInstruction.OpCode.Size);
        }

        public override void VisitInlineTypeInstruction(InlineTypeInstruction inlineTypeInstruction) {
            OverwriteInt32(ilInfo.GetTokenFor(inlineTypeInstruction.Type.TypeHandle),
               inlineTypeInstruction.Offset + inlineTypeInstruction.OpCode.Size);
        }

        public override void VisitInlineTokInstruction(InlineTokInstruction inlineTokInstruction) {
            MemberInfo mi = inlineTokInstruction.Member;
            int token = 0;
            if (mi.MemberType == MemberTypes.TypeInfo || mi.MemberType == MemberTypes.NestedType) {
                Type type = mi as Type;
                token = ilInfo.GetTokenFor(type.TypeHandle);
            } else if (mi.MemberType == MemberTypes.Method || mi.MemberType == MemberTypes.Constructor) {
                MethodBase m = mi as MethodBase;
                token = ilInfo.GetTokenFor(m.MethodHandle, m.DeclaringType.TypeHandle);
            } else if (mi.MemberType == MemberTypes.Field) {
                FieldInfo f = mi as FieldInfo;
                //CLR BUG: token = ilInfo.GetTokenFor(f.FieldHandle, f.DeclaringType.TypeHandle);
                token = ilInfo.GetTokenFor(f.FieldHandle);
            }

            OverwriteInt32(token,
                inlineTokInstruction.Offset + inlineTokInstruction.OpCode.Size);
        }

        void OverwriteInt32(int value, int pos) {
            code[pos++] = (byte)value;
            code[pos++] = (byte)(value >> 8);
            code[pos++] = (byte)(value >> 16);
            code[pos++] = (byte)(value >> 24);
        }
    }
}
