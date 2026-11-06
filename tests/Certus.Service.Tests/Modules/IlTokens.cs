using System.Reflection;
using System.Reflection.Emit;

namespace Certus.Service.Tests.Modules;

/// <summary>
/// Walks a method body's IL and yields every metadata token an instruction carries: the method a
/// call, callvirt, newobj or ldftn names, the type a box, castclass or ldtoken names, the field a
/// ldfld names. Both boundary scans read method bodies through this, so they cannot disagree about
/// what a body refers to.
/// </summary>
internal static class IlTokens
{
    private static readonly OpCode[] OneByte = new OpCode[0x100];
    private static readonly OpCode[] TwoByte = new OpCode[0x100];

    static IlTokens()
    {
        foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (field.GetValue(null) is not OpCode code)
                continue;
            var value = (ushort)code.Value;
            if (code.Size == 1)
                OneByte[value] = code;
            else
                TwoByte[value & 0xFF] = code;
        }
    }

    /// <summary>The token operands of <paramref name="il"/>, with the kind of operand each one is.</summary>
    public static IEnumerable<(OperandType Kind, int Token)> Enumerate(byte[] il)
    {
        var at = 0;
        while (at < il.Length)
        {
            OpCode code;
            var first = il[at++];
            if (first == 0xFE)
            {
                if (at >= il.Length)
                    yield break;
                code = TwoByte[il[at++]];
            }
            else
            {
                code = OneByte[first];
            }

            switch (code.OperandType)
            {
                case OperandType.InlineField:
                case OperandType.InlineMethod:
                case OperandType.InlineTok:
                case OperandType.InlineType:
                case OperandType.InlineSig:
                    yield return (code.OperandType, BitConverter.ToInt32(il, at));
                    at += 4;
                    break;
                case OperandType.InlineSwitch:
                    var count = BitConverter.ToInt32(il, at);
                    at += 4 + (4 * count);
                    break;
                case OperandType.InlineNone:
                    break;
                case OperandType.ShortInlineBrTarget:
                case OperandType.ShortInlineI:
                case OperandType.ShortInlineVar:
                    at += 1;
                    break;
                case OperandType.InlineVar:
                    at += 2;
                    break;
                case OperandType.InlineI8:
                case OperandType.InlineR:
                    at += 8;
                    break;
                default:
                    // InlineBrTarget, InlineI, InlineString, ShortInlineR: four bytes.
                    at += 4;
                    break;
            }
        }
    }
}
