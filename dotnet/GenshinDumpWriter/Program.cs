using System.Globalization;
using System.Text;
using System.Text.Json;
using Mono.Cecil;

if (args.Length != 2)
    throw new ArgumentException("Usage: GenshinDumpWriter <GenshinInteropBatch dummy directory> <output directory>");

// Writes an Il2CppDumper-style reference from the Cpp2IL-style dummy assemblies the batch generator
// builds: dump.cs (every type, field, and method with its RVA), names.json (RVA to method names),
// and ghidra_apply_genshin_names.py, which labels those functions in GenshinImpact.exe.
var output = Directory.CreateDirectory(args[1]).FullName;
var names = new SortedDictionary<ulong, List<string>>();
int typeCount = 0, methodCount = 0;
using (var dump = new StreamWriter(Path.Combine(output, "dump.cs"), false, new UTF8Encoding(false)))
{
    foreach (var path in Directory.GetFiles(args[0], "*.dll").OrderBy(path => path, StringComparer.Ordinal))
    {
        using var module = ModuleDefinition.ReadModule(path);
        foreach (var type in module.GetTypes().Where(type => type.Name != "<Module>" && type.Namespace != "Cpp2ILInjected"))
        {
            typeCount++;
            WriteType(dump, module.Name, type);
            foreach (var method in type.Methods)
            {
                if (Rva(method) is not { } rva)
                    continue;
                methodCount++;
                if (!names.TryGetValue(rva, out var list))
                    names[rva] = list = [];
                list.Add($"{TypeName(type)}$${method.Name}");
            }
        }
    }
}
File.WriteAllText(Path.Combine(output, "names.json"), JsonSerializer.Serialize(
    names.ToDictionary(pair => $"0x{pair.Key:X}", pair => pair.Value)));
File.WriteAllText(Path.Combine(output, "ghidra_apply_genshin_names.py"), GhidraScript);
Console.WriteLine($"Wrote {typeCount} types and {methodCount} methods at {names.Count} distinct RVAs to {output}");

static void WriteType(StreamWriter dump, string image, TypeDefinition type)
{
    dump.WriteLine($"// Image: {image}");
    dump.WriteLine($"// Namespace: {TypeNamespace(type)}");
    string kind = type.IsEnum ? "enum" : type.IsValueType ? "struct" : type.IsInterface ? "interface" : "class";
    string modifiers = Visibility(type) + (type.IsAbstract && type.IsSealed && !type.IsInterface ? " static"
        : type.IsAbstract && !type.IsInterface ? " abstract" : type.IsSealed && kind == "class" ? " sealed" : "");
    var bases = new List<string>();
    if (type.BaseType is { } baseType && !type.IsEnum && !type.IsValueType && baseType.FullName != "System.Object")
        bases.Add(Name(baseType));
    bases.AddRange(type.Interfaces.Select(item => Name(item.InterfaceType)));
    dump.WriteLine($"{modifiers} {kind} {Name(type)}{(bases.Count > 0 ? " : " + string.Join(", ", bases) : "")}");
    dump.WriteLine("{");
    if (type.HasFields)
    {
        dump.WriteLine("\t// Fields");
        foreach (var field in type.Fields)
        {
            string value = field.HasConstant ? $" = {Literal(field.Constant)}" : "";
            string prefix = field.IsLiteral ? "const " : field.IsStatic ? "static " : field.IsInitOnly ? "readonly " : "";
            dump.WriteLine($"\t{FieldVisibility(field)} {prefix}{Name(field.FieldType)} {field.Name}{value};");
        }
    }
    if (type.HasMethods)
    {
        dump.WriteLine();
        dump.WriteLine("\t// Methods");
        foreach (var method in type.Methods)
        {
            dump.WriteLine(Rva(method) is { } rva ? $"\t// RVA: 0x{rva:X}" : "\t// RVA: -1");
            string generics = method.HasGenericParameters ? $"<{string.Join(", ", method.GenericParameters.Select(item => item.Name))}>" : "";
            string parameters = string.Join(", ", method.Parameters.Select(item => $"{Name(item.ParameterType)} {item.Name}"));
            string modifier = method.IsStatic ? " static" : method.IsAbstract ? " abstract" : method.IsVirtual ? " virtual" : "";
            dump.WriteLine($"\t{MethodVisibility(method)}{modifier} {Name(method.ReturnType)} {method.Name}{generics}({parameters}) {{ }}");
            dump.WriteLine();
        }
    }
    dump.WriteLine("}");
    dump.WriteLine();
}

static ulong? Rva(MethodDefinition method)
{
    var attribute = method.CustomAttributes.FirstOrDefault(item => item.AttributeType.Name == "AddressAttribute");
    var rva = attribute?.Properties.FirstOrDefault(item => item.Name == "RVA").Argument.Value as string;
    return rva is null ? null : Convert.ToUInt64(rva, 16) is var value && value != 0 ? value : null;
}

static string TypeNamespace(TypeDefinition type) => type.DeclaringType is { } parent ? TypeNamespace(parent) : type.Namespace;

static string TypeName(TypeDefinition type)
    => type.DeclaringType is { } parent ? $"{TypeName(parent)}.{type.Name}" : (type.Namespace.Length > 0 ? $"{type.Namespace}.{type.Name}" : type.Name);

static string Name(TypeReference type) => type switch
{
    GenericInstanceType generic => $"{Name(generic.ElementType).Split('`')[0]}<{string.Join(", ", generic.GenericArguments.Select(Name))}>",
    ArrayType array => $"{Name(array.ElementType)}[{new string(',', array.Rank - 1)}]",
    ByReferenceType reference => $"ref {Name(reference.ElementType)}",
    PointerType pointer => $"{Name(pointer.ElementType)}*",
    _ => type.FullName switch
    {
        "System.Void" => "void", "System.Boolean" => "bool", "System.Byte" => "byte", "System.SByte" => "sbyte",
        "System.Int16" => "short", "System.UInt16" => "ushort", "System.Int32" => "int", "System.UInt32" => "uint",
        "System.Int64" => "long", "System.UInt64" => "ulong", "System.Single" => "float", "System.Double" => "double",
        "System.Char" => "char", "System.String" => "string", "System.Object" => "object",
        _ => type.DeclaringType is { } parent ? $"{Name(parent)}.{type.Name}" : type.Name,
    },
};

static string Literal(object? value) => value switch
{
    null => "null",
    string text => $"\"{string.Concat(text.Select(item => Escape(item, '"')))}\"",
    char character => $"'{Escape(character, '\'')}'",
    bool flag => flag ? "true" : "false",
    float single when !float.IsFinite(single) => float.IsNaN(single) ? "float.NaN"
        : single > 0 ? "float.PositiveInfinity" : "float.NegativeInfinity",
    double number when !double.IsFinite(number) => double.IsNaN(number) ? "double.NaN"
        : number > 0 ? "double.PositiveInfinity" : "double.NegativeInfinity",
    float single => single.ToString(CultureInfo.InvariantCulture) + "f",
    _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "",
};

static string Escape(char character, char quote) => character switch
{
    '\\' => "\\\\",
    '\n' => "\\n",
    '\r' => "\\r",
    '\t' => "\\t",
    _ when character == quote => $"\\{quote}",
    _ when char.GetUnicodeCategory(character) is UnicodeCategory.Control or UnicodeCategory.Format
        or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned
        or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator => $"\\u{(int)character:X4}",
    _ => character.ToString(),
};

static string Visibility(TypeDefinition type)
    => type.IsPublic || type.IsNestedPublic ? "public" : type.IsNestedFamily ? "protected" : type.IsNestedPrivate ? "private" : "internal";

static string FieldVisibility(FieldDefinition field)
    => field.IsPublic ? "public" : field.IsFamily ? "protected" : field.IsPrivate ? "private" : "internal";

static string MethodVisibility(MethodDefinition method)
    => method.IsPublic ? "public" : method.IsFamily ? "protected" : method.IsPrivate ? "private" : "internal";

partial class Program
{
    const string GhidraScript = """
# Labels Genshin's IL2CPP methods in GenshinImpact.exe from names.json.
# Run from Ghidra's Script Manager with this file and names.json in the same folder.
# @category Genshin
import json
import os
from ghidra.program.model.symbol import SourceType

names_path = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), "names.json")
with open(names_path) as stream:
    names = json.load(stream)

base = currentProgram.getImageBase()
listing = currentProgram.getListing()
symbols = currentProgram.getSymbolTable()
labeled = 0
monitor.initialize(len(names))
for rva, methods in names.items():
    if monitor.isCancelled():
        break
    monitor.incrementProgress(1)
    address = base.add(int(rva, 16))
    if listing.getFunctionAt(address) is None:
        createFunction(address, None)
    for index, name in enumerate(methods):
        label = name.replace(" ", "_").replace("<", "(").replace(">", ")").replace(",", "_")
        symbol = symbols.createLabel(address, label, SourceType.USER_DEFINED)
        if index == 0:
            symbol.setPrimary()
    labeled += 1
print("Labeled %d functions" % labeled)
""";
}
