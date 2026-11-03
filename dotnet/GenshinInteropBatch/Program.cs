using System.Globalization;
using System.Text.Json;
using AsmResolver.DotNet;
using Il2CppInterop.Generator;
using Il2CppInterop.Generator.Runners;
using Cecil = Mono.Cecil;
using Cil = Mono.Cecil.Cil;

if (args.Length < 2 || args.Length > 3 || args.Length == 3 && args[2] != "--generate")
{
    Console.Error.WriteLine("Usage: GenshinInteropBatch <GenshinUnityAPI.json> <output-directory> [--generate]");
    return 2;
}
var generate = args.Length == 3;

using var document = JsonDocument.Parse(File.ReadAllText(args[0]));
var metadata = document.RootElement;
if (metadata.GetProperty("format").GetString() != "genshin-mhy-verified-subset-v1"
    || metadata.GetProperty("exe_sha256").GetString()
    != "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d")
    throw new InvalidDataException("Metadata export does not match the inspected Genshin build");

var batch = new BatchBuilder(metadata, Path.GetFullPath(args[1]));
batch.Build();
if (generate)
    batch.GenerateInterop();
return 0;

sealed class BatchBuilder
{
    private readonly JsonElement _metadata;
    private readonly string _root;
    private readonly Dictionary<int, Cecil.TypeDefinition> _types = [];
    private readonly Dictionary<Cecil.TypeDefinition, int> _typeIndices = [];
    private readonly Dictionary<string, Cecil.AssemblyDefinition> _assemblies = [];
    private readonly BatchAssemblyResolver _resolver = new();
    private readonly Dictionary<string, Cecil.MethodDefinition> _addressConstructors = [];
    private readonly Dictionary<string, int> _skipped = [];
    private readonly List<string> _renamed = [];
    private readonly Dictionary<string, Cecil.TypeDefinition> _coreTypes = [];
    private readonly Dictionary<int, int> _genericStarts = [];
    private int _methods;
    private int _fields;
    private int _addresses;

    public BatchBuilder(JsonElement metadata, string root)
    {
        _metadata = metadata;
        _root = root;
    }

    public void Build()
    {
        var images = _metadata.GetProperty("images").EnumerateArray().ToArray();
        foreach (var image in images)
            CreateAssembly(image.GetProperty("name").GetString()!);

        foreach (var image in images)
            AddTypes(image);
        foreach (var type in _metadata.GetProperty("referenced_types").EnumerateArray())
            AddReferencedType(type);
        foreach (var image in images)
            foreach (var type in image.GetProperty("types").EnumerateArray())
                RecordGenericParameterRange(type);

        foreach (var name in new[] { "Object", "Void", "ValueType", "String", "Boolean", "Char",
                     "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64",
                     "Single", "Double", "IntPtr", "UIntPtr", "TypedReference" })
        {
            var definition = _assemblies["mscorlib.dll"].MainModule.Types
                .SingleOrDefault(type => type.Namespace == "System" && type.Name == name);
            if (definition is null)
                throw new InvalidDataException($"mscorlib lacks System.{name}");
            _coreTypes.Add(name, definition);
        }

        foreach (var assembly in _assemblies.Values)
            AddAddressAttribute(assembly.MainModule);
        foreach (var image in images)
            AddMembers(image);
        foreach (var definition in _types.Values)
            AddProperties(definition);
        foreach (var definition in _types.Values)
        {
            if (definition.BaseType?.FullName != "System.MulticastDelegate"
                || definition.Methods.Any(method => method.Name == "Invoke"))
                continue;
            definition.BaseType = definition.Module.ImportReference(_coreTypes["Object"]);
            Skip("delegate without representable Invoke; emitted as Object subtype");
        }

        var fields = _assemblies.Values.SelectMany(assembly => assembly.MainModule.GetTypes())
            .SelectMany(type => type.Fields).ToList();
        var constants = fields.Count(field => field.HasConstant);
        if (fields.Any(field => field.IsLiteral && !field.HasConstant))
            throw new InvalidDataException("Literal fields have no constant values");

        var dummyDirectory = Path.Combine(_root, "dummy");
        Directory.CreateDirectory(dummyDirectory);
        foreach (var stale in Directory.GetFiles(dummyDirectory, "*.dll")
                     .Where(path => !_assemblies.ContainsKey(Path.GetFileName(path))))
            File.Delete(stale);
        foreach (var (fileName, assembly) in _assemblies)
            assembly.Write(Path.Combine(dummyDirectory, fileName));

        var report = new
        {
            format = "genshin-dummy-batch-v1",
            source_exe_sha256 = _metadata.GetProperty("exe_sha256").GetString(),
            assemblies = _assemblies.Count,
            types = _types.Count,
            methods = _methods,
            fields = _fields,
            method_addresses = _addresses,
            constants,
            generic_parameter_ranges = _genericStarts.Count,
            skipped = _skipped,
            renamed_types = _renamed,
        };
        File.WriteAllText(Path.Combine(_root, "report.json"),
            JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Wrote {_assemblies.Count} dummy assemblies: {_types.Count} types, "
            + $"{_methods} methods, {_fields} fields ({constants} constants), {_addresses} method addresses");
        foreach (var (reason, count) in _skipped.OrderByDescending(entry => entry.Value))
            Console.WriteLine($"Skipped {count}: {reason}");
        Console.WriteLine($"Renamed {_renamed.Count} types with duplicate names in one declaring scope");
    }

    public void GenerateInterop()
    {
        var dummyDirectory = Path.Combine(_root, "dummy");
        var outputDirectory = Path.Combine(_root, "interop");
        Directory.CreateDirectory(outputDirectory);
        foreach (var stale in Directory.GetFiles(outputDirectory, "*.dll")
                     .Concat(Directory.GetFiles(outputDirectory, "*.db")))
            File.Delete(stale);
        var input = Directory.GetFiles(dummyDirectory, "*.dll")
            .OrderBy(path => Path.GetFileName(path) == "mscorlib.dll" ? 0 : 1)
            .Select(AsmResolver.DotNet.AssemblyDefinition.FromFile)
            .ToList();
        var options = new GeneratorOptions
        {
            Source = input,
            OutputDir = outputDirectory,
            GameAssemblyPath = null,
            UnityBaseLibsDir = null,
            NoXrefCache = true,
            Parallel = false,
            PassthroughNames = true,
        };
        Il2CppInteropGenerator.Create(options).AddInteropAssemblyGenerator().Run();
        var generatedCount = Directory.GetFiles(outputDirectory, "*.dll").Length;
        if (generatedCount != _assemblies.Count)
            throw new InvalidDataException($"Generated {generatedCount} of {_assemblies.Count} assemblies");
        var coreImage = _metadata.GetProperty("images").EnumerateArray().Single(image =>
            image.GetProperty("name").GetString() == "UnityEngine.CoreModule.dll");
        var applicationQuitRva = coreImage.GetProperty("types").EnumerateArray().Single(type =>
            type.GetProperty("namespace").GetString() == "UnityEngine"
            && type.GetProperty("name").GetString() == "Application")
            .GetProperty("methods").EnumerateArray().Single(method =>
                method.GetProperty("name").GetString() == "Quit"
                && method.GetProperty("parameters").GetArrayLength() == 0)
            .GetProperty("code_rva").GetUInt64();
        CoreModulePatches.Apply(outputDirectory, applicationQuitRva);
        VerifyMethodAddresses(outputDirectory);
        VerifyGenericSignatures(outputDirectory);
        VerifyProperties(outputDirectory);
        Console.WriteLine($"Generated {generatedCount} interop assemblies");
    }

    private static void VerifyProperties(string outputDirectory)
    {
        foreach (var (image, namespaze, owner, name, getter, setter) in new[]
                 {
                     ("UnityEngine.CoreModule.dll", "UnityEngine", "Vector2", "zero", "get_zero", (string?)null),
                     ("UnityEngine.CoreModule.dll", "UnityEngine", "GameObject", "transform", "get_transform", null),
                     ("UnityEngine.CoreModule.dll", "UnityEngine", "RectTransform", "rect", "get_rect", null),
                     ("UnityEngine.UI.dll", "UnityEngine.UI", "Graphic", "color", "get_color", "set_color"),
                 })
        {
            using var assembly = Cecil.AssemblyDefinition.ReadAssembly(Path.Combine(outputDirectory, image));
            var definition = assembly.MainModule.GetTypes().Single(type =>
                type.Namespace == namespaze && type.Name == owner);
            var property = definition.Properties.SingleOrDefault(candidate => candidate.Name == name);
            if (property?.GetMethod?.Name != getter || property.SetMethod?.Name != setter)
                throw new InvalidDataException($"Generated {owner}.{name} property accessors differ");
        }
        Console.WriteLine("Verified four generated Unity property signatures");
    }

    private void VerifyMethodAddresses(string outputDirectory)
    {
        var map = File.ReadAllBytes(Path.Combine(outputDirectory, "MethodAddressToToken.db"));
        if (map.Length < 20 || BitConverter.ToInt32(map, 0) != 0x4D544D55)
            throw new InvalidDataException("Method address map is missing or invalid");
        var methodCount = BitConverter.ToInt32(map, 12);
        var dataOffset = BitConverter.ToInt32(map, 16);
        if (methodCount <= 0 || dataOffset < 20 || (long)dataOffset + 16L * methodCount > map.Length)
            throw new InvalidDataException("Method address map is truncated");
        var addresses = new Dictionary<ulong, (int token, int assembly)>();
        for (var index = 0; index < methodCount; index++)
        {
            var address = BitConverter.ToUInt64(map, dataOffset + 8 * index);
            var token = BitConverter.ToInt32(map, dataOffset + 8 * methodCount + 8 * index);
            var assembly = BitConverter.ToInt32(map, dataOffset + 8 * methodCount + 8 * index + 4);
            addresses.TryAdd(address, (token, assembly));
        }

        var coreImage = _metadata.GetProperty("images").EnumerateArray()
            .Single(image => image.GetProperty("name").GetString() == "UnityEngine.CoreModule.dll");
        using var generated = Cecil.AssemblyDefinition.ReadAssembly(
            Path.Combine(outputDirectory, "UnityEngine.CoreModule.dll"));
        int? coreAssemblyIndex = null;
        foreach (var (typeName, methodName, parameterCount) in new[]
                 {
                     ("Application", "Quit", 0),
                     ("Object", "get_name", 0),
                     ("GameObject", "Find", 1),
                 })
        {
            var sourceType = coreImage.GetProperty("types").EnumerateArray().Single(type =>
                type.GetProperty("namespace").GetString() == "UnityEngine"
                && type.GetProperty("name").GetString() == typeName);
            var sourceMethod = sourceType.GetProperty("methods").EnumerateArray().Single(method =>
                method.GetProperty("name").GetString() == methodName
                && method.GetProperty("parameters").GetArrayLength() == parameterCount);
            var rva = sourceMethod.GetProperty("code_rva").GetUInt64();
            var method = generated.MainModule.Types.Single(type =>
                type.Namespace == "UnityEngine" && type.Name == typeName)
                .Methods.Single(candidate => candidate.Name == methodName
                    && candidate.Parameters.Count == parameterCount);
            if (!addresses.TryGetValue(rva, out var mapped)
                || mapped.token != method.MetadataToken.ToInt32()
                || coreAssemblyIndex is not null && mapped.assembly != coreAssemblyIndex)
                throw new InvalidDataException($"Method address map disagrees with {typeName}.{methodName}");
            coreAssemblyIndex = mapped.assembly;
            Console.WriteLine($"Verified {typeName}.{methodName}: RVA 0x{rva:x}, "
                + $"token 0x{mapped.token:x8}, assembly {mapped.assembly}");
        }
        Console.WriteLine($"Method address map contains {methodCount} entries");

        foreach (var name in new[] { "GetComponent", "AddComponent" })
        {
            var method = generated.MainModule.Types.Single(type =>
                    type.Namespace == "UnityEngine" && type.Name == "GameObject")
                .Methods.Single(candidate => candidate.Name == name
                    && candidate.Parameters.Count == 0);
            if (method.GenericParameters.Count != 1
                || method.ReturnType is not Cecil.GenericParameter genericReturn
                || genericReturn.Type != Cecil.GenericParameterType.Method
                || genericReturn.Position != 0)
                throw new InvalidDataException($"Generated GameObject.{name}<T> signature is invalid");
            Console.WriteLine($"Verified GameObject.{name}<T> generic signature");
        }
    }

    private static void VerifyGenericSignatures(string outputDirectory)
    {
        var checks = new (string image, string namespaze, string owner, string method,
            int parameterCount, int signatureParameter, string genericType, string argument,
            Cecil.GenericParameterType? argumentParameter)[]
        {
            ("UnityEngine.TextRenderingModule.dll", "UnityEngine", "TextGenerator", "get_characters",
                0, -1, "IList`1", "UICharInfo", null),
            ("UnityEngine.TextRenderingModule.dll", "UnityEngine", "TextGenerator", "get_lines",
                0, -1, "IList`1", "UILineInfo", null),
            ("UnityEngine.UI.dll", "UnityEngine.UI", "Dropdown", "get_options",
                0, -1, "List`1", "OptionData", null),
            ("UnityEngine.UI.dll", "UnityEngine.EventSystems", "BaseRaycaster", "Raycast",
                2, 1, "List`1", "RaycastResult", null),
            ("UnityEngine.UI.dll", "UnityEngine.EventSystems", "ExecuteEvents", "get_deselectHandler",
                0, -1, "EventFunction`1", "IDeselectHandler", null),
            ("UnityEngine.UI.dll", "UnityEngine.EventSystems", "ExecuteEvents", "get_selectHandler",
                0, -1, "EventFunction`1", "ISelectHandler", null),
            ("UnityEngine.CoreModule.dll", "UnityEngine.Events", "UnityEvent`1", "AddListener",
                1, 0, "UnityAction`1", "", Cecil.GenericParameterType.Type),
            ("UnityEngine.CoreModule.dll", "UnityEngine.Events", "UnityEvent`1", "RemoveListener",
                1, 0, "UnityAction`1", "", Cecil.GenericParameterType.Type),
            ("UnityEngine.UI.dll", "UnityEngine.EventSystems", "ExecuteEvents", "Execute",
                3, 2, "EventFunction`1", "", Cecil.GenericParameterType.Method),
        };
        foreach (var check in checks)
        {
            using var assembly = Cecil.AssemblyDefinition.ReadAssembly(
                Path.Combine(outputDirectory, check.image));
            var owner = assembly.MainModule.GetTypes().Single(type =>
                type.Namespace == check.namespaze && type.Name == check.owner);
            var method = owner.Methods.Single(candidate => candidate.Name == check.method
                && candidate.Parameters.Count == check.parameterCount);
            var signature = check.signatureParameter < 0 ? method.ReturnType
                : method.Parameters[check.signatureParameter].ParameterType;
            if (signature is not Cecil.GenericInstanceType instance
                || instance.ElementType.Name != check.genericType
                || instance.GenericArguments.Count != 1)
                throw new InvalidDataException($"Generated {check.owner}.{check.method} lacks its generic type");
            var argument = instance.GenericArguments[0];
            if (check.argumentParameter is { } parameterType)
            {
                if (argument is not Cecil.GenericParameter genericArgument
                    || genericArgument.Type != parameterType || genericArgument.Position != 0)
                    throw new InvalidDataException($"Generated {check.owner}.{check.method} generic argument differs");
            }
            else if (argument.Name != check.argument)
                throw new InvalidDataException($"Generated {check.owner}.{check.method} generic argument differs");
        }
        Console.WriteLine($"Verified {checks.Length} UnityExplorer generic signatures");
    }

    private void AddTypes(JsonElement image)
    {
        var fileName = image.GetProperty("name").GetString()!;
        var module = _assemblies[fileName].MainModule;
        var names = new HashSet<string>();
        Cecil.TypeDefinition? currentOwner = null;
        foreach (var type in image.GetProperty("types").EnumerateArray())
        {
            var index = type.GetProperty("index").GetInt32();
            var name = type.GetProperty("name").GetString()!;
            if (name == "<Module>")
                continue;
            var namespaze = type.GetProperty("namespace").GetString()!;
            var flags = (Cecil.TypeAttributes)type.GetProperty("flags").GetUInt32();
            var visibility = flags & Cecil.TypeAttributes.VisibilityMask;
            var nested = visibility is >= Cecil.TypeAttributes.NestedPublic
                and <= Cecil.TypeAttributes.NestedFamORAssem && currentOwner is not null;
            var key = (nested ? currentOwner!.FullName : namespaze) + "\0" + name;
            if (!names.Add(key))
            {
                _renamed.Add($"{fileName}:{index}:{namespaze}.{name}");
                name += "$" + index;
            }
            if (!nested)
                flags = (flags & ~Cecil.TypeAttributes.VisibilityMask) |
                    (visibility == Cecil.TypeAttributes.Public
                        ? Cecil.TypeAttributes.Public : Cecil.TypeAttributes.NotPublic);
            var definition = new Cecil.TypeDefinition(namespaze, name, flags, null);
            var tick = name.LastIndexOf('`');
            if (tick >= 0 && int.TryParse(name[(tick + 1)..], out var arity))
                for (var parameter = 0; parameter < arity; parameter++)
                    definition.GenericParameters.Add(new Cecil.GenericParameter("T" + parameter, definition));
            if (nested)
                currentOwner!.NestedTypes.Add(definition);
            else
            {
                module.Types.Add(definition);
                currentOwner = definition;
            }
            _types.Add(index, definition);
            _typeIndices.Add(definition, index);
        }
    }

    private void AddReferencedType(JsonElement reference)
    {
        var index = reference.GetProperty("index").GetInt32();
        if (_types.ContainsKey(index))
            return;
        var fileName = reference.GetProperty("image").GetString();
        if (fileName is null)
        {
            Skip("referenced type without image");
            return;
        }
        if (!_assemblies.TryGetValue(fileName, out var assembly))
            assembly = CreateAssembly(fileName);
        var definition = new Cecil.TypeDefinition(reference.GetProperty("namespace").GetString(),
            reference.GetProperty("name").GetString(), Cecil.TypeAttributes.Public | Cecil.TypeAttributes.Class,
            null);
        assembly.MainModule.Types.Add(definition);
        _types.Add(index, definition);
        _typeIndices.Add(definition, index);
    }

    private Cecil.AssemblyDefinition CreateAssembly(string fileName)
    {
        var name = Path.GetFileNameWithoutExtension(fileName);
        var assembly = Cecil.AssemblyDefinition.CreateAssembly(
            new Cecil.AssemblyNameDefinition(name, new Version(0, 0, 0, 0)), name,
            new Cecil.ModuleParameters { Kind = Cecil.ModuleKind.Dll, AssemblyResolver = _resolver });
        _resolver.Register(assembly);
        _assemblies.Add(fileName, assembly);
        return assembly;
    }

    private void AddAddressAttribute(Cecil.ModuleDefinition module)
    {
        var definition = new Cecil.TypeDefinition("Cpp2ILInjected", "AddressAttribute",
            Cecil.TypeAttributes.Public | Cecil.TypeAttributes.Class,
            module.ImportReference(typeof(Attribute)));
        module.Types.Add(definition);
        var constructor = new Cecil.MethodDefinition(".ctor",
            Cecil.MethodAttributes.Public | Cecil.MethodAttributes.HideBySig |
            Cecil.MethodAttributes.SpecialName | Cecil.MethodAttributes.RTSpecialName,
            module.ImportReference(typeof(void)));
        constructor.Body.Instructions.Add(Cil.Instruction.Create(Cil.OpCodes.Ret));
        definition.Methods.Add(constructor);
        _addressConstructors.Add(module.Name, constructor);
    }

    private void RecordGenericParameterRange(JsonElement type)
    {
        var index = type.GetProperty("index").GetInt32();
        if (!_types.TryGetValue(index, out var definition) || !definition.HasGenericParameters)
            return;
        var parameters = new HashSet<int>();
        var parent = type.GetProperty("parent");
        if (parent.ValueKind == JsonValueKind.Object)
            CollectGenericParameterIndices(parent, parameters);
        foreach (var field in type.GetProperty("fields").EnumerateArray())
            CollectGenericParameterIndices(field.GetProperty("type"), parameters);
        foreach (var method in type.GetProperty("methods").EnumerateArray())
        {
            CollectGenericParameterIndices(method.GetProperty("return_type"), parameters);
            foreach (var parameter in method.GetProperty("parameters").EnumerateArray())
                CollectGenericParameterIndices(parameter.GetProperty("type"), parameters);
        }
        if (parameters.Count != definition.GenericParameters.Count)
            return;
        var start = parameters.Min();
        if (parameters.All(parameter => parameter >= start
            && parameter < start + definition.GenericParameters.Count))
            _genericStarts.Add(index, start);
    }

    private static void CollectGenericParameterIndices(JsonElement type, HashSet<int> parameters)
    {
        if (type.GetProperty("kind").GetInt32() == 19
            && type.TryGetProperty("generic_parameter_index", out var genericIndex))
            parameters.Add(genericIndex.GetInt32());
        if (type.TryGetProperty("element_type", out var element))
            CollectGenericParameterIndices(element, parameters);
        if (type.TryGetProperty("generic_arguments", out var arguments))
            foreach (var argument in arguments.EnumerateArray())
                CollectGenericParameterIndices(argument, parameters);
    }

    private void AddMembers(JsonElement image)
    {
        var fileName = image.GetProperty("name").GetString()!;
        var module = _assemblies[fileName].MainModule;
        foreach (var type in image.GetProperty("types").EnumerateArray())
        {
            var index = type.GetProperty("index").GetInt32();
            if (!_types.TryGetValue(index, out var definition))
                continue;
            var parent = type.GetProperty("parent");
            if (parent.ValueKind == JsonValueKind.Object)
            {
                if (TryResolve(parent, module, definition, out var baseType))
                    definition.BaseType = baseType;
                else if (!definition.IsInterface && definition != _coreTypes["Object"])
                {
                    definition.BaseType = module.ImportReference(_coreTypes["Object"]);
                    Skip("unsupported parent type");
                }
            }
            foreach (var field in type.GetProperty("fields").EnumerateArray())
                AddField(definition, field, module);
            foreach (var method in type.GetProperty("methods").EnumerateArray())
                AddMethod(definition, method, module);
        }
    }

    private void AddField(Cecil.TypeDefinition owner, JsonElement source, Cecil.ModuleDefinition module)
    {
        if (!TryResolve(source.GetProperty("type"), module, owner, out var fieldType))
        {
            Skip("unsupported field type");
            return;
        }
        var flags = (Cecil.FieldAttributes)source.GetProperty("flags").GetUInt32();
        flags &= ~(Cecil.FieldAttributes.HasDefault | Cecil.FieldAttributes.HasFieldRVA |
                   Cecil.FieldAttributes.HasFieldMarshal);
        var name = source.GetProperty("name").GetString()!;
        var field = new Cecil.FieldDefinition(name, flags, fieldType);
        if (field.IsLiteral)
        {
            var defaultValue = source.GetProperty("default_value");
            var value = defaultValue.GetProperty("value");
            object? constant = defaultValue.GetProperty("type").GetString() switch
            {
                "bool" => value.GetBoolean(),
                "char" => (char)value.GetUInt16(),
                "sbyte" => value.GetSByte(),
                "byte" => value.GetByte(),
                "int16" => value.GetInt16(),
                "uint16" => value.GetUInt16(),
                "int32" => value.GetInt32(),
                "uint32" => value.GetUInt32(),
                "int64" => value.GetInt64(),
                "uint64" => value.GetUInt64(),
                "single" => float.Parse(FloatText(value), CultureInfo.InvariantCulture),
                "double" => double.Parse(FloatText(value), CultureInfo.InvariantCulture),
                "string" => value.GetString(),
                var type => throw new InvalidDataException($"{owner.FullName}.{name} has unsupported constant type {type}"),
            };
            // Cecil encodes a constant with its field type's element type. mscorlib's own String
            // definition has none, so Cecil would store its string constants as null class references.
            if (constant is string && fieldType == _coreTypes["String"])
                field.FieldType = module.ImportReference(typeof(string));
            // Cecil's Constant getter discards the value while the field has no module, so only set it here.
            field.Attributes |= Cecil.FieldAttributes.HasDefault;
            field.Constant = constant;
        }
        owner.Fields.Add(field);
        _fields++;
    }

    private static string FloatText(JsonElement value)
        => value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText();

    private static void AddProperties(Cecil.TypeDefinition owner)
    {
        foreach (var getter in owner.Methods.Where(method =>
                     method.Name.StartsWith("get_", StringComparison.Ordinal)
                     && method.ReturnType.FullName != "System.Void"))
        {
            var name = getter.Name[4..];
            var setter = owner.Methods.FirstOrDefault(method =>
                method.Name == "set_" + name
                && method.IsStatic == getter.IsStatic
                && method.ReturnType.FullName == "System.Void"
                && method.Parameters.Count == getter.Parameters.Count + 1
                && method.Parameters[^1].ParameterType.FullName == getter.ReturnType.FullName
                && getter.Parameters.Select(parameter => parameter.ParameterType.FullName)
                    .SequenceEqual(method.Parameters.Take(method.Parameters.Count - 1)
                        .Select(parameter => parameter.ParameterType.FullName)));
            var property = new Cecil.PropertyDefinition(name, Cecil.PropertyAttributes.None,
                getter.ReturnType) { GetMethod = getter, SetMethod = setter };
            foreach (var parameter in getter.Parameters)
                property.Parameters.Add(new Cecil.ParameterDefinition(parameter.Name,
                    parameter.Attributes, parameter.ParameterType));
            owner.Properties.Add(property);
        }
    }

    private void AddMethod(Cecil.TypeDefinition owner, JsonElement source, Cecil.ModuleDefinition module)
    {
        var methodParameters = new SortedSet<int>();
        var inferredPositions = new SortedSet<int>();
        CollectMethodGenericParameterIndices(source.GetProperty("return_type"), methodParameters,
            inferredPositions);
        foreach (var parameter in source.GetProperty("parameters").EnumerateArray())
            CollectMethodGenericParameterIndices(parameter.GetProperty("type"), methodParameters,
                inferredPositions);

        var flags = (Cecil.MethodAttributes)source.GetProperty("flags").GetUInt32();
        flags &= ~(Cecil.MethodAttributes.PInvokeImpl | Cecil.MethodAttributes.HasSecurity);
        var methodName = source.GetProperty("name").GetString();
        if (methodName == "<unnamed>" && flags.HasFlag(Cecil.MethodAttributes.RTSpecialName))
        {
            if (source.GetProperty("return_type").GetProperty("kind").GetInt32() != 1)
                throw new InvalidDataException("Unnamed constructor has a non-void return type");
            if (flags.HasFlag(Cecil.MethodAttributes.Static))
            {
                Skip("unnamed static initializer; generated wrapper owns .cctor");
                return;
            }
            methodName = ".ctor";
        }
        var method = new Cecil.MethodDefinition(methodName, flags,
            module.ImportReference(typeof(void)));
        var methodGenericParameters = new Dictionary<int, Cecil.GenericParameter>();
        var inferredCount = inferredPositions.Count == 0 ? 0 : inferredPositions.Max + 1;
        if (inferredPositions.Count != inferredCount)
        {
            Skip("noncontiguous inferred method generic parameters");
            return;
        }
        for (var position = 0; position < Math.Max(methodParameters.Count, inferredCount); position++)
        {
            var parameter = new Cecil.GenericParameter("M" + position, method);
            method.GenericParameters.Add(parameter);
        }
        foreach (var (index, position) in methodParameters.Select((index, position) => (index, position)))
            methodGenericParameters.Add(index, method.GenericParameters[position]);

        if (!TryResolve(source.GetProperty("return_type"), module, owner, out var returnType,
                methodGenericParameters, method))
        {
            Skip("unsupported method return type");
            return;
        }
        var parameters = new List<(string? name, Cecil.TypeReference type)>();
        foreach (var parameter in source.GetProperty("parameters").EnumerateArray())
        {
            if (!TryResolve(parameter.GetProperty("type"), module, owner, out var parameterType,
                    methodGenericParameters, method))
            {
                Skip("unsupported method parameter type");
                return;
            }
            parameters.Add((parameter.GetProperty("name").GetString(), parameterType));
        }
        method.ReturnType = returnType;
        foreach (var (name, type) in parameters)
            method.Parameters.Add(new Cecil.ParameterDefinition(name, Cecil.ParameterAttributes.None, type));
        if (!method.IsAbstract)
        {
            method.Body.Instructions.Add(Cil.Instruction.Create(Cil.OpCodes.Ldnull));
            method.Body.Instructions.Add(Cil.Instruction.Create(Cil.OpCodes.Throw));
        }
        var address = source.GetProperty("code_rva");
        var rva = address.ValueKind == JsonValueKind.Number ? address.GetUInt64() : 0;
        if (rva != 0)
        {
            var attribute = new Cecil.CustomAttribute(_addressConstructors[module.Name]);
            attribute.Properties.Add(new Cecil.CustomAttributeNamedArgument("RVA",
                new Cecil.CustomAttributeArgument(module.ImportReference(typeof(string)), $"0x{rva:x}")));
            attribute.Properties.Add(new Cecil.CustomAttributeNamedArgument("Offset",
                new Cecil.CustomAttributeArgument(module.ImportReference(typeof(string)), "0x0")));
            method.CustomAttributes.Add(attribute);
            _addresses++;
        }
        owner.Methods.Add(method);
        _methods++;
    }

    private bool TryResolve(JsonElement source, Cecil.ModuleDefinition module,
        Cecil.TypeDefinition owner, out Cecil.TypeReference type,
        IReadOnlyDictionary<int, Cecil.GenericParameter>? methodGenericParameters = null,
        Cecil.MethodDefinition? method = null)
    {
        var kind = source.GetProperty("kind").GetInt32();
        Type? primitive = kind switch
        {
            1 => typeof(void), 2 => typeof(bool), 3 => typeof(char), 4 => typeof(sbyte),
            5 => typeof(byte), 6 => typeof(short), 7 => typeof(ushort), 8 => typeof(int),
            9 => typeof(uint), 10 => typeof(long), 11 => typeof(ulong), 12 => typeof(float),
            13 => typeof(double), 22 => typeof(TypedReference), 24 => typeof(nint),
            25 => typeof(nuint),
            _ => null,
        };
        if (primitive is not null)
        {
            type = module.ImportReference(primitive);
            return true;
        }
        if (kind is 14 or 28)
        {
            type = module.ImportReference(_coreTypes[kind == 14 ? "String" : "Object"]);
            return true;
        }
        if (kind == 19 && source.TryGetProperty("generic_parameter_index", out var genericIndex)
            && _genericStarts.TryGetValue(_typeIndices[owner], out var start))
        {
            var rawPosition = genericIndex.GetInt32() - start;
            if (rawPosition >= 0 && rawPosition < owner.GenericParameters.Count)
            {
                type = owner.GenericParameters[rawPosition];
                return true;
            }
        }
        if (kind == 19 && source.TryGetProperty("generic_parameter_position", out var typePosition))
        {
            var ownerPosition = typePosition.GetInt32();
            if (ownerPosition >= 0 && ownerPosition < owner.GenericParameters.Count)
            {
                type = owner.GenericParameters[ownerPosition];
                return true;
            }
        }
        if (kind == 30 && source.TryGetProperty("generic_parameter_index", out genericIndex)
            && methodGenericParameters is not null
            && methodGenericParameters.TryGetValue(genericIndex.GetInt32(), out var methodParameter))
        {
            type = methodParameter;
            return true;
        }
        if (kind == 30 && source.TryGetProperty("generic_parameter_position", out var methodPosition)
            && method is not null)
        {
            var methodGenericPosition = methodPosition.GetInt32();
            if (methodGenericPosition >= 0 && methodGenericPosition < method.GenericParameters.Count)
            {
                type = method.GenericParameters[methodGenericPosition];
                return true;
            }
        }
        if (kind is 17 or 18 && source.TryGetProperty("definition", out var index)
            && _types.TryGetValue(index.GetInt32(), out var definition))
        {
            type = module.ImportReference(definition);
            return true;
        }
        if (kind is 15 or 29 && source.TryGetProperty("element_type", out var element)
            && TryResolve(element, module, owner, out var elementType, methodGenericParameters, method))
        {
            type = kind == 15 ? new Cecil.PointerType(elementType) : new Cecil.ArrayType(elementType);
            return true;
        }
        if (kind == 21 && source.TryGetProperty("generic_definition", out var genericDefinition)
            && source.TryGetProperty("generic_arguments", out var genericArguments)
            && _types.TryGetValue(genericDefinition.GetInt32(), out var genericType))
        {
            var instance = new Cecil.GenericInstanceType(module.ImportReference(genericType));
            foreach (var argument in genericArguments.EnumerateArray())
            {
                if (!TryResolve(argument, module, owner, out var argumentType,
                        methodGenericParameters, method))
                {
                    type = null!;
                    return false;
                }
                instance.GenericArguments.Add(argumentType);
            }
            if (instance.GenericArguments.Count != genericType.GenericParameters.Count)
            {
                type = null!;
                return false;
            }
            type = instance;
            return true;
        }
        type = null!;
        return false;
    }

    private static void CollectMethodGenericParameterIndices(JsonElement type, ISet<int> parameters,
        ISet<int> inferredPositions)
    {
        if (type.GetProperty("kind").GetInt32() == 30
            && type.TryGetProperty("generic_parameter_index", out var genericIndex))
            parameters.Add(genericIndex.GetInt32());
        if (type.GetProperty("kind").GetInt32() == 30
            && type.TryGetProperty("generic_parameter_position", out var position))
            inferredPositions.Add(position.GetInt32());
        if (type.TryGetProperty("element_type", out var element))
            CollectMethodGenericParameterIndices(element, parameters, inferredPositions);
        if (type.TryGetProperty("generic_arguments", out var arguments))
            foreach (var argument in arguments.EnumerateArray())
                CollectMethodGenericParameterIndices(argument, parameters, inferredPositions);
    }

    private void Skip(string reason)
        => _skipped[reason] = _skipped.GetValueOrDefault(reason) + 1;
}

// Cecil resolves an enum-typed constant's field type to find its underlying type, so the
// sibling assemblies, which exist only in memory until written, must be resolvable.
sealed class BatchAssemblyResolver : Cecil.DefaultAssemblyResolver
{
    public void Register(Cecil.AssemblyDefinition assembly) => RegisterAssembly(assembly);
}
