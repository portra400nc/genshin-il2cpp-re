using Mono.Cecil;
using Mono.Cecil.Cil;

internal static class CoreModulePatches
{
    public static void Apply(string outputDirectory, ulong applicationQuitRva)
    {
        var path = Path.Combine(outputDirectory, "UnityEngine.CoreModule.dll");
        using var assembly = AssemblyDefinition.ReadAssembly(path);
        var module = assembly.MainModule;
        var oldMethods = module.GetTypes()
            .SelectMany(type => type.Methods.Select((method, index) =>
                (method.MetadataToken, type.FullName, index, method.FullName)))
            .ToArray();
        var applicationQuit = module.GetTypes().Single(type =>
            type.FullName == "UnityEngine.Application").Methods.Single(method =>
            method.Name == "Quit" && method.Parameters.Count == 0);
        var oldQuitToken = applicationQuit.MetadataToken.ToInt32();
        var handle = module.GetTypes().Single(type =>
            type.FullName == "Unity.IL2CPP.RuntimeServices.Il2CppRuntimeClassHandle");
        var handleField = handle.Fields.Single(field => field.Name == "m_Handle"
            && field.FieldType.MetadataType == MetadataType.IntPtr);

        foreach (var (ownerName, methodName) in new[]
                 {
                     ("GameObject", "AddComponent"),
                     ("GameObject", "GetComponent"),
                     ("Component", "GetComponent"),
                 })
        {
            var owner = module.GetTypes().Single(type =>
                type.Namespace == "UnityEngine" && type.Name == ownerName);
            var generic = owner.Methods.Single(method => method.Name == methodName
                && method.Parameters.Count == 0 && method.GenericParameters.Count == 1);
            var classHandle = owner.Methods.Single(method => method.Name == methodName
                && method.Parameters.Count == 1
                && method.Parameters[0].ParameterType.FullName == handle.FullName);
            if (generic.ReturnType is not GenericParameter resultType
                || resultType.Type != GenericParameterType.Method
                || resultType.Position != 0
                || classHandle.ReturnType.FullName != "UnityEngine.Component")
                throw new InvalidDataException($"Unexpected {ownerName}.{methodName}<T> signature");

            var nativeClassPtr = FindNativeClassPointer(generic);
            var objectPointer = FindObjectPointer(classHandle);
            var pooledObject = FindObjectPoolGet(classHandle, generic.GenericParameters[0]);
            Rewrite(generic, classHandle, handle, handleField, nativeClassPtr,
                objectPointer, pooledObject);
            Console.WriteLine($"Patched {ownerName}.{methodName}<T> through class handle");
        }
        PatchNamedColors(module);

        var temporary = path + ".patched";
        assembly.Write(temporary);
        File.Move(temporary, path, true);
        using var rewritten = AssemblyDefinition.ReadAssembly(path);
        var newTypes = rewritten.MainModule.GetTypes()
            .ToDictionary(type => type.FullName);
        var tokenChanges = new Dictionary<int, int>();
        foreach (var (oldToken, ownerName, index, signature) in oldMethods)
        {
            var current = newTypes[ownerName].Methods[index];
            if (current.FullName != signature)
                throw new InvalidDataException($"Method order changed for {signature}");
            tokenChanges.Add(oldToken.ToInt32(), current.MetadataToken.ToInt32());
        }
        RemapAddressDatabase(outputDirectory, applicationQuitRva, oldQuitToken, tokenChanges);
    }

    private static void PatchNamedColors(ModuleDefinition module)
    {
        var color = module.GetTypes().Single(type => type.FullName == "UnityEngine.Color");
        if (!color.IsValueType)
            throw new InvalidDataException("Generated UnityEngine.Color is not a value type");
        var fields = new[] { "r", "g", "b", "a" }.Select(name =>
            color.Fields.Single(field => field.Name == name
                && field.FieldType.MetadataType == MetadataType.Single)).ToArray();
        var values = new Dictionary<string, float[]>
        {
            ["red"] = [1f, 0f, 0f, 1f],
            ["green"] = [0f, 1f, 0f, 1f],
            ["blue"] = [0f, 0f, 1f, 1f],
            ["white"] = [1f, 1f, 1f, 1f],
            ["black"] = [0f, 0f, 0f, 1f],
            ["yellow"] = [1f, 1f, 0f, 1f],
            ["cyan"] = [0f, 1f, 1f, 1f],
            ["magenta"] = [1f, 0f, 1f, 1f],
            ["gray"] = [0.5f, 0.5f, 0.5f, 1f],
            ["grey"] = [0.5f, 0.5f, 0.5f, 1f],
            ["clear"] = [0f, 0f, 0f, 0f],
        };
        foreach (var (name, components) in values)
        {
            var method = color.Methods.Single(candidate => candidate.Name == $"get_{name}"
                && candidate.Parameters.Count == 0);
            if (!method.IsStatic || method.ReturnType.FullName != color.FullName)
                throw new InvalidDataException($"Unexpected Color.{name} getter signature");
            var body = new MethodBody(method) { InitLocals = true, MaxStackSize = 2 };
            var result = new VariableDefinition(color);
            body.Variables.Add(result);
            var il = body.GetILProcessor();
            il.Append(Instruction.Create(OpCodes.Ldloca_S, result));
            il.Append(Instruction.Create(OpCodes.Initobj, color));
            for (var index = 0; index < fields.Length; index++)
            {
                il.Append(Instruction.Create(OpCodes.Ldloca_S, result));
                il.Append(Instruction.Create(OpCodes.Ldc_R4, components[index]));
                il.Append(Instruction.Create(OpCodes.Stfld, fields[index]));
            }
            il.Append(Instruction.Create(OpCodes.Ldloc, result));
            il.Append(Instruction.Create(OpCodes.Ret));
            method.Body = body;
        }
        Console.WriteLine($"Patched {values.Count} named Color getters with literal values");
    }

    private static void RemapAddressDatabase(string outputDirectory, ulong knownRva,
        int knownToken, Dictionary<int, int> tokenChanges)
    {
        var path = Path.Combine(outputDirectory, "MethodAddressToToken.db");
        var data = File.ReadAllBytes(path);
        var count = BitConverter.ToInt32(data, 12);
        var offset = BitConverter.ToInt32(data, 16);
        if (BitConverter.ToInt32(data, 0) != 0x4D544D55
            || count <= 0 || offset < 20 || (long)offset + 16L * count > data.Length)
            throw new InvalidDataException("Generated method address map is invalid");
        var knownIndex = Enumerable.Range(0, count).Single(index =>
            BitConverter.ToUInt64(data, offset + 8 * index) == knownRva
            && BitConverter.ToInt32(data, offset + 8 * count + 8 * index) == knownToken);
        var coreAssembly = BitConverter.ToInt32(data, offset + 8 * count + 8 * knownIndex + 4);
        var changed = 0;
        for (var index = 0; index < count; index++)
        {
            var tokenOffset = offset + 8 * count + 8 * index;
            if (BitConverter.ToInt32(data, tokenOffset + 4) != coreAssembly)
                continue;
            var oldToken = BitConverter.ToInt32(data, tokenOffset);
            if (!tokenChanges.TryGetValue(oldToken, out var newToken))
                throw new InvalidDataException($"Unmapped CoreModule method token 0x{oldToken:x8}");
            BitConverter.GetBytes(newToken).CopyTo(data, tokenOffset);
            changed++;
        }
        if (changed == 0)
            throw new InvalidDataException("No CoreModule method addresses were remapped");
        File.WriteAllBytes(path, data);
        Console.WriteLine($"Remapped {changed} CoreModule method addresses after Cecil write");
    }

    private static FieldReference FindNativeClassPointer(MethodDefinition generic)
    {
        var source = generic.DeclaringType.NestedTypes
            .SelectMany(type => type.Methods)
            .Where(method => method.Name == ".cctor" && method.HasBody)
            .SelectMany(method => method.Body.Instructions)
            .Select(instruction => instruction.Operand)
            .OfType<FieldReference>()
            .First(field => field.Name == "NativeClassPtr"
                && field.DeclaringType.GetElementType().FullName
                    == "Il2CppInterop.Runtime.Il2CppClassPointerStore`1");
        var closedStore = new GenericInstanceType(source.DeclaringType.GetElementType());
        closedStore.GenericArguments.Add(generic.GenericParameters[0]);
        return new FieldReference(source.Name, source.FieldType, closedStore);
    }

    private static MethodReference FindObjectPointer(MethodDefinition classHandle)
        => classHandle.Body.Instructions
            .Select(instruction => instruction.Operand)
            .OfType<MethodReference>()
            .First(method => method.Name == "Il2CppObjectBaseToPtrNotNull"
                && method.DeclaringType.FullName == "Il2CppInterop.Runtime.IL2CPP");

    private static MethodReference FindObjectPoolGet(MethodDefinition classHandle,
        GenericParameter resultType)
    {
        var source = classHandle.Body.Instructions
            .Select(instruction => instruction.Operand)
            .OfType<GenericInstanceMethod>()
            .First(method => method.Name == "Get"
                && method.DeclaringType.FullName
                    == "Il2CppInterop.Runtime.Runtime.Il2CppObjectPool");
        var pooledObject = new GenericInstanceMethod(source.ElementMethod);
        pooledObject.GenericArguments.Add(resultType);
        return pooledObject;
    }

    private static void Rewrite(MethodDefinition generic, MethodDefinition classHandle,
        TypeDefinition handle, FieldDefinition handleField, FieldReference nativeClassPtr,
        MethodReference objectPointer, MethodReference pooledObject)
    {
        var body = new MethodBody(generic) { InitLocals = true, MaxStackSize = 2 };
        var handleLocal = new VariableDefinition(handle);
        var componentLocal = new VariableDefinition(classHandle.ReturnType);
        body.Variables.Add(handleLocal);
        body.Variables.Add(componentLocal);
        var found = Instruction.Create(OpCodes.Ldloc, componentLocal);
        var il = body.GetILProcessor();
        il.Append(Instruction.Create(OpCodes.Ldloca_S, handleLocal));
        il.Append(Instruction.Create(OpCodes.Initobj, handle));
        il.Append(Instruction.Create(OpCodes.Ldloca_S, handleLocal));
        il.Append(Instruction.Create(OpCodes.Ldsfld, nativeClassPtr));
        il.Append(Instruction.Create(OpCodes.Stfld, handleField));
        il.Append(Instruction.Create(OpCodes.Ldarg_0));
        il.Append(Instruction.Create(OpCodes.Ldloc, handleLocal));
        il.Append(Instruction.Create(OpCodes.Call, classHandle));
        il.Append(Instruction.Create(OpCodes.Stloc, componentLocal));
        il.Append(Instruction.Create(OpCodes.Ldloc, componentLocal));
        il.Append(Instruction.Create(OpCodes.Brtrue_S, found));
        il.Append(Instruction.Create(OpCodes.Ldnull));
        il.Append(Instruction.Create(OpCodes.Ret));
        il.Append(found);
        il.Append(Instruction.Create(OpCodes.Call, objectPointer));
        il.Append(Instruction.Create(OpCodes.Call, pooledObject));
        il.Append(Instruction.Create(OpCodes.Ret));
        generic.Body = body;
    }
}
