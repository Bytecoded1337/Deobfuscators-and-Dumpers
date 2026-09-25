# IronBrew1 Deobfuscation / Analyze
This project decodes the IronBrew1 wrapper format from the included sample, parses its serialized prototype tree, dumps constants/instructions, emits a conservative `recovered.lua`, compares recovered literals against the dumped constants, and can semantically rename common Roblox locals.

## Important
`recovered.lua` intentionally does **not** invent VM semantics. Until an opcode is mapped, it stays as an explicit `__ib1_op(...)` entry. This makes the output trustworthy for analysis instead of silently turning unknown handlers into incorrect Lua.

## Install
```powershell
py -m pip install -e .
```
Then use either `ib1 ...`, `py -m ironbrew1_deobf ...`, or the zero-install launcher `py ib1.py ...`.

## Full pipeline
```powershell
ib1 all sample/input_obfuscated.lua -o out
```
Optional map:
```powershell
ib1 all sample/input_obfuscated.lua -o out --opcode-map examples/opcode_map.example.json
```
If you have the source from *before* obfuscation, compare it too:
```powershell
ib1 all sample/input_obfuscated.lua -o out --against original.lua
```

## Individual commands
```powershell
ib1 unpack input.lua -o serialized.bin
ib1 dump serialized.bin -o out
ib1 recover serialized.bin -o recovered.lua
ib1 compare out/constants.json out/recovered.lua -o out
ib1 rename decompiled.lua -o renamed.lua
```

## Output from `all`
- `serialized.bin` - decompressed IronBrew1 serialized stream
- `summary.json` - counts and opcode frequencies
- `manifest.json` - hashes, artifacts and comparison summary
- `prototypes.json` - prototype metadata
- `constants.json` - machine-readable constant pool
- `constants.txt` - human-readable constants by prototype
- `constants.csv` - spreadsheet-friendly constants
- `strings.txt` - only string constants
- `opcodes.csv` - every parsed instruction
- `ir.txt` - human-readable VM IR
- `recovered.lua` - valid Lua analysis representation
- `compare.json` - machine-readable constant/recovered comparison
- `compare.txt` - human-readable comparison

## Constant comparison
The default comparison checks whether each dumped string constant is represented in `recovered.lua`. Because `recovered.lua` deliberately contains each prototype's constant table, this is a representation-integrity check, **not proof that VM semantics have been recovered**.
`--against original.lua` is stronger: it compares dumped constants to the string literals in your known pre-obfuscation source and helps detect a stale/wrong embedded payload.

## Renamer
The renamer recognizes patterns such as:
```lua
local v1 = Instance.new("ScreenGui")
local v2 = game:GetService("Players")
local v3 = v2.LocalPlayer
```
and turns them into names such as `screenGui`, `players`, and `localPlayer`. It avoids replacing identifiers inside quoted strings/comments.
## Next stage
The remaining hard part is the VM handler/opcode lifter. Add known encoded-opcode names to an opcode-map JSON as handlers are identified. Once handler semantics are known, `recover.py` can be upgraded from `__ib1_op` IR to actual Lua statements and expressions.

## External decompiler hook
After the VM lifter eventually reconstructs **real standard Lua/Luau bytecode**, you can invoke any local open-source decompiler without hard-coding one into the project:
```powershell
ib1 decompile-external rebuilt.luac --exe C:\tools\luadec.exe -o decompiled.lua
```
Extra command-line arguments can be repeated with `--arg`. Do **not** pass `serialized.bin` directly to a Lua/Luau decompiler; it is the IronBrew1 private serialized format, not a standard chunk.

**Open sourced by Bytecode1337** *(not made by)*