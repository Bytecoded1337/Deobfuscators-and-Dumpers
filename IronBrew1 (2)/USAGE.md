# CLI quick reference

## One command

```powershell
ib1 all input.lua -o out
```

## Verify a suspected payload mismatch

If you still have the unobfuscated input:

```powershell
ib1 all input.lua -o out --against original.lua
```

Read `out/compare.txt` and `out/compare.json`.

## Work stage-by-stage

```powershell
ib1 unpack input.lua -o serialized.bin
ib1 dump serialized.bin -o out
ib1 recover serialized.bin -o out/recovered.lua
ib1 compare out/constants.json out/recovered.lua -o out
```

## Roblox renaming

```powershell
ib1 rename decompiled.lua -o readable.lua
```

The generated `readable.renames.json` records every rename.

## Opcode mapping

Create a JSON file:

```json
{
  "13": "GETGLOBAL",
  "24": "CALL"
}
```

Then:

```powershell
ib1 all input.lua -o out --opcode-map opcode_map.json
```

Known names are attached as comments in `recovered.lua` while numeric opcode IDs remain preserved.
