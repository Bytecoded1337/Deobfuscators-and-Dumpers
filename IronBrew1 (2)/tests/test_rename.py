from ironbrew1_deobf.rename import semantic_rename_lua

src = '''
local v1 = Instance.new("ScreenGui")
local v2 = Instance.new("Frame")
local v3 = game:GetService("Players")
local v4 = v3.LocalPlayer
print("v1 must stay inside this string")
'''

out, names = semantic_rename_lua(src)
assert 'local screenGui = Instance.new("ScreenGui")' in out
assert 'local frame = Instance.new("Frame")' in out
assert 'local players = game:GetService("Players")' in out
assert 'local localPlayer = players.LocalPlayer' in out
assert '"v1 must stay inside this string"' in out
