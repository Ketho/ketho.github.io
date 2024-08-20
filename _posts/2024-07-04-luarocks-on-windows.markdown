---
layout: post
title: "Setting up LuaRocks on Windows"
date: 2024-07-04 +0200
categories: jekyll update
---
![](https://ketho.github.io/data/lua/logo.jpg)

## Lua
[Lua](https://www.lua.org/) is a scripting language which is simple and quite easy to learn. It's used in games like [World of Warcraft](https://warcraft.wiki.gg/wiki/World_of_Warcraft_API) and [Minetest](https://www.minetest.net/), and software like [Wireshark](https://www.wireshark.org/) and [MediaWiki](https://www.mediawiki.org/wiki/Extension:Scribunto).

[LuaRocks](https://luarocks.org/) is the package manager for Lua to install modules. But it's difficult to set up on Windows, compared to on Unix. Its ecosystem is smaller compared to ones for other languages, and any issues are more difficult to debug; which is why I'd advocate for using Python instead of Lua.

I personally use Lua for generating [LuaLS](https://github.com/LuaLS/lua-language-server) annotations for a WoW [VS Code extension](https://github.com/Ketho/vscode-wow-api) which needs to load the [Blizzard_APIDocumentation](https://github.com/Gethe/wow-ui-source/tree/live/Interface/AddOns/Blizzard_APIDocumentationGenerated) Lua files.

## Install
This guide is for setting up Lua 5.4 64-bit. Note that Lua has no installer, you just get the available Windows binaries. We also need MinGW for Windows to be able to install LuaRocks modules.

Requirements:
- Lua binary: [lua-5.4.2_Win64_bin.zip](https://sourceforge.net/projects/luabinaries/files/5.4.2/Tools%20Executables/lua-5.4.2_Win64_bin.zip/download)
  - from [https://sourceforge.net/projects/luabinaries/files/5.4.2/Tools%20Executables/](https://sourceforge.net/projects/luabinaries/files/5.4.2/Tools%20Executables/)
- Lua library: [lua-5.4.2_Win64_vc17_lib](https://sourceforge.net/projects/luabinaries/files/5.4.2/Windows%20Libraries/Static/lua-5.4.2_Win64_vc17_lib.zip/download)
  - from [https://sourceforge.net/projects/luabinaries/files/5.4.2/Windows%20Libraries/Static/](https://sourceforge.net/projects/luabinaries/files/5.4.2/Windows%20Libraries/Static/)
- LuaRocks: [luarocks-3.11.1-windows-64](https://luarocks.org/releases/luarocks-3.11.1-windows-64.zip) (all-in-one package)
  - from [https://github.com/luarocks/luarocks/wiki/Download](https://github.com/luarocks/luarocks/wiki/Download)
- MinGW: [winlibs-x86_64-posix-seh-gcc-14.2.0-llvm-18.1.8-mingw-w64ucrt-12.0.0-r1.zip](https://github.com/brechtsanders/winlibs_mingw/releases/download/14.2.0posix-18.1.8-12.0.0-ucrt-r1/winlibs-x86_64-posix-seh-gcc-14.2.0-llvm-18.1.8-mingw-w64ucrt-12.0.0-r1.zip)
  - from [https://winlibs.com/](https://winlibs.com/)
- OpenSSL: `openssl-3.0.2-win64-mingw` (for LuaSec)
  - from [https://curl.se/windows/](https://curl.se/windows/) but they [no longer](https://archive.is/Ogwbv) provide OpenSSL windows binaries, and I could not find any similar distributions so use this [mirror](https://github.com/Ketho/ketho.github.io/raw/main/data/lua/openssl-3.0.2-win64-mingw.zip) at your own risk.

### Notes
- Either static (vc17) or dynamic (dll17) Lua libraries can be used, the only thing we need is the `include` folder from it and to move that into our Lua folder, e.g. `lua-5.4.2_Win64_bin/include`.
- This requires installing [PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4) and changing the [execution policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.4); please do this at your own risk.
```ps1
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
```

This PowerShell script tries to automate the setup steps, but I suggest going through it step for step in case of any errors.
```powershell
# your work directory
$base = "D:/Dev"

# https://sourceforge.net/projects/luabinaries/files/5.4.2/Tools%20Executables/ -> lua-5.4.2_Win64_bin.zip
# https://sourceforge.net/projects/luabinaries/files/5.4.2/Windows%20Libraries/Static/ -> lua-5.4.2_Win64_vc17_lib.zip
$lua = "$base/lua-5.4.2_Win64_bin"
# https://github.com/luarocks/luarocks/wiki/Download
$luarocks = "$base/luarocks-3.11.1-windows-64"
# https://winlibs.com/ -> GCC 14.2.0 (with POSIX threads) + LLVM/Clang/LLD/LLDB 18.1.8 + MinGW-w64 12.0.0 UCRT - release 1
$mingw = "$base/winlibs-x86_64-posix-seh-gcc-14.2.0-llvm-18.1.8-mingw-w64ucrt-12.0.0-r1\mingw64\bin"
# https://curl.se/windows/ (no longer available)
$openssl = "$base/openssl-3.0.2-win64-mingw\bin"

# add to windows path
$env:path = $env:path + ($lua, $luarocks, $mingw, $openssl -join ";")
[Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

# set luarocks path
setx -m LUA_PATH "$luarocks\lua\?.lua;$luarocks\lua\?\init.lua;$luarocks\?.lua;$luarocks\?\init.lua;$luarocks\..\share\lua\5.4\?.lua;$luarocks\..\share\lua\5.4\?\init.lua;.\?.lua;.\?\init.lua;$env:APPDATA/luarocks/share/lua/5.4/?.lua;$env:APPDATA/luarocks/share/lua/5.4/?/init.lua"
setx -m LUA_CPATH "$luarocks\?.dll;$luarocks\..\lib\lua\5.4\?.dll;$luarocks\loadall.dll;.\?.dll;$env:APPDATA/luarocks/lib/lua/5.4/?.dll"

# create luarocks config
New-Item -Force -Path "$env:APPDATA/luarocks" -Name "config-5.4.lua" -Value "
variables.LUA_DIR = '$lua'
--variables.LUA_BINDIR = '$lua'
variables.LUA_INCDIR = '$lua/include'
variables.LUA_LIBDIR = '$lua'"

luarocks install luafilesystem
luarocks install lua-path
luarocks install luasocket
luarocks install luasec OPENSSL_DIR=$openssl
luarocks install xml2lua
luarocks install lua-cjson
luarocks install gumbo
luarocks install csv
```

## Issues
### PowerShell script
There is a caveat with this script I haven't solved. Any user variables (vs system varables) also show up in the path so they get duplicated. You will need to delete them afterwards from the system variables.
```powershell
$env:path = $env:path + ($lua, $luarocks, $mingw, $openssl -join ";")
[Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
```
For example these paths would show up twice in the system variables.

![](https://ketho.github.io/data/lua/uservars.png)

### LuaSocket
The latest [LuaSocket](https://luarocks.org/modules/lunarmodules/luasocket) version `scm-3` has an issue on Windows.
- [https://github.com/lunarmodules/luasocket/pull/433](https://github.com/lunarmodules/luasocket/pull/433)

Until the pull request has been merged you will need to download the [rockspec](https://github.com/lunarmodules/luasocket/blob/master/luasocket-scm-3.rockspec), apply the [patch](https://github.com/lunarmodules/luasocket/pull/433/files) to the rockspec and install it manually.
```
luarocks install .\luasocket-scm-3.rockspec
```

## Testing
This should print the html contents of a website.
```lua
local https = require "ssl.https"

local url = "https://www.google.com/"
local body = https.request(url)
print(body)
```
