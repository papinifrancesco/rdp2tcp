# rdp2tcp virtual channel plugin for mstsc.exe

`rdp2tcp_vc.dll` lets the Microsoft RDP client (`mstsc.exe`) carry the
rdp2tcp virtual channel. FreeRDP ships its own `rdp2tcp` channel, so this
plugin is only needed for mstsc.

The plugin contains no tunnelling logic. Exactly like FreeRDP's channel, it
spawns `rdp2tcp.exe` as a child process with anonymous pipes on its
stdin/stdout and shuttles bytes between those pipes and the virtual channel.
Both RDP clients therefore drive the same client binary.

## Build

    make plugin-mingw32      # -> plugin/rdp2tcp_vc.dll
    make client-mingw32      # -> client/rdp2tcp.exe

Both are 64-bit (`x86_64-w64-mingw32`). `mstsc.exe` is 64-bit on 64-bit
Windows and will not load a 32-bit plugin.

## Install

Put `rdp2tcp_vc.dll` and `rdp2tcp.exe` in the same directory — the plugin
looks for the helper next to itself. Then register the add-in:

    reg add "HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\rdp2tcp" ^
        /v Name /t REG_SZ /d "C:\path\to\rdp2tcp_vc.dll" /f

Restart `mstsc.exe` and connect. On the server side, run `rdp2tcp.exe`
(the one built from `server/`) inside the RDP session as usual.

To remove it:

    reg delete "HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\rdp2tcp" /f

## Configuration

| Variable | Effect |
| --- | --- |
| `RDP2TCP_EXE` | Full path to the client helper, overriding the default of `rdp2tcp.exe` beside the DLL. |

The controller still listens on `127.0.0.1:8477`, so `tools/rdp2tcp.py`
works unchanged.

## Troubleshooting

The plugin has no console to print to, so it logs through
`OutputDebugString`. Run [DebugView](https://learn.microsoft.com/sysinternals/downloads/debugview)
and filter on `[rdp2tcp]` to see channel registration, the helper command
line, and any spawn failures.

If nothing appears at all, mstsc did not load the DLL — check that the
registry path and the `Name` value are right, and that the DLL is 64-bit.
