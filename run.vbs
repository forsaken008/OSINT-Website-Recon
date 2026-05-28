' Deep Web Recon — silent launcher
' Runs pythonw.exe with no visible window (wscript has no console by default)
Dim sDir, oShell
sDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
Set oShell = CreateObject("WScript.Shell")
oShell.Run """C:\Users\petermommsen\AppData\Local\Python\bin\pythonw.exe"" """ & sDir & "DeepWebRecon.py""", 0, False
