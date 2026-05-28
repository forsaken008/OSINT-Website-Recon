' Deep Web Recon — silent launcher
' Runs pythonw from PATH with no visible window (wscript has no console by default).
' Works on any Windows machine as long as Python is installed and in PATH.
Dim sDir, oShell
sDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
Set oShell = CreateObject("WScript.Shell")
oShell.Run "pythonw """ & sDir & "DeepWebRecon.py""", 0, False
