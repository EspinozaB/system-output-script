#Requires -Version 3.0
<#
.SYNOPSIS
    Comprehensive system information gathering script for forensics, compliance, and troubleshooting.

.DESCRIPTION
    This PowerShell script collects detailed system information including hardware specs, 
    network configuration, installed software, running processes, security settings, and more.
    Designed to work with minimal privileges and provides structured output for analysis.

.PARAMETER OutputPath
    Specifies the output file path. Default is "SystemInfo_<hostname>_<timestamp>.txt"

.PARAMETER Format
    Output format: 'Text' (default), 'JSON', or 'CSV' for structured data sections

.PARAMETER IncludeEventLogs
    Include recent event log entries (requires elevated privileges for some logs)

.PARAMETER MaxEventLogEntries
    Maximum number of event log entries to retrieve (default: 10)

.EXAMPLE
    .\Get-SystemInfo.ps1
    
.EXAMPLE
    .\Get-SystemInfo.ps1 -OutputPath "C:\Reports\system_audit.txt" -Format JSON

.EXAMPLE
    .\Get-SystemInfo.ps1 -IncludeEventLogs -MaxEventLogEntries 25

.NOTES
    Created for forensics, compliance, and troubleshooting purposes.
    Works with standard user privileges for most information.
    Some sections may require elevated privileges for complete data.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [ValidateSet("Text", "JSON", "CSV")]
    [string]$Format = "Text",
    [switch]$IncludeEventLogs,
    [int]$MaxEventLogEntries = 10
)

# Initialize variables
$StartTime = Get-Date
$ComputerName = $env:COMPUTERNAME
$CurrentUser = $env:USERNAME

# Set default output path if not specified
if (-not $OutputPath) {
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = "SystemInfo_${ComputerName}_${Timestamp}.txt"
}

# Function to write section headers
function Write-SectionHeader {
    param([string]$Title)
    $separator = "=" * 60
    return "`n$separator`n=== $Title ===`n$separator`n"
}

# Function to safely execute commands and handle errors
function Invoke-SafeCommand {
    param(
        [string]$Command,
        [string]$Description = "Command execution"
    )
    
    try {
        Write-Host "Gathering: $Description" -ForegroundColor Green
        return Invoke-Expression $Command
    }
    catch {
        Write-Warning "Failed to execute: $Description - $($_.Exception.Message)"
        return "Error: Unable to retrieve $Description - $($_.Exception.Message)"
    }
}

# Function to get formatted output
function Get-FormattedOutput {
    param(
        [object]$Data,
        [string]$Format = "Text"
    )
    
    switch ($Format) {
        "JSON" { return $Data | ConvertTo-Json -Depth 3 }
        "CSV" { return $Data | ConvertTo-Csv -NoTypeInformation }
        default { return $Data | Format-Table -AutoSize | Out-String }
    }
}

Write-Host "Starting system information gathering..." -ForegroundColor Cyan
Write-Host "Output will be saved to: $OutputPath" -ForegroundColor Yellow

# Start building the output
$Output = @()
$Output += "System Information Report"
$Output += "Generated: $(Get-Date)"
$Output += "Computer: $ComputerName"
$Output += "User: $CurrentUser"
$Output += "Script Version: 2.0"
$Output += ""

# Basic System Information
$Output += Write-SectionHeader "Basic System Information"
$Output += "Date/Time: $(Get-Date)"
$Output += "Hostname: $ComputerName"
$Output += "Current User: $env:USERDOMAIN\$env:USERNAME"
$Output += "PowerShell Version: $($PSVersionTable.PSVersion)"
$Output += "OS Information:"
$Output += Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, TotalVisibleMemorySize, FreePhysicalMemory | Format-List | Out-String

# Hardware Information
$Output += Write-SectionHeader "Hardware Information"
$Output += "Computer System:"
$Output += Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Name, Manufacturer, Model, TotalPhysicalMemory, NumberOfProcessors, NumberOfLogicalProcessors | Format-List | Out-String

$Output += "Processor Information:"
$Output += Get-CimInstance -ClassName Win32_Processor | Select-Object Name, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors | Format-List | Out-String

$Output += "Memory Information:"
$Output += Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object Capacity, Speed, Manufacturer, PartNumber | Format-Table -AutoSize | Out-String

# Network Configuration
$Output += Write-SectionHeader "Network Configuration"
$Output += "Network Adapters:"
$Output += Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object Description, IPAddress, SubnetMask, DefaultIPGateway, DHCPEnabled, DNSServerSearchOrder | Format-List | Out-String

$Output += "IP Configuration (ipconfig /all):"
$Output += Invoke-SafeCommand "ipconfig /all" "IP Configuration"

$Output += "Network Statistics:"
$Output += Invoke-SafeCommand "netstat -nao" "Network Statistics"

$Output += "Routing Table:"
$Output += Invoke-SafeCommand "netstat -rn" "Routing Table"

# User and Group Information
$Output += Write-SectionHeader "User and Group Information"
$Output += "Local Users:"
$Output += Get-CimInstance -ClassName Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true } | Select-Object Name, FullName, Disabled, Lockout, PasswordRequired | Format-Table -AutoSize | Out-String

$Output += "Local Groups:"
$Output += Get-CimInstance -ClassName Win32_Group | Where-Object { $_.LocalAccount -eq $true } | Select-Object Name, Description | Format-Table -AutoSize | Out-String

$Output += "Administrators Group Members:"
$Output += Invoke-SafeCommand "net localgroup administrators" "Administrators Group"

# Installed Software
$Output += Write-SectionHeader "Installed Software"
$Output += "Programs (Registry - Current User):"
$InstalledPrograms = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -ne $null } | Sort-Object DisplayName
$Output += $InstalledPrograms | Format-Table -AutoSize | Out-String

$Output += "Programs (Registry - Local Machine):"
try {
    $InstalledProgramsLM = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -ne $null } | Sort-Object DisplayName
    $Output += $InstalledProgramsLM | Format-Table -AutoSize | Out-String
}
catch {
    $Output += "Unable to access HKLM registry (requires elevated privileges)`n"
}

# Running Processes and Services
$Output += Write-SectionHeader "Running Processes and Services"
$Output += "Running Processes:"
$Output += Get-Process | Select-Object Name, Id, CPU, WorkingSet, StartTime, Path | Sort-Object CPU -Descending | Format-Table -AutoSize | Out-String

$Output += "Running Services:"
$Output += Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName, Status, StartType | Sort-Object Name | Format-Table -AutoSize | Out-String

$Output += "Startup Programs:"
$Output += Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize | Out-String

# System Drivers
$Output += Write-SectionHeader "System Drivers"
try {
    $Output += Get-WindowsDriver -Online | Select-Object Driver, ClassName, ProviderName, Date, Version | Format-Table -AutoSize | Out-String
}
catch {
    $Output += Invoke-SafeCommand "driverquery" "System Drivers"
}

# Disk Information
$Output += Write-SectionHeader "Disk Information"
$Output += "Logical Disks:"
$Output += Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID, Description, FileSystem, Size, FreeSpace, @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}}, @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize | Out-String

$Output += "Physical Disks:"
$Output += Get-CimInstance -ClassName Win32_DiskDrive | Select-Object Model, Size, MediaType, InterfaceType | Format-Table -AutoSize | Out-String

# Environment Variables
$Output += Write-SectionHeader "Environment Variables"
$Output += "System Environment Variables:"
$Output += Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize | Out-String

# Security and Firewall
$Output += Write-SectionHeader "Security Information"
$Output += "Windows Firewall Profiles:"
try {
    $Output += Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize | Out-String
}
catch {
    $Output += Invoke-SafeCommand "netsh advfirewall show allprofiles" "Firewall Configuration"
}

$Output += "Installed Hotfixes:"
$Output += Get-HotFix | Select-Object HotFixID, InstalledOn, InstalledBy, Description | Sort-Object InstalledOn -Descending | Format-Table -AutoSize | Out-String

# Hardware Devices
$Output += Write-SectionHeader "Hardware Devices"
$Output += "Display Information:"
$Output += Get-CimInstance -ClassName Win32_VideoController | Select-Object Name, VideoProcessor, AdapterRAM, DriverVersion, DriverDate | Format-List | Out-String

$Output += "Installed Printers:"
$Output += Get-CimInstance -ClassName Win32_Printer | Select-Object Name, DriverName, PortName, PrinterStatus | Format-Table -AutoSize | Out-String

$Output += "USB Devices:"
$Output += Get-CimInstance -ClassName Win32_USBControllerDevice | ForEach-Object { [wmi]$_.Dependent } | Select-Object Name, Description, DeviceID | Format-Table -AutoSize | Out-String

# Event Logs (if requested)
if ($IncludeEventLogs) {
    $Output += Write-SectionHeader "Event Logs"
    
    $LogNames = @("System", "Application", "Security")
    foreach ($LogName in $LogNames) {
        $Output += "Recent $LogName Events:"
        try {
            $Events = Get-WinEvent -LogName $LogName -MaxEvents $MaxEventLogEntries -ErrorAction SilentlyContinue
            $Output += $Events | Select-Object TimeCreated, Id, LevelDisplayName, LogName, Message | Format-Table -AutoSize | Out-String
        }
        catch {
            $Output += "Unable to access $LogName log (may require elevated privileges)`n"
        }
    }
}

# System Performance
$Output += Write-SectionHeader "System Performance"
$Output += "System Uptime:"
$Uptime = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$Output += "Last Boot: $((Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime)"
$Output += "Uptime: $($Uptime.Days) days, $($Uptime.Hours) hours, $($Uptime.Minutes) minutes`n"

$Output += "Memory Usage:"
$OS = Get-CimInstance -ClassName Win32_OperatingSystem
$TotalRAM = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
$FreeRAM = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
$UsedRAM = $TotalRAM - $FreeRAM
$Output += "Total RAM: $TotalRAM GB"
$Output += "Free RAM: $FreeRAM GB"
$Output += "Used RAM: $UsedRAM GB"
$Output += "Memory Usage: $([math]::Round(($UsedRAM / $TotalRAM) * 100, 2))%`n"

# Completion
$EndTime = Get-Date
$Duration = $EndTime - $StartTime
$Output += Write-SectionHeader "Script Completion"
$Output += "Start Time: $StartTime"
$Output += "End Time: $EndTime"
$Output += "Duration: $($Duration.Minutes) minutes, $($Duration.Seconds) seconds"
$Output += "Output saved to: $OutputPath"

# Save output to file
try {
    $Output | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "System information successfully saved to: $OutputPath" -ForegroundColor Green
    Write-Host "Total execution time: $($Duration.Minutes) minutes, $($Duration.Seconds) seconds" -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to save output to $OutputPath - $($_.Exception.Message)"
}

# Display summary
Write-Host "`nCollection Summary:" -ForegroundColor Yellow
Write-Host "- Computer: $ComputerName" -ForegroundColor White
Write-Host "- User: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor White
Write-Host "- Output file: $OutputPath" -ForegroundColor White
Write-Host "- File size: $([math]::Round((Get-Item $OutputPath).Length / 1KB, 2)) KB" -ForegroundColor White

# Offer to open the file
$OpenFile = Read-Host "`nWould you like to open the output file? (y/n)"
if ($OpenFile -eq 'y' -or $OpenFile -eq 'Y') {
    try {
        Start-Process notepad.exe -ArgumentList $OutputPath
    }
    catch {
        Write-Warning "Unable to open file automatically. Please navigate to: $OutputPath"
    }
}