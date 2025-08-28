# Enhanced PowerShell script for comprehensive system information gathering
# Designed for forensics, compliance, and troubleshooting with minimal privilege requirements
# Output saved to multiple formats for different analysis needs

param(
    [switch]$NoElevationCheck,
    [string]$OutputPath = (Get-Location),
    [switch]$SkipSensitive,
    [switch]$SkipSFC
)

try {
    # Start timing
    $scriptStartTime = Get-Date
    
    Write-Host "Enhanced System Information Gathering Tool" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Script started at: $($scriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray

    # Check if running as admin (informational only)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($isAdmin) {
        Write-Host "[INFO] Running with administrative privileges - full data collection available" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Running with standard privileges - some data may be limited" -ForegroundColor Yellow
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $hostname = $env:COMPUTERNAME
    $basePath = $OutputPath
    
    # Output files
    $txtOutput = Join-Path -Path $basePath -ChildPath "system_report_${hostname}_$timestamp.txt"
    $csvPrograms = Join-Path -Path $basePath -ChildPath "installed_programs_${hostname}_$timestamp.csv"
    $csvProcesses = Join-Path -Path $basePath -ChildPath "running_processes_${hostname}_$timestamp.csv"
    $csvServices = Join-Path -Path $basePath -ChildPath "services_${hostname}_$timestamp.csv"
    $csvNetwork = Join-Path -Path $basePath -ChildPath "network_connections_${hostname}_$timestamp.csv"
    $csvUsers = Join-Path -Path $basePath -ChildPath "user_accounts_${hostname}_$timestamp.csv"
    $csvDrivers = Join-Path -Path $basePath -ChildPath "drivers_${hostname}_$timestamp.csv"
    $csvStartup = Join-Path -Path $basePath -ChildPath "startup_programs_${hostname}_$timestamp.csv"
    $csvHardware = Join-Path -Path $basePath -ChildPath "hardware_info_${hostname}_$timestamp.csv"
    $csvCertificates = Join-Path -Path $basePath -ChildPath "certificates_${hostname}_$timestamp.csv"
    $csvScheduledTasks = Join-Path -Path $basePath -ChildPath "scheduled_tasks_${hostname}_$timestamp.csv"
    $csvEventLogs = Join-Path -Path $basePath -ChildPath "recent_events_${hostname}_$timestamp.csv"

    # Initialize report
    $encoding = New-Object System.Text.UTF8Encoding $false
    $reportHeader = @"
=== ENHANCED SYSTEM INFORMATION REPORT ===
Generated: $(Get-Date)
Script Started: $scriptStartTime
Hostname: $hostname
User: $env:USERNAME
Domain: $env:USERDOMAIN
Administrative Rights: $isAdmin
PowerShell Version: $($PSVersionTable.PSVersion)
OS: $([System.Environment]::OSVersion.VersionString)

"@
    $reportHeader | Out-File -FilePath $txtOutput -Encoding UTF8

    function Get-ElapsedTime {
        $elapsed = (Get-Date) - $scriptStartTime
        return "{0:D2}:{1:D2}:{2:D2}" -f $elapsed.Hours, $elapsed.Minutes, $elapsed.Seconds
    }

    function Append-Section($title, $content) {
        $sectionHeader = "`r`n$('='*50)`r`n$title`r`n$('='*50)"
        Add-Content -Path $txtOutput -Value $sectionHeader
        if ($content) {
            $content | Out-String | ForEach-Object { $_.TrimEnd() } | Out-File -Append -FilePath $txtOutput -Encoding UTF8
        } else {
            Add-Content -Path $txtOutput -Value "[No data available or access denied]"
        }
    }

    function Safe-Execute($scriptBlock, $errorMessage = "Access denied or command failed", $timeoutSeconds = 30) {
        try {
            if ($timeoutSeconds -gt 0) {
                $job = Start-Job -ScriptBlock $scriptBlock
                if (Wait-Job $job -Timeout $timeoutSeconds) {
                    $result = Receive-Job $job
                    Remove-Job $job
                    return $result
                } else {
                    Remove-Job $job -Force
                    Write-Warning "$errorMessage : Operation timed out after $timeoutSeconds seconds"
                    return "Operation timed out - data collection skipped"
                }
            } else {
                & $scriptBlock
            }
        } catch {
            Write-Warning "$errorMessage : $($_.Exception.Message)"
            return $null
        }
    }

    function Test-KeyPress($key) {
        if ([Console]::KeyAvailable) {
            $pressedKey = [Console]::ReadKey($true)
            return $pressedKey.Key -eq $key
        }
        return $false
    }

    function Start-InterruptibleOperation($scriptBlock, $message, $cancelKey = 'X', $timeoutMinutes = 5) {
        Write-Host "$message" -ForegroundColor Yellow
        Write-Host "    Press '$cancelKey' to skip this operation..." -ForegroundColor Cyan
        
        $job = Start-Job -ScriptBlock $scriptBlock
        $timeout = (Get-Date).AddMinutes($timeoutMinutes)
        
        while ((Get-Date) -lt $timeout -and $job.State -eq 'Running') {
            if (Test-KeyPress $cancelKey) {
                Write-Host "    Operation cancelled by user" -ForegroundColor Yellow
                Remove-Job $job -Force
                return "Operation cancelled by user - press '$cancelKey' was detected"
            }
            Start-Sleep -Milliseconds 500
        }
        
        if ($job.State -eq 'Running') {
            Write-Host "    Operation timed out after $timeoutMinutes minutes" -ForegroundColor Yellow
            Remove-Job $job -Force
            return "Operation timed out after $timeoutMinutes minutes"
        } else {
            $result = Receive-Job $job
            Remove-Job $job
            Write-Host "    Operation completed successfully" -ForegroundColor Green
            return $result
        }
    }

    # Enhanced step tracking
    $steps = @(
        "System Overview", "Hardware Information", "Operating System Details", 
        "User Accounts & Security", "Network Configuration", "Installed Software",
        "System Services", "Startup Programs", "Running Processes", "Drivers",
        "Storage Information", "Environment & Registry", "Event Logs", 
        "Security Configuration", "Performance Counters", "System Files",
        "Certificates", "Scheduled Tasks", "USB/Hardware History", 
        "Browser Information", "Recent Activity", "System Integrity"
    )
    $stepCount = 0

    function Show-Progress($step) {
        $percent = [math]::Round(($script:stepCount / $steps.Count) * 100)
        $elapsed = Get-ElapsedTime
        Write-Host "[$percent%] [$elapsed] Collecting: $step..." -ForegroundColor Cyan
        $script:stepCount++
    }
    
    function Complete-Progress($step) {
        $percent = [math]::Round(($script:stepCount / $steps.Count) * 100)
        $elapsed = Get-ElapsedTime
        Write-Host "[$percent%] [$elapsed] Completed: $step" -ForegroundColor Green
    }

    # System Overview
    Show-Progress $steps[$stepCount]
    $systemInfo = Safe-Execute { Get-ComputerInfo }
    Append-Section "SYSTEM OVERVIEW" $systemInfo

    # Hardware Information  
    Show-Progress $steps[$stepCount]
    $cpu = Safe-Execute { Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors }
    $memory = Safe-Execute { Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer, Capacity, Speed, PartNumber }
    $motherboard = Safe-Execute { Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber }
    $bios = Safe-Execute { Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Version, ReleaseDate, SerialNumber }
    
    # Combine hardware info for CSV
    $hardwareInfo = @()
    if ($cpu) {
        foreach ($proc in $cpu) {
            $hardwareInfo += [PSCustomObject]@{
                Component = "CPU"
                Name = $proc.Name
                Manufacturer = $proc.Manufacturer
                Details = "Cores: $($proc.NumberOfCores), Logical: $($proc.NumberOfLogicalProcessors), Speed: $($proc.MaxClockSpeed)MHz"
            }
        }
    }
    if ($memory) {
        foreach ($mem in $memory) {
            $hardwareInfo += [PSCustomObject]@{
                Component = "Memory"
                Name = $mem.PartNumber
                Manufacturer = $mem.Manufacturer
                Details = "Capacity: $([math]::Round($mem.Capacity/1GB,2))GB, Speed: $($mem.Speed)MHz"
            }
        }
    }
    if ($motherboard) {
        $hardwareInfo += [PSCustomObject]@{
            Component = "Motherboard"
            Name = $motherboard.Product
            Manufacturer = $motherboard.Manufacturer
            Details = "Serial: $($motherboard.SerialNumber)"
        }
    }
    if ($bios) {
        $hardwareInfo += [PSCustomObject]@{
            Component = "BIOS/UEFI"
            Name = $bios.Version
            Manufacturer = $bios.Manufacturer
            Details = "Release: $($bios.ReleaseDate), Serial: $($bios.SerialNumber)"
        }
    }
    $hardwareInfo | Export-Csv -Path $csvHardware -NoTypeInformation -ErrorAction SilentlyContinue
    
    Append-Section "CPU INFORMATION" $cpu
    Append-Section "MEMORY MODULES" $memory
    Append-Section "MOTHERBOARD" $motherboard
    Append-Section "BIOS/UEFI" $bios

    # Operating System Details
    Show-Progress $steps[$stepCount]
    $osInfo = Safe-Execute { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, InstallDate, LastBootUpTime, TotalVisibleMemorySize }
    $timezone = Safe-Execute { Get-TimeZone }
    $updates = Safe-Execute { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 }
    
    Append-Section "OPERATING SYSTEM" $osInfo
    Append-Section "TIMEZONE" $timezone
    Append-Section "RECENT UPDATES (Last 20)" $updates

    # User Accounts & Security
    Show-Progress $steps[$stepCount]
    $localUsers = Safe-Execute { Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordExpires }
    $localGroups = Safe-Execute { Get-LocalGroup }
    $adminMembers = Safe-Execute { Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue }
    $userProfiles = Safe-Execute { Get-CimInstance Win32_UserProfile | Where-Object { $_.Special -eq $false } | Select-Object LocalPath, LastUseTime, SID }
    $logonSessions = Safe-Execute { Get-CimInstance Win32_LogonSession | Select-Object LogonId, LogonType, StartTime }
    
    # Export user information to CSV
    $userInfo = @()
    if ($localUsers) {
        foreach ($user in $localUsers) {
            $userInfo += [PSCustomObject]@{
                Type = "LocalUser"
                Name = $user.Name
                Enabled = $user.Enabled
                LastLogon = $user.LastLogon
                PasswordRequired = $user.PasswordRequired
                PasswordExpires = $user.PasswordExpires
                Details = ""
            }
        }
    }
    if ($adminMembers) {
        foreach ($admin in $adminMembers) {
            $userInfo += [PSCustomObject]@{
                Type = "Administrator"
                Name = $admin.Name
                Enabled = $true
                LastLogon = ""
                PasswordRequired = ""
                PasswordExpires = ""
                Details = "ObjectClass: $($admin.ObjectClass)"
            }
        }
    }
    $userInfo | Export-Csv -Path $csvUsers -NoTypeInformation -ErrorAction SilentlyContinue
    
    Append-Section "LOCAL USERS" $localUsers
    Append-Section "LOCAL GROUPS" $localGroups
    Append-Section "ADMINISTRATORS GROUP" $adminMembers
    Append-Section "USER PROFILES" $userProfiles
    Append-Section "ACTIVE LOGON SESSIONS" $logonSessions

    # Network Configuration
    Show-Progress $steps[$stepCount]
    $networkAdapters = Safe-Execute { Get-NetAdapter | Select-Object Name, InterfaceDescription, LinkSpeed, Status, MacAddress }
    $ipConfig = Safe-Execute { Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer }
    $routingTable = Safe-Execute { Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric }
    $dnsCache = Safe-Execute { Get-DnsClientCache | Select-Object Entry, Name, Type, Status, TTL }
    $networkConnections = Safe-Execute { 
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $process.ProcessName -PassThru
        }
    }
    $networkConnections | Export-Csv -Path $csvNetwork -NoTypeInformation -ErrorAction SilentlyContinue
    
    Append-Section "NETWORK ADAPTERS" $networkAdapters
    Append-Section "IP CONFIGURATION" $ipConfig
    Append-Section "ROUTING TABLE" $routingTable
    Append-Section "DNS CACHE (Recent)" ($dnsCache | Select-Object -First 50)
    Append-Section "NETWORK CONNECTIONS" ($networkConnections | Select-Object -First 100)

    # Installed Software - FIXED
    Show-Progress $steps[$stepCount]
    $programs = @()
    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    foreach ($regPath in $registryPaths) {
        try {
            if (Test-Path $regPath) {
                $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                foreach ($subKey in $subKeys) {
                    try {
                        $app = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue
                        if ($app -and $app.DisplayName -and $app.DisplayName.Trim() -ne "") {
                            $installDate = $null
                            if ($app.InstallDate -and $app.InstallDate -match '^[0-9]{8}$') {
                                try {
                                    $installDate = [datetime]::ParseExact($app.InstallDate,'yyyyMMdd',$null)
                                } catch {
                                    $installDate = $null
                                }
                            }
                            
                            $programs += [PSCustomObject]@{
                                Name = $app.DisplayName
                                Vendor = $app.Publisher
                                Version = $app.DisplayVersion
                                InstallLocation = $app.InstallLocation
                                InstallDate = $installDate
                                EstimatedSize = $app.EstimatedSize
                                RegistryPath = $regPath
                            }
                        }
                    } catch {
                        # Skip individual entries that cause errors
                        continue
                    }
                }
            }
        } catch {
            Write-Warning "Could not access registry path: $regPath"
            continue
        }
    }
    
    $programs = $programs | Sort-Object Name | Select-Object -Unique Name, Vendor, Version, InstallLocation, InstallDate, EstimatedSize
    $programs | Export-Csv -Path $csvPrograms -NoTypeInformation -ErrorAction SilentlyContinue
    Append-Section "INSTALLED PROGRAMS" $programs

    # System Services
    Show-Progress $steps[$stepCount]
    $services = Safe-Execute { Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType }
    $services | Export-Csv -Path $csvServices -NoTypeInformation -ErrorAction SilentlyContinue
    Append-Section "SYSTEM SERVICES" ($services | Sort-Object Status, Name)

    # Startup Programs
    Show-Progress $steps[$stepCount]
    $startupWMI = Safe-Execute { Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User }
    $startupRegistry = Safe-Execute { 
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    }
    $startupTasks = Safe-Execute { 
        Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -and $_.Triggers.Enabled -eq $true } |
        Select-Object TaskName, TaskPath, State, Author
    }
    
    # Export startup programs to CSV
    $startupInfo = @()
    if ($startupWMI) {
        foreach ($startup in $startupWMI) {
            $startupInfo += [PSCustomObject]@{
                Type = "WMI Startup"
                Name = $startup.Name
                Command = $startup.Command
                Location = $startup.Location
                User = $startup.User
                Details = ""
            }
        }
    }
    if ($startupTasks) {
        foreach ($task in $startupTasks) {
            $startupInfo += [PSCustomObject]@{
                Type = "Scheduled Task"
                Name = $task.TaskName
                Command = $task.TaskPath
                Location = "Task Scheduler"
                User = $task.Author
                Details = "State: $($task.State)"
            }
        }
    }
    $startupInfo | Export-Csv -Path $csvStartup -NoTypeInformation -ErrorAction SilentlyContinue
    
    Append-Section "STARTUP PROGRAMS (WMI)" $startupWMI
    Append-Section "STARTUP REGISTRY ENTRIES" $startupRegistry
    Append-Section "SCHEDULED STARTUP TASKS" $startupTasks

    # Running Processes
    Show-Progress $steps[$stepCount]
    $processes = Safe-Execute { 
        Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, VirtualMemorySize, StartTime, Path, Company, ProductVersion |
        Sort-Object CPU -Descending
    }
    $processes | Export-Csv -Path $csvProcesses -NoTypeInformation -ErrorAction SilentlyContinue
    Append-Section "RUNNING PROCESSES" $processes

    # Drivers
    Show-Progress $steps[$stepCount]
    $drivers = Safe-Execute { Get-WindowsDriver -Online | Select-Object Driver, Date, Version, BootCritical }
    $systemDrivers = Safe-Execute { Get-CimInstance Win32_SystemDriver | Select-Object Name, State, StartMode, PathName }
    
    # Export drivers to CSV
    $driverInfo = @()
    if ($drivers) {
        foreach ($driver in $drivers) {
            $driverInfo += [PSCustomObject]@{
                Type = "Windows Driver"
                Name = $driver.Driver
                Version = $driver.Version
                Date = $driver.Date
                State = ""
                StartMode = ""
                PathName = ""
                BootCritical = $driver.BootCritical
            }
        }
    }
    if ($systemDrivers) {
        foreach ($sysDriver in $systemDrivers) {
            $driverInfo += [PSCustomObject]@{
                Type = "System Driver"
                Name = $sysDriver.Name
                Version = ""
                Date = ""
                State = $sysDriver.State
                StartMode = $sysDriver.StartMode
                PathName = $sysDriver.PathName
                BootCritical = ""
            }
        }
    }
    $driverInfo | Export-Csv -Path $csvDrivers -NoTypeInformation -ErrorAction SilentlyContinue
    
    Append-Section "INSTALLED DRIVERS" ($drivers | Sort-Object Date -Descending | Select-Object -First 100)
    Append-Section "SYSTEM DRIVERS" $systemDrivers

    # Storage Information
    Show-Progress $steps[$stepCount]
    $disks = Safe-Execute { Get-Disk | Select-Object Number, FriendlyName, Size, HealthStatus, OperationalStatus }
    $volumes = Safe-Execute { Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining, HealthStatus }
    $diskUsage = Safe-Execute { Get-PSDrive -PSProvider 'FileSystem' | Select-Object Name, Used, Free, @{Name="Size(GB)"; Expression={"{0:N2}" -f ($_.Used + $_.Free)/1GB}} }
    
    Append-Section "PHYSICAL DISKS" $disks
    Append-Section "VOLUMES" $volumes
    Append-Section "DISK USAGE" $diskUsage

    # Environment & Registry
    Show-Progress $steps[$stepCount]
    $envVars = Safe-Execute { Get-ChildItem Env: | Select-Object Name, Value }
    $pathDirs = $env:PATH -split ';' | Sort-Object
    $recentFiles = Safe-Execute { 
        Get-ChildItem "$env:USERPROFILE\Recent" -ErrorAction SilentlyContinue | 
        Select-Object Name, CreationTime, LastAccessTime -First 20
    }
    
    Append-Section "ENVIRONMENT VARIABLES" $envVars
    Append-Section "PATH DIRECTORIES" $pathDirs
    if (-not $SkipSensitive) {
        Append-Section "RECENT FILES" $recentFiles
    }

    # Event Logs
    Show-Progress $steps[$stepCount]
    $systemEvents = Safe-Execute { Get-EventLog -LogName System -Newest 20 -ErrorAction SilentlyContinue }
    $applicationEvents = Safe-Execute { Get-EventLog -LogName Application -Newest 20 -ErrorAction SilentlyContinue }
    $securityEvents = Safe-Execute { Get-EventLog -LogName Security -Newest 10 -ErrorAction SilentlyContinue }
    
    # Export event logs to CSV
    $eventInfo = @()
    if ($systemEvents) {
        foreach ($event in $systemEvents) {
            $eventInfo += [PSCustomObject]@{
                LogType = "System"
                TimeGenerated = $event.TimeGenerated
                EntryType = $event.EntryType
                Source = $event.Source
                EventID = $event.EventID
                Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
            }
        }
    }
    if ($applicationEvents) {
        foreach ($event in $applicationEvents) {
            $eventInfo += [PSCustomObject]@{
                LogType = "Application"
                TimeGenerated = $event.TimeGenerated
                EntryType = $event.EntryType
                Source = $event.Source
                EventID = $event.EventID
                Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
            }
        }
    }
    if ($securityEvents -and $isAdmin) {
        foreach ($event in $securityEvents) {
            $eventInfo += [PSCustomObject]@{
                LogType = "Security"
                TimeGenerated = $event.TimeGenerated
                EntryType = $event.EntryType
                Source = $event.Source
                EventID = $event.EventID
                Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
            }
        }
    }
    $eventInfo | Export-Csv -Path $csvEventLogs -NoTypeInformation -ErrorAction SilentlyContinue
    
    Append-Section "RECENT SYSTEM EVENTS" $systemEvents
    Append-Section "RECENT APPLICATION EVENTS" $applicationEvents
    if ($isAdmin) {
        Append-Section "RECENT SECURITY EVENTS" $securityEvents
    }

    # Security Configuration
    Show-Progress $steps[$stepCount]
    $firewallProfiles = Safe-Execute { Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction }
    $antivirus = Safe-Execute { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue }
    $windowsDefender = Safe-Execute { Get-MpPreference -ErrorAction SilentlyContinue }
    $uac = Safe-Execute { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue }
    
    Append-Section "FIREWALL PROFILES" $firewallProfiles
    Append-Section "ANTIVIRUS PRODUCTS" $antivirus
    if ($windowsDefender) { Append-Section "WINDOWS DEFENDER STATUS" $windowsDefender }
    Append-Section "UAC CONFIGURATION" $uac

    # Performance Counters
    Show-Progress $steps[$stepCount]
    $perfCounters = Safe-Execute {
        @{
            'CPU_Usage' = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 2 -MaxSamples 2 | Select-Object -ExpandProperty CounterSamples | Select-Object -Last 1).CookedValue
            'Memory_Available_MB' = (Get-Counter '\Memory\Available MBytes' | Select-Object -ExpandProperty CounterSamples).CookedValue
            'Disk_Queue_Length' = (Get-Counter '\PhysicalDisk(_Total)\Current Disk Queue Length' | Select-Object -ExpandProperty CounterSamples).CookedValue
        }
    }
    Append-Section "PERFORMANCE SNAPSHOT" $perfCounters

    # System Files & Integrity - FIXED WITH INTERRUPTIBLE OPERATION
    Show-Progress $steps[$stepCount]
    if ($isAdmin -and -not $SkipSFC) {
        $systemFileCheck = Start-InterruptibleOperation -scriptBlock { 
            sfc /verifyonly 2>&1 
        } -message "[INFO] Starting system file check (this may take several minutes)..." -cancelKey 'X' -timeoutMinutes 10
        
        Append-Section "SYSTEM FILE INTEGRITY" $systemFileCheck
    } else {
        if ($SkipSFC) {
            Append-Section "SYSTEM FILE INTEGRITY" "Skipped by user parameter -SkipSFC"
        } else {
            Append-Section "SYSTEM FILE INTEGRITY" "Requires administrative privileges - skipped"
        }
    }
    Complete-Progress "System Files"

    # Certificates
    Show-Progress $steps[$stepCount]
    $certificates = Safe-Execute { 
        Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Issuer, NotAfter, Thumbprint -First 20
    }
    $certificates | Export-Csv -Path $csvCertificates -NoTypeInformation -ErrorAction SilentlyContinue
    Append-Section "MACHINE CERTIFICATES" $certificates

    # Scheduled Tasks
    Show-Progress $steps[$stepCount]
    $scheduledTasks = Safe-Execute { 
        Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | 
        Select-Object TaskName, TaskPath, State, Author -First 50
    }
    $scheduledTasks | Export-Csv -Path $csvScheduledTasks -NoTypeInformation -ErrorAction SilentlyContinue
    Append-Section "ACTIVE SCHEDULED TASKS" $scheduledTasks

    # USB/Hardware History
    Show-Progress $steps[$stepCount]
    $usbDevices = Safe-Execute { 
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName } |
        Select-Object FriendlyName, Mfg, Service
    }
    $pnpDevices = Safe-Execute { Get-PnpDevice -PresentOnly | Select-Object Name, Status, Class, Manufacturer }
    
    Append-Section "USB STORAGE HISTORY" $usbDevices
    Append-Section "PLUG AND PLAY DEVICES" $pnpDevices

    # Browser Information (if not sensitive)
    Show-Progress $steps[$stepCount]
    if (-not $SkipSensitive) {
        $browsers = @()
        $browserPaths = @{
            'Chrome' = "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
            'Firefox' = "$env:PROGRAMFILES\Mozilla Firefox\firefox.exe"
            'Edge' = "$env:PROGRAMFILES(X86)\Microsoft\Edge\Application\msedge.exe"
            'EdgeNew' = "$env:PROGRAMFILES\Microsoft\Edge\Application\msedge.exe"
        }
        foreach ($browser in $browserPaths.GetEnumerator()) {
            if (Test-Path $browser.Value) {
                try {
                    $version = (Get-ItemProperty $browser.Value).VersionInfo.ProductVersion
                    $browsers += [PSCustomObject]@{Name=$browser.Key; Path=$browser.Value; Version=$version}
                } catch {
                    $browsers += [PSCustomObject]@{Name=$browser.Key; Path=$browser.Value; Version="Unknown"}
                }
            }
        }
        Append-Section "INSTALLED BROWSERS" $browsers
    }

    # Recent Activity
    Show-Progress $steps[$stepCount]
    if (-not $SkipSensitive) {
        $recentDocs = Safe-Execute {
            Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -ErrorAction SilentlyContinue
        }
        Append-Section "RECENT ACTIVITY" "Recent documents registry data collected"
    }

    # Generate JSON summary
    Show-Progress "Generating Summary"
    $summary = @{
        'Timestamp' = Get-Date
        'Hostname' = $hostname
        'Username' = $env:USERNAME
        'IsAdmin' = $isAdmin
        'OS' = if ($osInfo) { $osInfo.Caption } else { "Unknown" }
        'TotalPrograms' = if ($programs) { $programs.Count } else { 0 }
        'RunningProcesses' = if ($processes) { $processes.Count } else { 0 }
        'ActiveServices' = if ($services) { ($services | Where-Object {$_.Status -eq 'Running'}).Count } else { 0 }
        'NetworkConnections' = if ($networkConnections) { $networkConnections.Count } else { 0 }
        'OutputFiles' = @($txtOutput, $csvPrograms, $csvProcesses, $csvServices, $csvNetwork, $csvUsers, $csvDrivers, $csvStartup, $csvHardware, $csvCertificates, $csvScheduledTasks, $csvEventLogs)
    }

    # Final report footer with elapsed time
    $scriptEndTime = Get-Date
    $totalElapsed = $scriptEndTime - $scriptStartTime
    $elapsedFormatted = "{0:D2}:{1:D2}:{2:D2}" -f $totalElapsed.Hours, $totalElapsed.Minutes, $totalElapsed.Seconds
    
    Add-Content -Path $txtOutput -Value "`r`n$('='*50)`r`n=== END OF REPORT ===`r`n$('='*50)"
    Add-Content -Path $txtOutput -Value "Report completed: $scriptEndTime"
    Add-Content -Path $txtOutput -Value "Total execution time: $elapsedFormatted"
    Add-Content -Path $txtOutput -Value "Total sections: $($steps.Count)"

    Write-Host "`n" -NoNewline
    Write-Host "System information collection completed successfully!" -ForegroundColor Green
    Write-Host "Total execution time: $elapsedFormatted" -ForegroundColor Cyan
    Write-Host "`nOutput files generated:" -ForegroundColor Cyan
    Write-Host "  Main Report:         $txtOutput" -ForegroundColor White
    Write-Host "  Programs CSV:        $csvPrograms" -ForegroundColor White  
    Write-Host "  Processes CSV:       $csvProcesses" -ForegroundColor White
    Write-Host "  Services CSV:        $csvServices" -ForegroundColor White
    Write-Host "  Network CSV:         $csvNetwork" -ForegroundColor White
    Write-Host "  Users CSV:           $csvUsers" -ForegroundColor White
    Write-Host "  Drivers CSV:         $csvDrivers" -ForegroundColor White
    Write-Host "  Startup CSV:         $csvStartup" -ForegroundColor White
    Write-Host "  Hardware CSV:        $csvHardware" -ForegroundColor White
    Write-Host "  Certificates CSV:    $csvCertificates" -ForegroundColor White
    Write-Host "  Scheduled Tasks CSV: $csvScheduledTasks" -ForegroundColor White
    Write-Host "  Event Logs CSV:      $csvEventLogs" -ForegroundColor White
    
    Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

} catch {
    Write-Host "`nCRITICAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    Read-Host "`nPress Enter to close"
}