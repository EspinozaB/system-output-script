rem This script was created for listing system specs, info, and more for analysis or troubleshooting.

@echo off

echo Gathering system information...

(
    echo.
    echo === System Information ===
    echo.

    date /t
    time /t

    echo Hostname:
    hostname

    echo Current user:
    whoami

    echo IP Configuration:
    ipconfig /all

    echo System Information:
    systeminfo

    echo User Accounts:
    net user

    echo Administrators:
    net localgroup administrators

    echo Network Statistics:
    netstat -nao -r

    echo Installed Programs:
    wmic product get name, version, vendor

    echo Running Services:
    net start

    echo Startup Programs:
    wmic startup get caption, command

    echo System Drivers:
    driverquery

    echo Disk Usage:
    wmic logicaldisk get caption, description, freespace, size

    echo Running Processes:
    tasklist

    echo Additional Information:
    systeminfo /s localhost

    echo Environment Variables:
    set

    echo Firewall Configuration:
    netsh advfirewall show all

    echo Installed Printers:
    wmic printer get name, portname, drivername

    echo Display Information:
    wmic desktopmonitor get caption, screenheight, screenwidth

    echo Installed Hotfixes:
    wmic qfe get hotfixid, installedon

    echo Event Logs:
    wevtutil qe System /c:10 /rd:true /f:text /e:Events
    wevtutil qe Application /c:10 /rd:true /f:text /e:Events

    echo Disk Partition Information:
    wmic diskdrive get Caption, Size, MediaType

    echo.
    echo === End of System Information ===
    echo.

    echo Elapsed Time: %time%
) >>system_script_output.txt

echo System information has been successfully gathered and saved to system_script_output.txt.

pause
