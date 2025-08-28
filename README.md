# System Spec Listing Script

These scripts are designed to gather and list basic system specifications of a Windows operating system. It can be useful for various purposes such as system diagnostics, system analysis, or educational purposes.

## Usage

*Skip to step 4 if using download.*

1. Open a command prompt window or text editor. 
2. Copy and paste the script you wish to use (.py, .bat, or .ps1) into a text editor.
3. Save the script with a .bat, .py extension, or .ps1 extension (e.g., system_script.bat or system_script.py).
4. Double-click the script file to execute it. The Python interpreter must be installed for the Python script.
5. PowerShell script users may encounter an error regarding the execution policy in your domain. Use the command (without outer quotes) "powershell.exe -ExecutionPolicy Bypass -File "System.Output.Simple.ps1""

### Script Overview

The script uses various Windows command-line utilities to gather system information and outputs the results to a file named system_script_output.txt. Those using the Powershell simple script will receive a text file with the format: SystemInfo_hostname_date_time.txt 
While those using the enhanced script will receive several files. A system report text file for the main overview with the format: system_report_hostname_date_time.txt and several CSV files for different aspects of the system. 


The Python and batch script will perform the following operations:

-	Appends the current date to output.
-	Appends the current time to output.
-	Retrieves the hostname and appends it to output.
-	Retrieves the current user and appends it to output.
-	Retrieves the IP configuration details and appends them to output.
-	Retrieves detailed system information and appends it to output.
-	Retrieves user account information and appends it to output.
-	Retrieves the members of the local administrators group and appends them to output.
-	Retrieves network statistics and appends them to output.
-	Retrieves startup programs and appends them to output.
-	Retrieves system drivers and appends them to output.
-	Retrieves disk usage and appends them to output.
-	Retrieves running processes and appends them to output.
-	Retrieves additional system information from localhost and appends them to output.
-	Retrieves environment variables and appends them to output.
-	Retrieves firewall configuration and appends them to output.
-	Retrieves installed printer information and appends them to output.
-	Retrieves display information and appends them to output.
-	Retrieves hotfix information and appends them to output.
-	Retrieves event log information and appends them to output.
-	Retrieves disk partition information and appends them to output.
-	Appends the current date again to output.
-	Appends the elapsed time to the end of the output.

The PowerShell scripts contain the following:

- Comprehensive Data Collection: Gathers 20+ categories of system information
- Multiple Output Formats: Generates structured TXT and CSV files for easy analysis
- Minimal Privilege Requirements: Works with standard user privileges (enhanced with admin rights)
- Real-time Progress Tracking: Visual progress indicators with elapsed time
- Interruptible Operations: Skip time-intensive operations with keypress
- Error Handling: Robust error handling with graceful degradation
- Timeout Protection: Prevents script hanging on problematic commands

# Output

The scripts generate an output file(s) in the same directory where the script is executed. This file contains a log of the gathered system specifications, including the date and time of execution. 
Using the PowerShell scripts will result in one text file for the simple script and one text file with multiple CSV files for different catergories of the system such as the list of programs, processes, services, network, users, drivers, startup programs, hardware, certificates, scheduled tasks, and event logs.

# Note

This script provides only basic system information and may not cover all aspects of a Windows system. For a more comprehensive system analysis, consider using specialized tools or consulting professional resources.These scripts are provided for legitimate system administration, forensics, and troubleshooting purposes. Users are responsible for ensuring compliance with applicable laws and organizational policies. Always obtain proper authorization before running system analysis tools on networks or systems you do not own.
