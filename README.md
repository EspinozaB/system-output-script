## System Spec Listing Script

This script is designed to gather and list basic system specifications of a Windows operating system. It can be useful for various purposes such as system diagnostics, system analysis, or educational purposes.

# Usage

*Skip to step 4 if using download.*

1. Open a command prompt window. 
2. Copy and paste the script into a text editor.
3. Save the script with a .bat extension (e.g., system_script.bat).
4. Double-click the script file to execute it.

# Script Overview

The script uses various Windows command-line utilities to gather system information and outputs the results to a file named system_script_output.txt. The script performs the following operations:

-	Appends the current date to system_script_output.txt.
-	Appends the current time to system_script_output.txt.
-	Retrieves the hostname and appends it to system_script_output.txt.
-	Retrieves the current user and appends it to system_script_output.txt.
-	Retrieves the IP configuration details and appends them to system_script_output.txt.
-	Retrieves detailed system information and appends it to system_script_output.txt.
-	Retrieves user account information and appends it to system_script_output.txt.
-	Retrieves the members of the local administrators group and appends them to system_script_output.txt.
-	Retrieves network statistics and appends them to system_script_output.txt.
-	Appends the current date again to system_script_output.txt.
-	Appends the current time again to system_script_output.txt.

# Output

The script generates an output file named system_script_output.txt in the same directory where the script is executed. This file contains a log of the gathered system specifications, including the date and time of execution.

# Note

This script provides only basic system information and may not cover all aspects of a Windows system. For a more comprehensive system analysis, consider using specialized tools or consulting professional resources.
