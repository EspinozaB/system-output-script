# This script was created for listing system specs, info, and more for analysis or troubleshooting.

# import modules required 
import csv
import datetime
import subprocess
import time
import os
import platform
import socket

def append_text(csv_writer, text):
    csv_writer.writerow([text])


def append_section_heading(csv_writer, text):
    csv_writer.writerow([text])
    csv_writer.writerow([])  # add an empty row for spacing


def append_command_output(csv_writer, command):
    section_heading = f"=== {command.upper()} ==="
    append_section_heading(csv_writer, section_heading)

    output = subprocess.check_output(command, shell=True, text=True)
    output_lines = output.splitlines()
    csv_writer.writerows([[line] for line in output_lines])


def gather_system_information(filename):
    start_time = time.time()
    current_date = datetime.date.today().strftime("%B %d, %Y")
    current_time = datetime.datetime.now().strftime("%I:%M %p")

    # open CSV for writing 
    with open(filename, 'w', newline='') as file:
        csv_writer = csv.writer(file)
        
        # write system information header
        append_section_heading(csv_writer, "System Information")
        append_text(csv_writer, f"Date: {current_date}")
        append_text(csv_writer, f"Time: {current_time}")

        # execute each command and append the output to the CSV file
        append_command_output(csv_writer, "hostname")
        append_command_output(csv_writer, "whoami")
        append_command_output(csv_writer, "ipconfig /all")
        append_command_output(csv_writer, "systeminfo")
        append_command_output(csv_writer, "net user")
        append_command_output(csv_writer, "net localgroup administrators")
        append_command_output(csv_writer, "netstat -nao -r")
        append_command_output(csv_writer, "wmic product get name, version, vendor")
        append_command_output(csv_writer, "net start")
        append_command_output(csv_writer, "wmic startup get caption, command")
        append_command_output(csv_writer, "driverquery")
        append_command_output(csv_writer, "wmic logicaldisk get caption, description, freespace, size")
        append_command_output(csv_writer, "tasklist")
        append_command_output(csv_writer, "systeminfo /s localhost")
        append_command_output(csv_writer, "set")
        append_command_output(csv_writer, "netsh advfirewall show all")
        append_command_output(csv_writer, "wmic printer get name, portname, drivername")
        append_command_output(csv_writer, "wmic desktopmonitor get caption, screenheight, screenwidth")
        append_command_output(csv_writer, "wmic qfe get hotfixid, installedon")
        append_command_output(csv_writer, "wevtutil qe System /c:10 /rd:true /f:text /e:Events")
        append_command_output(csv_writer, "wevtutil qe Application /c:10 /rd:true /f:text /e:Events")
        append_command_output(csv_writer, "wmic diskdrive get Caption, Size, MediaType")

    # starts the elapsed time
    elapsed_time = time.time() - start_time
    end_time = datetime.datetime.now().strftime("%I:%M %p")
    
    # open the CSV file again in append mode
    with open(filename, 'a', newline='') as file:
        csv_writer = csv.writer(file)

    # write the elapsed time and end time to the CSV file
        append_section_heading(csv_writer, "Script Information")
        append_text(csv_writer, f"Elapsed Time: {elapsed_time:.2f} seconds")
        append_text(csv_writer, f"End Time: {end_time}")
    
    print(f"System information has been successfully gathered and saved to '{filename}'.")

# creates the file
output_filename = "system_script_output.csv"
gather_system_information(output_filename)
