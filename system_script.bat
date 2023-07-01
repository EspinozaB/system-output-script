rem This script was created for listing system specs

@echo off

date /t >>system_script_output.txt

time /t >>system_script_output.txt

hostname >>system_script_output.txt

whoami >>system_script_output.txt

ipconfig /all >>system_script_output.txt

systeminfo >>system_script_output.txt

net user >>system_script_output.txt

net localgroup administrators >>system_script_output.txt

netstat -nao -r >>system_script_output.txt

date /t >>system_script_output.txt

time /t  >>system_script_output.txt