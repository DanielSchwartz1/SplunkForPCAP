@echo off
REM Daniel Schwartz
REM This script converts pcap files to a csv file using tshark 1.10.x
REM Version 1.3
REM Created: May 2015
REM Updated: December 2016

for /f "tokens=2 delims== " %%a in ('findstr "path" "%SPLUNK_HOME%\etc\apps\SplunkForPCAP\local\inputs.conf"') do (
for /F %%f in ('dir /b "%%a\*.pcap"') do "%programfiles%\Wireshark\tshark" -r "%%a\%%f" -T fields -e frame.time -e tcp.stream -e ip.src -e ip.dst -e col.Protocol -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.window_size -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.push -e tcp.flags.fin -e tcp.flags.reset -e ip.ttl -e col.Info -e tcp.analysis.ack_rtt -e vlan.id > "%SPLUNK_HOME%\var\log\pcap\PCAPcsv\%%f.csv"
move  "%%a\*.pcap" "%SPLUNK_HOME%\var\log\pcap\PCAPConverted\" >nul 2>&1
)