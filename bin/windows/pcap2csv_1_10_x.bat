@echo off
REM Daniel Schwartz
REM This script converts pcap files to a csv file using tshark 1.10.x
REM Version 1.3
REM Created: May 2015
REM Updated: September 2016

for /F %%f in ('dir /b "C:\Program Files\Splunk\etc\apps\SplunkForPCAP\bin\windows\*.pcap"') do "c:\Program Files\Wireshark\tshark" -r "C:\Program Files\Splunk\etc\apps\SplunkForPCAP\bin\windows\%%f" -T fields -e frame.time -e tcp.stream -e ip.src -e ip.dst -e col.Protocol -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.window_size -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.push -e tcp.flags.fin -e tcp.flags.reset -e ip.ttl -e col.Info -e tcp.analysis.ack_rtt -e vlan.id > "C:\Program Files\Splunk\etc\apps\SplunkForPCAP\bin\windows\%%f.csv"

move  "C:\Program Files\Splunk\etc\apps\SplunkForPCAP\bin\windows\*.pcap" "C:\Program Files\Splunk\etc\apps\SplunkForPCAP\bin\windows\PCAPConverted\"