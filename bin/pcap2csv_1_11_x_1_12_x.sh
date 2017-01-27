#!/bin/bash
#Daniel Schwartz
#This script converts pcap files to a csv file using tshark <=1.11.x
#Created: May 2015
#Updated: December 2016
#Version 1.4

VAR=$(more $SPLUNK_HOME/etc/apps/SplunkForPCAP/local/inputs.conf | grep path |  awk '{print $3}')

for line in $VAR
do

	for file in $line/*.pcap
	do tshark -r "$file" -T fields -e frame.time -e tcp.stream -e ip.src -e ip.dst -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.window_size -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.push -e tcp.flags.fin -e tcp.flags.reset -e ip.ttl -e _ws.col.Info -e tcp.analysis.ack_rtt -e vlan.id > $SPLUNK_HOME/var/log/pcap/PCAPcsv/${file##*/}.csv
	mv "$file" $SPLUNK_HOME/var/log/pcap/PCAPConverted/
	done
done
