#!/bin/bash
#Daniel Schwartz
#This script aims to check which tshark script to execute
#Created: December 2016
#Version 1.0

TSHARK=$(which tshark)
TSHARK_V=$(/usr/sbin/tshark -v | grep TShark | grep -Po '(?<= )\d\.\d{1,2}'|sed 's/.*1.//')
V10="$SPLUNK_HOME/etc/apps/SplunkForPCAP/bin/pcap2csv_1_10_x.sh"
V11="$SPLUNK_HOME/etc/apps/SplunkForPCAP/bin/pcap2csv_1_11_x_1_12_x.sh"


if [ -d $SPLUNK_HOME/var/log/pcap ] ; then
	echo "Yes"
else  
	mkdir -p $SPLUNK_HOME/var/log/pcap
fi

if [ -d $SPLUNK_HOME/var/log/pcap/PCAPcsv ] ; then
        echo "Yes"
else
        mkdir -p $SPLUNK_HOME/var/log/pcap/PCAPcsv
fi

if [ -d $SPLUNK_HOME/var/log/pcap/PCAPConverted ] ; then
        echo "Yes"
else
        mkdir -p $SPLUNK_HOME/var/log/pcap/PCAPConverted
fi

if [ "$TSHARK_V" -le "10" ]; then
	./$V10
else
	./$V11
fi
