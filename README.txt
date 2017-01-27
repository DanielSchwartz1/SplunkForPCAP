INTRODUCTION

The Splunk App for PCAP files will express the pcap files into helpful charts by converting the files into a Splunk readable CSV file

Included with this first version of the Splunk App For PCAP is:
- Script (pcap2csv.bat and pcap2csv.sh) for Windows and Unix systems to convert the PCAP files to a CSV file 
(sourcetype is defined for the output of the included script)

NOTES ABOUT THE DATA

I have suffered from timestamp problems with PCAP files over 500MB. 
In case of big files I have split the pcap files into smaller files by using editcap.exe out of the Wireshark package.

-Sourcetype defined for the data:
-->sourcetype=pcap:csv

-Inputs are defined as follows:
-->Windows: [monitor://C:\Program Files\Splunk\etc\apps\SplunkForPCAP\bin\windows\PCAPcsv\*.csv*]
-->Unix: [monitor:///opt/splunk/etc/apps/SplunkForPCAP/bin/unix/PCAPcsv/*.csv*]

REQUIREMENTS

- Wireshark (tshark) needs to be installed (available)

GETTING STARTED

After the installation:
Step 1: Make sure the ../SplunkForPCAP/bin/ folder has all administrative privileges to execute the batch and shell script
Step 2: Make sure the path in the pcap2csv scripts will fit with your path configured (default: C:/Program Files/Splunk or /opt/splunk)
Step 3: Make sure the Splunk Home path fits to the inputs.conf file in /default folder.
Step 4: In case of a configuration change (inputs.conf), you have to restart splunk.

How to convert PCAP to CSV:

1. Put your PCAP files into the ../SplunkForPCAP/bin/*/PCAPtoConvert/ and execute the pcap2csv script
--> Automatically a CSV file with the filename will be created into "PCAPcsv" folder (test.pcap --> test.csv)
2. Splunk is reading the data from the /bin/*/PCAPcsv folder as defined in the inputs.conf.
--> index=* sourcetype=pcap:csv

ROADMAP

- Support for more protocols and more use cases
- Dashboards will change to highlight the most important use cases for troubleshooting.

Feedback welcome! You can contact me by emailing <1daniel.schwartz1@gmail.com>.