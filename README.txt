=> NOTES
- What is tshark? TShark is a network protocol analyzer. It lets you capture packet data from a live network, or read packets from a previously saved capture file, either printing a decoded form of those packets to the standard output or writing the packets to a file

=> CONTACT
Feedback welcome! You can contact me by emailing <1daniel.schwartz1@gmail.com>.

For issues please contact me via email or open a new issue on Github: 
https://github.com/DanielSchwartz1/SplunkForPCAP/issues/new

Emails will be usually answered between Monday-Friday 9am - 6pm European Time.
Getting started: https://schwartzdaniel.com/pcap-analyzer-for-splunk-getting-started/

=> INTRODUCTION

The Splunk App for PCAP files will express the .pcap OR .pcapng files into helpful charts by converting the files into a Splunk readable file

=> NOTES ABOUT THE DATA

In case of big files It might be an option to split the files into smaller files by using editcap out of the Wireshark package.

-Index defined for the data: Default Index is choosed

-Sourcetype defined for the data:
-->sourcetype=pcap:analyzer

-Sourcetype defined for the debug data:
-->sourcetype=pcap:analyzer:debug

=>REQUIREMENTS

Wireshark (tshark) needs to be installed (available)
=> GETTING STARTED

Getting started - Requirements!
Step 1: Make sure the ../SplunkForPCAP/bin/ folder has all administrative privileges to execute the main script
Step 2: Make sure you have tshark installed (in most cases delivered with Wireshark)
Step 3: Make sure you have set SPLUNK_HOME variable

To allow Splunk to collect your PCAP Files you have to specify where you have stored your pcap files.
You can specify your location in the Data Inputs (via Settings) --> PCAP File Location.

The app checks every 5 minutes for a new pcap file in your specified folder.

You will recognize that after you can see your pcap file indexed in Splunk it is moved away from your folder. 
The file will be moved to "converted" folder in the same location of your trace file. 
That is happening to avoid that the automatic script converts your pcap file twice.

=> ROADMAP

Support for more protocols and more use cases
Dashboards will change to highlight the most important use cases for troubleshooting.
