@echo off
REM Daniel Schwartz
REM This script aims to check which tshark script to execute
REM Version 1.0
REM Created: December 2016

IF EXIST "%SPLUNK_HOME%\var\log\pcap" (
echo Yes 
) ELSE (
md "%SPLUNK_HOME%\var\log\pcap"
)

IF EXIST "%SPLUNK_HOME%\var\log\pcap\PCAPcsv" (
echo Yes 
) ELSE (
md "%SPLUNK_HOME%\var\log\pcap\PCAPcsv"
)

IF EXIST "%SPLUNK_HOME%\var\log\pcap\PCAPConverted" (
echo Yes 
) ELSE (
md "%SPLUNK_HOME%\var\log\pcap\PCAPConverted"
)


for /f "delims=" %%i in ('"%programfiles%\Wireshark\tshark" -v ^| findstr /r \(v') do set "TS=%%i"
	set T=%TS:~9,2%

IF %T% LEQ 10 (
	CALL "%SPLUNK_HOME%\etc\apps\SplunkForPCAP\bin\pcap2csv_1_10_x.bat"
	) ELSE (
	CALL "%SPLUNK_HOME%\etc\apps\SplunkForPCAP\bin\pcap2csv_1_11_x_1_12_x.bat"
	)