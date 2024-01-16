"""
Author: Daniel Schwartz (1daniel.schwartz1@gmail.com)
Last update: 07.01.2024

Description:
This script processes .pcap and .pcapng  files, extracts relevant information to be collected by Splunk.
It reads your trace folder from local\inputs.conf and processes files within this folder every 5min.

Instructions:
1. Ensure that the required dependencies are installed (Tshark / Wireshark)
2. Make sure that you have set the $SPLUNK_HOME variable properly to the location of your Splunk installation
3. Make sure that the Splunk user can read and write into the trace file location of your choice
4. The very first step is to define a folder where your pcap files are located via Settings –> Data Inputs –> PCAP File Location

"""

import sys
import shutil
import configparser
import os
import time
import traceback

# Add the 'lib' directory to sys.path
lib_dir = os.path.join(os.path.dirname(__file__), "lib")
sys.path.append(lib_dir)

import lib.pyshark as pyshark

# Get the value of the SPLUNK_HOME environment variable
splunk_home = os.environ.get("SPLUNK_HOME")

# Ensure SPLUNK_HOME is defined
if splunk_home is None:
    print("SPLUNK_HOME environment variable is not defined.")
    exit(1)

# Construct the full path to inputs.conf
inputs_conf_path = os.path.join(splunk_home, "etc", "apps", "SplunkForPCAP", "local", "inputs.conf")

# Read paths from inputs.conf
config = configparser.ConfigParser()
config.read(inputs_conf_path, encoding='utf-8-sig')

# Set the output directory for CSV files
output_directory = os.path.join(splunk_home, "etc", "apps", "SplunkForPCAP", "PCAP_Output")


#################################################################################
#################################################################################
#################################################################################
# Field name definition

base4_field_names = [
    "time_epoch",
    "packet_number",
    "time_delta",
    "time_relative",
    "protocol",
    "highest_layer",
    "length",
    "source_ip",
    "destination_ip",
    "ttl",
]

base6_field_names = [
    "time_epoch",
    "packet_number",
    "time_delta",
    "time_relative",
    "protocol",
    "highest_layer",
    "length",
    "source_ip",
    "destination_ip",
]

tcp_field_names = [
    "tcp_stream",
    "tcp_source_port",
    "tcp_destination_port",
    "tcp_window_size",
    "tcp_flags",
    "tcp_syn_flag",
    "tcp_ack_flag",
    "tcp_push_flag",
    "tcp_fin_flag",
    "tcp_reset_flag",
    "seq_number",
    "ack_number",
    "rtt",
    "bytes_in_flight",
    "retransmission",
    "duplicate_ack",
    "zero_window",
    "window_full",
    "reused_port",
]

udp_field_names = [
    "udp_stream",
    "udp_source_port",
    "udp_destination_port",
]

dns_query_field_names = [
    "dns_id",
    "dns_query_type",
    "dns_query_name",
]

dns_response_field_names = [
    "dns_id",
    "dns_status",
    "dns_response_name",
    "dns_time",
    "dns_response_ipv4",
    "dns_response_ipv6",
]

tls_field_names = [
    "tls_record_layer",
    "tls_content_type",
    "tls_record_version",
    "tls_record_length",
]

http_field_names = [
    "http_request_method",
    "http_request_uri",
    "http_request_version",
    "http_request_host",
    "http_response_for_uri",
    "http_response_status",
    "http_request_in_packet",
    "http_time",
]

http_request_field_names = [
    "http_method",
    "http_request_uri",
    "http_request_version",
    "http_host",
]

http_response_field_names = [
    "http_response_for_uri",
    "http_status",
    "http_request_in_packet",
    "http_time",
]

eth_field_names = [
    "source_mac",
    "destination_mac",
]

vlan_field_names = [
    "vlan_id",
]

smb2_request_field_names = [
    "smb2_sessionid",
    "smb2_messageid",
    "smb2_cmd",
]

smb2_response_field_names = [
    "smb2_sessionid",
    "smb2_messageid",
    "smb2_cmd",
    "smb2_nt_status",
    "smb2_time",
]

rpc_request_field_names = [
    "rpc_xid",
    "rpc_msgtyp",
    "rpc_program",
    "rpc_programversion",
    "rpc_procedure",
    "rpc_auth_machinename",
    "rpc_auth_uid",
    "rpc_auth_gid",
]

rpc_response_field_names = [
    "rpc_xid",
    "rpc_msgtyp",
    "rpc_program",
    "rpc_programversion",
    "rpc_procedure",
    "rpc_request_in_packet",
    "rpc_time",
]

nfs_response_field_names = [
    "nfs_status",
]

mq_tsh_field_names = [
    "mq_tsh_structid",
    "mq_tsh_seglength",
    "mq_tsh_convid",
    "mq_tsh_requestid",
    "mq_tsh_type",
    "mq_tsh_ccsid",
]


#################################################################################
#################################################################################
#################################################################################
# Function to extract data from a PCAP file

def extract_data_from_pcap(file_path):
    def write_current_line(output_file, current_line):
        if current_line:
            output_file.write(current_line + "\n")
    current_packet_number = None
    current_line = ""

    try:
        capture = pyshark.FileCapture(file_path)
        with open(os.path.join(output_directory, os.path.basename(file_path) + ".out"), "w") as output_file:
            for packet in capture:
                #print(packet.frame_info)
                #field_names = packet.frame_info._all_fields
                #print(field_names)
                if "IP" in packet:
                    packet_number = packet.frame_info.number
                    base_row = extract_base4(packet)
                    if current_packet_number != packet_number:
                        write_current_line(output_file, current_line)
                        current_packet_number = packet_number
                        current_line = ""
                    if base_row:
                        current_line += " | ".join(f"{field}={value}" for field, value in zip(base4_field_names, base_row))
                    
                    #ETH
                    if hasattr(packet, 'eth'):
                        eth_row = extract_eth(packet)
                        if eth_row:
                            current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(eth_field_names, eth_row))

                    if hasattr(packet, 'vlan'):
                        vlan_row = extract_vlan(packet)
                        if vlan_row:
                            current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(vlan_field_names, vlan_row))                     

                    #TCP
                    if hasattr(packet, 'tcp'):
                        tcp_row = extract_tcp(packet)
                        if tcp_row:
                            current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(tcp_field_names, tcp_row))
                            if hasattr(packet, 'tls'):
                                tls_row = extract_tls(packet)
                                if tls_row:
                                    current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(tls_field_names, tls_row))
                            
                            elif hasattr(packet, 'http'):
                                http_row = extract_http(packet)
                                if http_row:
                                    current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(http_field_names, http_row))
                            
                            elif hasattr(packet, 'smb2'):
                                if packet.smb2.flags_response == '0':
                                    smb2_request = extract_smb2_request(packet)
                                    if smb2_request:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(smb2_request_field_names, smb2_request))
                                elif packet.smb2.flags_response == '1':
                                    smb2_response = extract_smb2_response(packet)
                                    if smb2_response:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(smb2_response_field_names, smb2_response))
                            
                            elif hasattr(packet, "rpc") and hasattr(packet, "nfs"):
                                if packet.rpc.msgtyp == '0':
                                    rpc_request = extract_rpc_request(packet)
                                    if rpc_request:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(rpc_request_field_names, rpc_request))
                                elif packet.rpc.msgtyp == '1':
                                    rpc_response = extract_rpc_response(packet)
                                    if rpc_response:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(rpc_response_field_names, rpc_response))
                                        if hasattr(packet, "nfs") and (packet.nfs.status):
                                            nfs_response_row = extract_nfs_response(packet)
                                            if nfs_response_row:
                                                current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(nfs_response_field_names, nfs_response_row))
                            elif hasattr(packet, "mq"):
                                mq_row = extract_mq_tsh(packet)
                                if mq_row:
                                    current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(mq_tsh_field_names, mq_row))


                    #UDP
                    if hasattr(packet, 'udp'):
                        #field_names = packet.dns._all_fields
                        #print(field_names)
                        udp_row = extract_udp(packet)
                        if udp_row:
                            current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(udp_field_names, udp_row))
                            if hasattr(packet, 'dns'):
                                if packet.dns.flags_response == '0':
                                    dns_query_name = extract_dns_query(packet)
                                    if dns_query_name:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(dns_query_field_names, dns_query_name))
                                elif packet.dns.flags_response == '1':
                                    dns_response_name = extract_dns_response(packet)
                                    if dns_response_name:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(dns_response_field_names, dns_response_name))
                            
                elif "IPV6" in packet:
                    #field_names = packet.ipv6._all_fields
                    #print(field_names)
                    packet_number = packet.frame_info.number
                    base_ip6_row = extract_base6(packet)
                    if current_packet_number != packet_number:
                        write_current_line(output_file, current_line)
                        current_packet_number = packet_number
                        current_line = ""
                    if base_ip6_row:
                        current_line += " | ".join(f"{field}={value}" for field, value in zip(base6_field_names, base_ip6_row)) 

                    #ETH
                    if hasattr(packet, 'eth'):
                        eth_row = extract_eth(packet)
                        if eth_row:
                            current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(eth_field_names, eth_row))

                    if hasattr(packet, 'vlan'):
                        vlan_row = extract_vlan(packet)
                        if vlan_row:
                            current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(vlan_field_names, vlan_row))                     

                    #TCP
                    if hasattr(packet, 'tcp'):
                        tcp_row = extract_tcp(packet)
                        if tcp_row:
                            current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(tcp_field_names, tcp_row))
                            if hasattr(packet, 'tls'):
                                tls_row = extract_tls(packet)
                                if tls_row:
                                    current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(tls_field_names, tls_row))
                            
                            elif hasattr(packet, 'http'):
                                http_row = extract_http(packet)
                                if http_row:
                                    current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(http_field_names, http_row))   

                            elif hasattr(packet, 'smb2'):
                                if packet.smb2.flags_response == '0':
                                    smb2_request = extract_smb2_request(packet)
                                    if smb2_request:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(smb2_request_field_names, smb2_request))
                                if packet.smb2.flags_response == '1':
                                    smb2_response = extract_smb2_response(packet)
                                    if smb2_response:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(smb2_response_field_names, smb2_response))   

                            elif hasattr(packet, "rpc") and hasattr(packet, "nfs"):
                                if packet.rpc.msgtyp == '0':
                                    rpc_request = extract_rpc_request(packet)
                                    if rpc_request:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(rpc_request_field_names, rpc_request))
                                elif packet.rpc.msgtyp == '1':
                                    rpc_response = extract_rpc_response(packet)
                                    if rpc_response:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(rpc_response_field_names, rpc_response))
                                        if hasattr(packet, "nfs") and (packet.nfs.status):
                                            nfs_response_row = extract_nfs_response(packet)
                                            if nfs_response_row:
                                                current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(nfs_response_field_names, nfs_response_row))
                            elif hasattr(packet, "mq"):
                                mq_row = extract_mq_tsh(packet)
                                if mq_row:
                                    current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(mq_tsh_field_names, mq_row))



                    #UDP
                    if hasattr(packet, 'udp') and packet.highest_layer!="MDNS":
                        #field_names = packet.dns._all_fields
                        #print(field_names)
                        udp_row = extract_udp(packet)
                        if udp_row:
                            current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(udp_field_names, udp_row))
                            if hasattr(packet, 'dns'): 
                                if packet.dns.flags_response == '0':
                                    dns_query_name = extract_dns_query(packet)
                                    if dns_query_name:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(dns_query_field_names, dns_query_name))
                                elif packet.dns.flags_response == '1':
                                    dns_response_name = extract_dns_response(packet)
                                    if dns_response_name:
                                        current_line += " | " + " | ".join(f"{field}={value}" for field, value in zip(dns_response_field_names, dns_response_name))
                            
            write_current_line(output_file, current_line)
            capture.close()
            return True
    except Exception as e:
        print(f"Error processing file: {file_path}, Error: {str(e)}")
        traceback.print_exc()
        

#################################################################################
#################################################################################
#################################################################################
# Definition of extract functions

def extract_base4(packet):
    try:
        base4_row = [
            packet.frame_info.time_epoch,
            packet.frame_info.number,
            packet.frame_info.time_delta,
            packet.frame_info.time_relative,
            packet.transport_layer, #protocol
            packet.highest_layer, #protocol
            packet.length, #length
            packet.ip.src,
            packet.ip.dst,
            packet.ip.ttl,
        ]
        return base4_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_base6(packet):
    try:
        base6_row = [
            packet.frame_info.time_epoch,
            packet.frame_info.number,
            packet.frame_info.time_delta,
            packet.frame_info.time_relative,
            packet.transport_layer, #protocol
            packet.highest_layer, #protocol
            packet.length, #length
            packet.ipv6.src,
            packet.ipv6.dst,
        ]
        return base6_row
    except Exception as e:
        print(f"Error processing ipv6 packet: {packet}, Error: {str(e)}")


def extract_eth(packet):
    try:
        eth_row = [
            packet.eth.src if hasattr(packet.eth, 'src') else "",
            packet.eth.dst if hasattr(packet.eth, 'dst') else "",
        ]
        return eth_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_vlan(packet):
    try:
        vlan_row = [
            packet.vlan.id if hasattr(packet.vlan, 'id') else "",
        ]
        return vlan_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_tcp(packet):
    try:
        tcp_row = [
            packet.tcp.stream if hasattr(packet.tcp, 'stream') else "",
            packet.tcp.srcport if hasattr(packet.tcp, 'srcport') else "",
            packet.tcp.dstport if hasattr(packet.tcp, 'dstport') else "",
            packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else "",
            packet.tcp.flags if hasattr(packet.tcp, 'flags') else "",
            packet.tcp.flags_syn if hasattr(packet.tcp, 'flags_syn') else "",
            packet.tcp.flags_ack if hasattr(packet.tcp, 'flags_ack') else "",
            packet.tcp.flags_push if hasattr(packet.tcp, 'flags_push') else "",
            packet.tcp.flags_fin if hasattr(packet.tcp, 'flags_fin') else "",
            packet.tcp.flags_reset if hasattr(packet.tcp, 'flags_reset') else "",
            packet.tcp.seq_raw if hasattr(packet.tcp, 'seq_raw') else "",
            packet.tcp.ack_raw if hasattr(packet.tcp, 'ack_raw') else "",
            packet.tcp.analysis_ack_rtt if hasattr(packet.tcp, 'analysis_ack_rtt') else "0",
            packet.tcp.analysis_bytes_in_flight if hasattr(packet.tcp, 'analysis_bytes_in_flight') else "0",
            "yes" if hasattr(packet.tcp, 'analysis_retransmission') else "no",
            "yes" if hasattr(packet.tcp, 'analysis_duplicate_ack') else "no",
            "yes" if hasattr(packet.tcp, 'analysis_zero_window') else "no",
            "yes" if hasattr(packet.tcp, 'analysis_window_full') else "no",
            "yes" if hasattr(packet.tcp, 'analysis_reused_ports') else "no",
        ]
        return tcp_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_tls(packet):
    try:
        tls_row = [
            packet.tls.record if hasattr(packet.tls, 'record') else "",
            packet.tls.record_content_type if hasattr(packet.tls, 'record_content_type') else "",
            packet.tls.record_version if hasattr(packet.tls, 'record_version') else "",
            packet.tls.record_length if hasattr(packet.tls, 'record_length') else "",
        ]
        return tls_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_http(packet):
    try:
        http_row = [
            packet.http.request_method if hasattr(packet.http, 'request_method') else "",
            packet.http.request_full_uri if hasattr(packet.http, 'request_full_uri') else "",
            packet.http.request_version if hasattr(packet.http, 'request_version') else "",
            packet.http.host if hasattr(packet.http, 'host') else "",
            packet.http.response_for_uri if hasattr(packet.http, 'response_for_uri') else "",
            packet.http.response_code if hasattr(packet.http, 'response_code') else "",
            packet.http.request_in if hasattr(packet.http, 'request_in') else "",
            packet.http.time if hasattr(packet.http, 'time') else "",
        ]
        return http_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_http_request(packet):
    try:
        http_request_row = [
            packet.http.request_method if hasattr(packet.http, 'request_method') else "",
            packet.http.request_full_uri if hasattr(packet.http, 'request_full_uri') else "",
            packet.http.request_version if hasattr(packet.http, 'request_version') else "",
            packet.http.host if hasattr(packet.http, 'host') else "",
        ]
        return http_request_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_http_response(packet):
    try:
        http_response_row = [
            packet.http.response_for_uri if hasattr(packet.http, 'response_for_uri') else "",
            packet.http.response_code if hasattr(packet.http, 'response_code') else "",
            packet.http.request_in if hasattr(packet.http, 'request_in') else "",
            packet.http.time if hasattr(packet.http, 'time') else "",
        ]
        return http_response_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")


def extract_udp(packet):
    try:
        udp_row = [
            packet.udp.stream if hasattr(packet.udp, 'stream') else "",
            packet.udp.srcport if hasattr(packet.udp, 'srcport') else "",
            packet.udp.dstport if hasattr(packet.udp, 'dstport') else "",
        ]
        return udp_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_dns_query(packet):
    try:
        dns_query = [
            packet.dns.id if hasattr(packet.dns, 'id') else "",
            packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else "",
            packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else "",
        ]
        return dns_query
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_dns_response(packet):
    try:
        dns_response = [
            packet.dns.id if hasattr(packet.dns, 'id') else "",
            packet.dns.flags_rcode if hasattr(packet.dns, 'flags_rcode') else "",
            packet.dns.resp_name if hasattr(packet.dns, 'resp_name') else "",
            packet.dns.time if hasattr(packet.dns, 'time') else "",
            packet.dns.a if hasattr(packet.dns, 'a') else "",
            packet.dns.aaaa if hasattr(packet.dns, 'aaaa') else "",
        ]
        return dns_response
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")


def extract_smb2_request(packet):
    try:
        smb2_request = [
            packet.smb2.sesid if hasattr(packet.smb2, 'sesid') else "",
            packet.smb2.msg_id if hasattr(packet.smb2, 'msg_id') else "",
            packet.smb2.cmd if hasattr(packet.smb2, 'cmd') else "",
        ]
        return smb2_request
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_smb2_response(packet):
    try:
        smb2_response = [
            packet.smb2.sesid if hasattr(packet.smb2, 'sesid') else "",
            packet.smb2.msg_id if hasattr(packet.smb2, 'msg_id') else "",
            packet.smb2.cmd if hasattr(packet.smb2, 'cmd') else "",
            packet.smb2.nt_status if hasattr(packet.smb2, 'nt_status') else "",
            packet.smb2.time if hasattr(packet.smb2, 'time') else "",
        ]
        return smb2_response
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")


def extract_rpc_request(packet):
    try:
        rpc_request = [
            packet.rpc.xid if hasattr(packet.rpc, 'xid') else "",
            packet.rpc.msgtyp if hasattr(packet.rpc, 'msgtyp') else "",
            packet.rpc.program if hasattr(packet.rpc, 'program') else "",
            packet.rpc.programversion if hasattr(packet.rpc, 'programversion') else "",
            packet.rpc.procedure if hasattr(packet.rpc, 'procedure') else "",
            packet.rpc.auth_machinename if hasattr(packet.rpc, 'auth_machinename') else "",
            packet.rpc.auth_uid if hasattr(packet.rpc, 'auth_uid') else "",
            packet.rpc.auth_gid if hasattr(packet.rpc, 'auth_gid') else "",
        ]
        return rpc_request
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_rpc_response(packet):
    try:
        rpc_response = [
            packet.rpc.xid if hasattr(packet.rpc, 'xid') else "",
            packet.rpc.msgtyp if hasattr(packet.rpc, 'msgtyp') else "",
            packet.rpc.program if hasattr(packet.rpc, 'program') else "",
            packet.rpc.programversion if hasattr(packet.rpc, 'programversion') else "",
            packet.rpc.procedure if hasattr(packet.rpc, 'procedure') else "",
            packet.rpc.repframe if hasattr(packet.rpc, 'repframe') else "",
            packet.rpc.time if hasattr(packet.rpc, 'time') else "",
            packet.nfs.status3 if hasattr(packet.nfs, 'status3') else "",
            packet.nfs.nfsstat4 if hasattr(packet.nfs, 'nfsstat4') else "",
        ]
        return rpc_response
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_nfs_response(packet):
    try:
        nfs_response_row = [
            packet.nfs.status if hasattr(packet.nfs, 'status') else "",
        ]
        return nfs_response_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")

def extract_mq_tsh(packet):
    try:
        mq_tsh_row = [
            packet.mq.tsh_structid if hasattr(packet.mq, 'tsh_structid') else "",
            packet.mq.tsh_seglength if hasattr(packet.mq, 'tsh_seglength') else "",
            packet.mq.tsh_convid if hasattr(packet.mq, 'tsh_convid') else "",
            packet.mq.tsh_requestid if hasattr(packet.mq, 'tsh_requestid') else "",
            packet.mq.tsh_type if hasattr(packet.mq, 'tsh_type') else "",
            packet.mq.tsh_ccsid if hasattr(packet.mq, 'tsh_ccsid') else "",
        ]
        return mq_tsh_row
    except Exception as e:
        print(f"Error processing packet: {packet}, Error: {str(e)}")


#################################################################################
#################################################################################
#################################################################################
# Iterate through the PCAP paths from inputs.conf and process them

def checkPermission(directory):
    # Check if PCAP_Output is writeable
    if os.access(directory, os.W_OK):
        return True
    else:
        return False

def checkFile(file):
    # Check if the file exists
    return os.path.exists(file)


def processFile():
    try:
        # Check if PCAP_Output is writeable
        if not checkPermission(output_directory):
            raise PermissionError(f"No write permission in the directory: {output_directory}")

        # Check if inputs.conf exists
        if not checkFile(inputs_conf_path):
            raise FileNotFoundError(f"File not found: {inputs_conf_path}")

        files_processed = False

        for section in config.sections():
            if section.startswith("pcap://"):
                path = config.get(section, "path")
                for file in os.listdir(path):
                    if file.endswith(".pcap") or file.endswith(".pcapng"):
                        file_path = os.path.join(path, file)
                        initial_size = os.path.getsize(file_path) # Get file size
                        start_time = time.time()  # Record the start time
                        
                        # Check if extract_data_from_pcap was successful
                        success = extract_data_from_pcap(file_path)

                        if success:
                            destination_folder = os.path.dirname(file_path)
                            destination_path = os.path.join(destination_folder, "converted", file)
                            os.makedirs(os.path.dirname(destination_path), exist_ok=True)
                            shutil.move(file_path, destination_path)
                            end_time = time.time()  # Record the end time
                            elapsed_time = end_time - start_time
                            files_processed = True
                            print(f"Converted {file} with size of {initial_size} bytes in {elapsed_time:.2f} seconds.")
                        else:
                            print(f"Skipping file {file} due to errors in processing.")


        if not files_processed:
            print("No .pcap or .pcapng files found for processing.")

    except PermissionError as pe:
        print(f"Permission error: {str(pe)}")

    except FileNotFoundError as fe:
        print(f"FileNotFoundError: {fe}")

    except Exception as e:
        print(f"Error processing files: {file}, Error: {str(e)}")

# main
if __name__ == "__main__":
    processFile()