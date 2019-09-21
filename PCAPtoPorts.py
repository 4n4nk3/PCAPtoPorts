#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PCAPtoPorts, a simple parser written in python to quickly get ports and connections related to a specific HOST from a PCAP file.\n"""

# Written By Ananke: https://github.com/4n4nk3
import argparse
from colorama import init, Back, Style
import pyshark

init()

parser = argparse.ArgumentParser(
    description='A simple parser written in python to quickly get ports and connections related to a specific HOST from a PCAP file.')
required = parser.add_argument_group('required arguments')
# Required arguments
required.add_argument('--input', help='Input file name', required=True)
required.add_argument('--host', help='Specify the IP address of the host on which you want to investigate',
                      required=True)

args = parser.parse_args()
incoming = {}
outgoing = {}

try:
    # Open pcap file
    cap = pyshark.FileCapture(args.input)
    for packet in cap:
        if 'IP' in packet:
            destination_ip = str(packet.ip.dst)
            origin_ip = str(packet.ip.src)
            # Check if target IP is involved with the current packet
            if destination_ip == args.host or origin_ip == args.host:
                # Check if current packet is TCP or UDP and so if I can get PORT's data from it
                if 'UDP' in packet or 'TCP' in packet:
                    if 'UDP' in packet:
                        packet_type = 'udp'
                        destination_port = str(packet.udp.dstport)
                        source_port = str(packet.udp.port)
                    else:
                        packet_type = 'tcp'
                        destination_port = str(packet.tcp.dstport)
                        source_port = str(packet.tcp.port)
                    # If the destination IP is the same as the target IP the packet is INCOMING to the target
                    if destination_ip == args.host:
                        if origin_ip not in incoming:
                            incoming[origin_ip] = set()
                        else:
                            incoming[origin_ip].add(
                                packet_type + ':' + source_port + ':' + destination_port + ':' + origin_ip)
                    # If the origin IP is the same as the target IP the packet is OUTGOING from the target
                    elif origin_ip == args.host:
                        if destination_ip not in outgoing:
                            outgoing[destination_ip] = set()
                        else:
                            outgoing[destination_ip].add(
                                packet_type + ':' + source_port + ':' + destination_port + ':' + destination_ip)

    # Print the results
    output_header = ['TYPE', 'SOURCE PORT', 'DESTINATION PORT', 'ORIGIN IP']
    print('\nINCOMING TRAFFIC')
    for ip in incoming:
        check = False
        for connection in incoming[ip]:
            output = connection.split(':')
            if len(output) == 4:
                check = True
                break
        if check is True:
            print(Style.DIM + '\t' + '=' * 100 + Style.RESET_ALL)
            print('\t{}Incoming{} traffic from IP:\t\t\t\t\t\t\t{}{}{}'.format(Back.LIGHTBLUE_EX, Style.RESET_ALL,
                                                                               Back.LIGHTBLUE_EX, ip, Style.RESET_ALL))
            print(Style.DIM + '\t' + '-' * 100 + Style.RESET_ALL)
            print('\t' + ''.join(element.ljust(25) for element in output_header))
            print(Style.DIM + '\t' + '-' * 100 + Style.RESET_ALL)
            for connection in incoming[ip]:
                print('\t' + ''.join(element.ljust(25) for element in output))
            print('\n\n')

    output_header = ['TYPE', 'SOURCE PORT', 'DESTINATION PORT', 'DESTINATION IP']
    print('\n' + Back.LIGHTRED_EX + ' ' * 108 + Style.RESET_ALL)
    print('OUTGOING TRAFFIC')
    for ip in outgoing:
        check = False
        for connection in outgoing[ip]:
            output = connection.split(':')
            if len(output) == 4:
                check = True
                break
        if check is True:
            print(Style.DIM + '\t' + '=' * 100 + Style.RESET_ALL)
            print('\t{}Outgoing{} traffic to IP:\t\t\t\t\t\t\t\t{}{}{}'.format(Back.LIGHTBLUE_EX, Style.RESET_ALL,
                                                                               Back.LIGHTBLUE_EX, ip, Style.RESET_ALL))
            print(Style.DIM + '\t' + '-' * 100 + Style.RESET_ALL)
            print('\t' + ''.join(element.ljust(25) for element in output_header))
            print(Style.DIM + '\t' + '-' * 100 + Style.RESET_ALL)
            for connection in outgoing[ip]:
                output = connection.split(':')
                print('\t' + ''.join(element.ljust(25) for element in output))
            print('\n\n')

except Exception as exception:
    if isinstance(exception, FileNotFoundError):
        print('Input file not found!\nExiting...')
    else:
        print(exception)
    exit(1)
