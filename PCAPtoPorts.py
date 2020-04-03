#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PCAPtoPorts, a simple parser written in python to quickly get ports and connections related to a specific HOST from a PCAP file.\n"""

# Written By Ananke: https://github.com/4n4nk3
import argparse
from sys import exit
from os import path
from collections import defaultdict

import pyshark
from colorama import init, Back, Fore, Style

init()

incoming = defaultdict(set)
outgoing = defaultdict(set)

def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='A simple parser written in python to quickly get ports and connections related to a specific HOST '
                    'from a PCAP file.')
    # Required arguments
    parser.add_argument('--input', help='Input file name', required=True)
    parser.add_argument('--host', help='Specify the IP address of the host on which you want to investigate',
                          required=True)
    # Optional arguments
    parser.add_argument('--tcp', help='Show TCP connections', required=False, action='store_true')
    parser.add_argument('--udp', help='Show UDP connections', required=False, action='store_true')
    parser.add_argument('--srcport', help='Display source ports for shown connections', required=False, action='store_true')
    parser.add_argument('--dstport', help='Display destination ports for shown connections', required=False, action='store_true')
    return parser


def result_printer(indicator, data):
    if indicator == 'incoming':
        if args.srcport is True and args.dstport is True:
            output_header = ['TYPE', 'SOURCE PORT', 'DESTINATION PORT', 'ORIGIN IP']
        elif args.srcport is True:
            output_header = ['TYPE', 'SOURCE PORT', 'ORIGIN IP']
        elif args.dstport is True:
            output_header = ['TYPE', 'DESTINATION PORT', 'ORIGIN IP']
        else:
            output_header = ['TYPE', 'ORIGIN IP']
        print('\nINCOMING TRAFFIC')
    elif indicator == 'outgoing':
        if args.srcport is True and args.dstport is True:
            output_header = ['TYPE', 'SOURCE PORT', 'DESTINATION PORT', 'DESTINATION IP']
        elif args.srcport is True:
            output_header = ['TYPE', 'SOURCE PORT', 'DESTINATION IP']
        elif args.dstport is True:
            output_header = ['TYPE', 'DESTINATION PORT', 'DESTINATION IP']
        else:
            output_header = ['TYPE', 'DESTINATION IP']
        print('\nOUTGOING TRAFFIC')
    else:
        return
    for ip in data:
        print()
        print(Style.DIM + '\t' + '=' * 100 + Style.RESET_ALL)
        if indicator == 'incoming':
            print(f'\t{Fore.LIGHTRED_EX}Incoming{Style.RESET_ALL} traffic from IP:\t\t\t\t\t\t\t{Fore.LIGHTGREEN_EX}{ip}{Style.RESET_ALL}')
        else:
            print(f'\t{Fore.LIGHTRED_EX}Outgoing{Style.RESET_ALL} traffic to IP:\t\t\t\t\t\t\t\t{Fore.LIGHTGREEN_EX}{ip}{Style.RESET_ALL}')
        print(Style.DIM + '\t' + '-' * 100 + Style.RESET_ALL)
        print('\t' + ''.join(element.ljust(25) for element in output_header))
        print(Style.DIM + '\t' + '-' * 100 + Style.RESET_ALL)
        for connection in data[ip]:
            output = connection.split(':')
            print('\t' + ''.join(element.ljust(25) for element in output))



parser = init_argparse()
args = parser.parse_args()

if args.tcp is False and args.udp is False:
    parser.error('In order to run PCAPtoPorts you need to specify at least one protocol!')

if path.isfile(args.input) is False:
    print('Input file not found!\nExiting...')
    exit(1)

# Open pcap file
cap = pyshark.FileCapture(args.input)
for packet in cap:
    if 'IP' in packet:
        destination_ip = str(packet.ip.dst)
        origin_ip = str(packet.ip.src)
        # Check if target IP is involved with the current packet
        if destination_ip == args.host or origin_ip == args.host:
            # Check if current packet is TCP or UDP and so if I can get PORT's data from it
            if 'UDP' in packet and args.udp is True:
                packet_type = 'udp'
                destination_port = str(packet.udp.dstport)
                source_port = str(packet.udp.port)
            elif 'TCP' in packet and args.tcp is True:
                packet_type = 'tcp'
                destination_port = str(packet.tcp.dstport)
                source_port = str(packet.tcp.port)
            else:
                continue
            # If the destination IP is the same as the target IP the packet is INCOMING to the target
            if destination_ip == args.host:
                if args.srcport is True and args.dstport is True:
                    incoming[origin_ip].add(packet_type + ':' + source_port + ':' + destination_port + ':' + origin_ip)
                elif args.srcport is True:
                    incoming[origin_ip].add(packet_type + ':' + source_port + ':' + origin_ip)
                elif args.dstport is True:
                    incoming[origin_ip].add(packet_type + ':' + destination_port + ':' + origin_ip)
                else:
                    incoming[origin_ip].add(packet_type + ':' + origin_ip)
            # If the origin IP is the same as the target IP the packet is OUTGOING from the target
            elif origin_ip == args.host:
                if args.srcport is True and args.dstport is True:
                    outgoing[destination_ip].add(
                        packet_type + ':' + source_port + ':' + destination_port + ':' + destination_ip)
                elif args.srcport is True:
                    outgoing[destination_ip].add(packet_type + ':' + source_port + ':' + destination_ip)
                elif args.dstport is True:
                    outgoing[destination_ip].add(packet_type + ':' + destination_port + ':' + destination_ip)
                else:
                    outgoing[destination_ip].add(packet_type + ':' + destination_ip)

result_printer('incoming', incoming)
print('\n' + Back.LIGHTBLUE_EX + ' ' * 108 + Style.RESET_ALL)
result_printer('outgoing', outgoing)
