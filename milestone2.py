#!/usr/bin/python3

#Imports at the top
import argparse
from scapy import asn1fields
from scapy.all import *

#All functions that organize code go here
def ArgParse_Helper():
    parser = argparse.ArgumentParser(description="Nmap application")
    parser.add_argument("--IP",action='store', help="Enter the IP oe IP block eg 10.10.10.10 or IP block 10.10.10.0/24")
    parser.add_argument("--scan_type",action='store', help="Enter the scan type, available options are  'TCP-ACK, TCP-SYN, UDP'")
    parser.add_argument("--port_range", nargs="+",  help="Enter the port number or port list", required=True)
    parser.add_argument("--version", action="version", version='%(progs)s 1.0')
    args=parser.parse_args()
    return args

def TCP_ACK(ip, port_list):
    for each_port in port_list:
        print(f"Scanning for port {each_port}...\n")
        ans, unans = sr( IP(dst=ip)/TCP(flags='A', dport=(each_port)), timeout=5)
        if len(ans) > 0:
            for sent,received in ans:
                if sent[IP].dport == received[IP].sport:
                    print(f"\nPort {each_port} is unfiltered and a stateful firewall is absent at server end")
                    print("-"*120)
                else:
                    print(f'\nPort {each_port} is filtered and a stateful firewall is present at server end')
                    print("-"*120)

        else:
            print('\nNo response received :( Try again')
            print("-"*120)

def TCP_SYN(ip, port_list):
    for each_port in port_list:
        print(f"Scanning for port {each_port}...\n")
        ans, unans = sr( IP(dst=ip)/TCP(flags='S', dport=(each_port)), timeout=5)
        if len(ans) > 0:
            for sent,received in ans:
                if sent[TCP].dport == received[TCP].sport:
                    print(f"\nHost with IP {ip} on port {each_port} is open")
                    print("-"*120)
                else:
                    print(f'\nHost with IP {ip} on port {each_port} is closed')
                    print("-"*120)

        else:
            print('\nNo response received :( Try again')
            print("-"*120)

def UDP_scan(ip, port_list):
    for each_port in port_list:
        print(f"Scanning for port {each_port}...\n")
        ans, unans = sr( IP(dst=ip)/UDP(dport=(each_port)), timeout=5)
        if len(ans) > 0:
            for sent,received in ans:
                if sent[IP].dport == received[IP].sport:
                    print(f"\nHost with IP {ip} on port {each_port} is open")
                    print("-"*120)
                else:
                    print(f'\nHost with IP {ip} on port {each_port} is closed')
                    print("-"*120)

        else:
            print('\nNo response received :( Try again')
            print("-"*120)

#At the end, the main function encapsulates the core logic
def main():
    args=ArgParse_Helper()
    port_list = [int(x) for x in args.port_range]

    if args.scan_type == 'TCP-ACK':
        TCP_ACK(args.IP, port_list)

    elif args.scan_type == 'TCP-SYN':
        TCP_SYN(args.IP, port_list)

    elif args.scan_type == 'UDP':
        UDP_scan(args.IP, port_list)

    else:
        print("Oops! Invalid scan type chosen :(.....Try again!!!!!")

#The code concludes with the namespace check.
if __name__ == "__main__":
    main()
