#!/usr/bin/ env python

import scapy.all as scapy
import optparse

def get_args():
    parser = optparse.OptionParser()
    parser.add_option('-t', '--target', dest='target', help='Choose target IP or IP range')
    options, arguments = parser.parse_args()

    if not options.target:
        parser.error("""[-] Missing target IP
                            Use --help for more info""")
    return options


def scan(ip):
    #sends IP request to network
    arp_request = scapy.ARP(pdst=ip)
    
    #sets destination MAC to broadcast MAC
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    
    #combines above packets into one packet
    arp_request_broadcast = broadcast/arp_request
    
    #sends packets and returns answered and unanswered requests
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False) [0]
    
    client_list = []
    for item in answered_list:

        client_dict = {
            "IP" : item[1].psrc,
            "MAC": item[1].hwsrc 
        }
        client_list.append(client_dict)   
    return client_list


def print_result(result_list):
    print("____________________________________________")
    print("IP\t\t\tMAC ADDRESS\n--------------------------------------------")
    for c in result_list:
        print(c['IP'] + "\t\t" + c['MAC'])

    
options = get_args()
scan_result = scan(options.target)
print_result(scan_result)
