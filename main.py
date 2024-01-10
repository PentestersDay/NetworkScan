#!usr/bin/env python
import scapy.all as scapy
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("-I", "--ip", dest="ip", help="Enter the desired IP address!")
options = parser.parse_args()
if not options.ip:
    parser.error("Please enter IP address!")
if len(options.ip) < 12:
    parser.error("Please check IP address!")
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []

    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(result_list):
    print("IP address \t\t MAC address \n---------------------------------------------------------")
    for client in result_list:
        print(client["IP"] + "\t\t" + client["MAC"])

result_list = scan(options.ip)
print_result(result_list)
