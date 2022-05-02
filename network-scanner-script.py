import scapy.all as scapy
import socket
import os
from datetime import datetime
import configparser

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

prog_config = configparser.ConfigParser()
prog_config.read(__location__+'/network-scanner-script.config')

network_scan_filename = prog_config.get('DEFAULT', 'NetworkScanFileName', fallback='network_scan.txt')
network_scan_filepath = prog_config.get('DEFAULT', 'NetworkScanFilePath', fallback='')
if(network_scan_filepath == ''):
    network_scan_filepath = __location__+'/'+network_scan_filename
ip_network_address = prog_config.get('DEFAULT', 'IPNetworkAddress', fallback='192.168')
ip_host_range_start = prog_config.getint('DEFAULT', 'IPHostRangeStart', fallback='0')
ip_host_range_end = prog_config.getint('DEFAULT', 'IPHostRangeEnd', fallback='1')

# output interface in case pc is defaulting to different than ethernet
print(scapy.conf.iface)

def scan(ip):
    ip = "192.168.88.244/24"
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unans = scapy.srp(arp_request_broadcast, timeout=0.25,verbose=False)
    clients_list = []
    if answered_list is not None:
        for element in answered_list:
            #print("answered")
            try:
                hostname = socket.gethostbyaddr(ip)
                hostname = hostname[0]
            except:
                hostname = "unknown"
            client_dict = {"hostname": hostname, "ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)
    return clients_list
 
#print("IP"+"\t\t\t"+"MAC")
with open(network_scan_filepath, 'w') as f:
    f.write('%s\n' %datetime.now())
    for i in range(ip_host_range_start,ip_host_range_end): #86,87
        for j in range(1,256):
            curr_ip = ip_network_address+"."+str(i)+"."+str(j)
            #print(curr_ip)
            scan_result = scan(curr_ip)
            if scan_result != []:
                #print(scan_result[0]['ip']+"\t\t"+scan_result[0]['hostname'])
                #print(scan_result[0]['hostname'])
                f.write(str(scan_result[0]['hostname'])+'\t'+str(scan_result[0]['ip'])+'\t'+str(scan_result[0]['mac'])+ '\n')
            
            
