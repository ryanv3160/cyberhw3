import socket
from struct import unpack
from datetime import datetime
    
# Note: AF_PACKET does not work on Mac, but works on Linux
_packets = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

# This function sniffs data and immediately puts it on a queue to be processed. It does this
# so that it doesn't miss other incoming packets while processing the data or while waiting
# to receive the table from another channel.
# 
# Note: not all packets will be received, but it allows us to capture x2 the number of
# packets from before. It may also be beneficial to start two sniffers at once. When I tested
# that, I got an extra 100 packets. Is the recvfrom method atomic as to prevent duplicates?
def sniff(data_queue): 
    
    while True:
        
        # Does this only sniff packets incoming to the host? If so, that might mean
        # storing the destination ip may not be necessary. At the moment, the destination
        # ip in the key isn't ever referenced. I think it can be removed. TODO: Test this
        ethernet_data, _ = _packets.recvfrom(65536)
        data_queue.put(ethernet_data)

def dissect(data_queue, channel):

    while True:

        ethernet_data = data_queue.get()
        dst_mac, src_mac, protocol, ip_data = ethernet_dissect(ethernet_data)
        
        if protocol == EthernetProtocol.IPV4:
            
            ip_protocol, src_ip, dst_ip, transport_data = ipv4_dissect(ip_data)
            
            if ip_protocol == IPProtocol.ICMP:
                icmp_type, icmp_code = icmp_dissect(transport_data)
                # do nothing..
            
            if ip_protocol == IPProtocol.TCP:
                src_port, dst_port = tcp_dissect(transport_data)
                table = channel.get()
                key = (src_ip, dst_ip, dst_port)
                if key not in table:
                    table[key] = datetime.now()
                channel.put(table)
                
            elif ip_protocol == IPProtocol.UDP:
                src_port, dst_port = udp_dissect(transport_data)
                # do nothing..
                
                # After we implement a scanner detector for TCP,
                # we may want to add UDP on top of that. We should
                # distinguish TCP and UDP ports in the table we
                # have, and we might need to incorporate logic
                # taken from ICMP? (I don't think think this is
                # the case)

class EthernetProtocol():
    IPV4 = 8

class IPProtocol():
    ICMP = 1
    TCP = 6
    UDP = 17

def ethernet_dissect(ethernet_data):
    dst_mac, src_mac, protocol = unpack('!6s 6s H', ethernet_data[:14])
    return mac_format(dst_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]

def mac_format(mac):
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()

def ipv4_dissect(ip_data):
    ip_protocol, source_ip, target_ip = unpack('!9x B 2x 4s 4s', ip_data[:20])
    return ip_protocol, ipv4_format(source_ip), ipv4_format(target_ip), ip_data[20:]

def ipv4_format(address):
    return '.'.join(map(str, address))

def icmp_dissect(transport_data):
    icmp_type, code = unpack('!BB', transport_data[:2])
    return icmp_type, code

def tcp_dissect(transport_data):
    source_port, dst_port = unpack('!HH', transport_data[:4])
    return source_port, dst_port

def udp_dissect(transport_data):
    source_port, dst_port = unpack('!HH', transport_data[:4])
    return source_port, dst_port

