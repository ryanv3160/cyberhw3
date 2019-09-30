# ****************************************************************************************************
# Name: Ryan Vacca
#       Matthew Moltzaou
#       Julia Vrooman
#
# Due Date: 10/08/2019
#
# Assignment: HW3 : Port Scanner Detector
#
# Program Description: 
#
# Program Status: 
#
# ****************************************************************************************************

# Import needed libraries
import ipaddress
import threading 
import time
import socket
import re
import struct


SUB_NET = "192.168.10."
FAN_OUT_SEC = 5
FAN_OUT_MIN = 100
FAN_OUT_FIVEMIN = 300
HASH_TABLE_SIZE = 262144

hashTable = {}

# Works
def populateHashTable():
    IPkeys = 0      # Range of IP's in LAN: 108.168.10.0 - 108.168.10.255
    PortKeys = 0    # TODO: update later to all ports 65536 ??? currently only 0 - 1023
   
    for i in range(HASH_TABLE_SIZE): # Range = (256 "IP's") * (1024 "Ports") = 262144
        hashTable[i] = (0,mapkeyToIp(str(IPkeys)),"Empty",PortKeys,0)

        if(PortKeys == 1023):
            PortKeys = 0
            IPkeys += 1

        else:
            PortKeys += 1

# Works
def printHashTable():
    for i in range(HASH_TABLE_SIZE):
        print(hashTable[i])


#******************* Portion from Sniffer lab03 ****************#

# Ethernet layer frame parser
# Capture each frame at this layer and dissect bytes in header based
# off known frame header layout
def ethernet_dissect(ethernet_data):
    # First six characters / bytes destination address, "6s" for MAC address.
    # Second six characters / bytes source address, "6s" for MAC address.
    # Third two characters / bytes type, "H" unsigned short integer for protocol
    dest_mac, src_mac, protocol = struct.unpack('!6s 6s H', ethernet_data[:14])
    # Return Source & Destination MAC address's, Protocol, and the payload
    # Note on Htons will convert protocol integers from host -> network byte order. Endian overcoming.
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]


# Function to format MAC address from byte string to proper readable format
def mac_format(mac):
    # Map the raw passed in mac address string with format selected
    mac = map('{:02x}'.format, mac)
    # Convert string to all same upper case and append : for readability
    return ':'.join(mac).upper()
def ipv4_dissect(ip_data):
    ip_protocol, source_ip, target_ip = struct.unpack('!9x B 2x 4s 4s', ip_data[:20])
    return ip_protocol, ipv4_format(source_ip), ipv4_format(target_ip), ip_data[20:]


# Format the data to strings and append dot for readability
def ipv4_format(address):
    return '.'.join(map(str, address))


# TCP Packet : Parse the data portion of the packet
# 1) Source Port : First 2 Bytes
# 2) Destination Port : Second 2 Bytes
def tcp_dissect(transport_data):
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port

# UDP Packet : Parse the data portion of the packet
# 1) Source Port : First 2 Bytes
# 2) Destination Port : Second 2 Bytes
def udp_dissect(transport_data):
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port



#******************* Set Up Threads Function *******************#
def initiateThreads():
    # Create Threads 
    sniff_traffic_thread = threading.Thread(target=snifferThread, args=("TH1",)) 
    fan_out_rate_thread = threading.Thread(target=fannerThread, args=("TH2",))
    table_time_out_thread = threading.Thread(target=timerThread, args=("TH3",)) 
  
    # Start Threads 
    sniff_traffic_thread.start() 
    fan_out_rate_thread.start() 
    table_time_out_thread.start()
  
    # Join threads 
    sniff_traffic_thread.join()  
    fan_out_rate_thread.join() 
    table_time_out_thread.join()
  
    # All threads complete  
    print("We have joined : Sniffer Thread, Fan Out Thread, Table Time Out Thread.")
    print("Program exit.")


#******************* Thread 1 : Sniff Traffic  Functions *******************#
def snifferThread(num): 

    print("Inside Sniffer: {}".format(num))

    # Create a Raw Socket
    packets = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

    # Main loop to listen for packets on LAN
    while True:

        # Max buffer size that can be defined
        # Return 1) ethernet data which is what is in the packet to which we will do
        # analysis on, We do not us address for this lab, implement dummy catcher
        ethernet_data, address = packets.recvfrom(65536)

        # Call function to parse returned frame
        dest_mac, src_mac, protocol, ip_data = ethernet_dissect(ethernet_data)

        # Exterior Gateway Protocol IP4 packet, which we are using.
        if protocol == 8:

            # Call function to parse IPV4 packet
            ip_protocol, source_ip, dest_ip, transport_data = ipv4_dissect(ip_data)

            # TCP Protocol within IP4 Packet
            if ip_protocol == 6:
                # TCP Parse Source and Destination Port portion of packet
                src_port, dest_port = tcp_dissect(transport_data)
                # Print desired format 
                #print("TCP --> source mac:{0}, dest mac:{1}, source ip:{2}, dest ip:{3}, protocol:{4}, source port:{5}, ""dest port:{6}".format(src_mac, dest_mac, source_ip, dest_ip, ip_protocol, src_port, dest_port))

            # UDP Protocol within IP4 Packet
            if ip_protocol == 17:
                # UDP Parse Source and Destination Port portion of packet
                src_port, dest_port = udp_dissect(transport_data)
                # Print desired format
                #print("UDP --> source mac:{0}, dest mac:{1}, source ip:{2}, dest ip:{3}, protocol:{4}, source port:{5}, ""dest port:{6}".format(src_mac, dest_mac, source_ip, dest_ip, ip_protocol, src_port, dest_port))


# Function adds new entry to table if entry not in table 
def newTableEntry(entry):

    # Not found in list, so add to list
    if checkInTable(entry):
        tup.append(entry)
    

#******************* Thread 2 : Fan Out Rate   Functions *******************#
def fannerThread(num): 
    print("Inside Fanner: {}".format(num))
    fannerOutput(5,100,300,"192.169.10.45")

def fannerOutput(second, minute, fiveminute, IPAddress):
    print("Port scanner detected on source IP {} ".format(IPAddress))
    print("Avg fan-out per second: {}, Avg fan-out per min: {}, Avg fan-out per 5min: {}".format(second,minute,fiveminute))

#******************* Thread 3 : Table Time Out Functions *******************#
def timerThread():
    print("Inside Timer: {}".format(num))

def checkTimeOutTableEntry(entry):
    current_time = time.time()

def deleteTableEntry():
    print("")

def checkInTable(entry):

    # Start off assuming entry is not in list
    found = False
"""
    # Check if entry exists in table 
    for tup in first_contact_list:
        if ((tup[0] == entry[0]) and (tup[1] == entry[1]) and (tup[2] == entry[2])):
            found = True
            return found
    return found 
"""

# Works
def mapkeyToIp(key):
    prefix = SUB_NET
    IPAddress = prefix + key
    return IPAddress

# Works
def mapIpToKey(IPAddress):
    postfix = IPAddress[11:]
    return postfix

# Function to delete first contact in table older than 5 minutes
def firstContactTimeElapse(index):

    # No entry for this source IP address
    # Return early 
    if hashTable[index][0] == 0:
        return 

    # Get difference in time current minus table entry
    time_difference = time.time() - hashTable[index][4]

    # If difference is greater or equal to 5 minutes
    # Zero out the entry 
    if time_difference >= 300.0:
        hashTable[index][0] = 0
        hashTable[index][2] = ""
        hashTable[index][3] = ""
        hashTable[index][4] = 0





# ****************************************************************************************************
# Function : main
#
# Description : This function
#
# Input:   1) 
#  
#
# Returns: Nothing
#
# **************************************************************************************************** 
def main():

    populateHashTable()
    printHashTable()



# Program entry 
if __name__ == "__main__": 
    main()











