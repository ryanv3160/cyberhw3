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

# *********** CONSTANTS *********** #
SUB_NET = "192.168.10."   # Subnet of LAN

OLD_ENTRY_TIME = 5        # Time value in minutes for stale table entry
FAN_OUT_SEC = 5           # Fan out rate for per second
FAN_OUT_MIN = 100         # Fan out rate for per minute
FAN_OUT_FIVE_MIN = 300     # Fan out rate for per five minute
HASH_TABLE_SIZE = 262144  # Size of hash table: (256 "IP's") * (1024 "Ports") = 262144 Total possible entries

STALE_ENTRY = False
CURRENT_ENTRY = True
EMPTY_STRING = "Empty"
ZERO_TIME = 0
FIVE_MINUTES = 300

PORT_MAX = 1023
IP_MAX = 255

PORT_MATH = 1024
IP_MATH = 256

# Enumerations for tuple
CURRENT_OR_STALE = 0
IPADDRESS_SOURCE = 1 
IPADDRESS_DESTINATION = 2
PORT_DESTINATION = 3
TIME_STAMP = 4





# Make Hash table of connections global
# Each entry in the hash table is comprised of a tuple in regards to an attempted connection
# Each tuple is of the form <boolean,string,string,integer,float> 1,2,3,4,5
# 1) Boolean value representing .. True: Timestamp < 5 minutes .. False: Timestamp >= 5 minutes
# 2) IPAddress of source 
# 3) IPAddress of destination 
# 4) Port number of destination
# 5) Timestamp of last attempted connection
hashTable = {}

# ****************************************************************************************************
# Function : populateHashTable
# Description : This function populates the hash table of all possible connections in the LAN.      
# Input:   None
# Returns: Nothing
# Note:    1) Range of IP's in LAN: 108.168.10.0 - 108.168.10.255
#          2) # TODO: update later to all ports 65536 ??? currently only 0 - 1023
# ****************************************************************************************************
def populateHashTable():
    IPkeys = 0      # Index for IPAddress's
    PortKeys = 0    # Index for Port's
   
    # Loop Through Table adding entries
    for i in range(HASH_TABLE_SIZE): # Range = 262144
        hashTable[i] = (STALE_ENTRY, mapkeyToIp(str(IPkeys)), EMPTY_STRING, PortKeys, ZERO_TIME)

        if(PortKeys == PORT_MAX):
            PortKeys = 0
            IPkeys += 1
        else:
            PortKeys += 1


# ****************************************************************************************************
# Function : printHashTable
# Description : This function prints the hashtable, ** mainly for testing purposes      
# Input:   None
# Returns: Nothing
# Note:
# ****************************************************************************************************
def printHashTable():
    for i in range(HASH_TABLE_SIZE):
        print(hashTable[i])


# ****************************************************************************************************
# Function : initiateThreads
# Description : This function creates the 3 threads needed for this program. 
#               1) sniff_traffic_thread:  Thread to capture all packet traffic on LAN
#               2) fan_out_rate_thread:   Thread to calculate fan out rate and display in std_out
#               3) table_time_out_thread: Thread to constantly cycle through hash table checking table 
#                                         entry timestamps, setting boolean value of tuple appropriatly
# Input:   None
# Returns: Nothing
# Note: Set Up Threads Function
# ****************************************************************************************************
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




# ----------------------------- Thread 1 : Sniff Traffic Functions ----------------------------------#

# ****************************************************************************************************
# Function : snifferThread : Entry point for thread 1!!
# Description : This function is logic behind sniffing traffic on the LAN .. TCP and UDP      
# Input:   Dummy string saying thread1. Can remove later...
# Returns: Nothing
# Note: TODO: Needs work !! Correctly sniffs traffic but doesnt yet populate the table 
# ****************************************************************************************************
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
                
                # ***** TODO ******
                # TEST THIS , function below logic works but havent run with live scan
                updateTableEntry(source_ip, dest_ip, dest_port)



            # UDP Protocol within IP4 Packet
            if ip_protocol == 17:
                # UDP Parse Source and Destination Port portion of packet
                src_port, dest_port = udp_dissect(transport_data)
                # Print desired format
                #print("UDP --> source mac:{0}, dest mac:{1}, source ip:{2}, dest ip:{3}, protocol:{4}, source port:{5}, ""dest port:{6}".format(src_mac, dest_mac, source_ip, dest_ip, ip_protocol, src_port, dest_port))
                
                # ***** TODO ******
                # TEST THIS , function below logic works but havent run with live scan
                updateTableEntry(source_ip, dest_ip, dest_port)


# ****************************************************************************************************
# Function : ethernet_dissect : Ethernet layer frame parser
# Description : This function parses packet into destination mac address, source mac address, and protocol
#               Capture each frame at this layer and dissect bytes in header based
#               First six characters / bytes destination address, "6s" for MAC address.
#               Second six characters / bytes source address, "6s" for MAC address.
#               Third two characters / bytes type, "H" unsigned short integer for protocol             
# Input:   1) Captured packet raw
# Returns: 1) Destination mac address
#          2) Source mac address
#          3) Protocol in byte order, Endian overcoming
#          4) Remaining data which is the payload
# Note: Works!
# ****************************************************************************************************
def ethernet_dissect(ethernet_data):
    dest_mac, src_mac, protocol = struct.unpack('!6s 6s H', ethernet_data[:14])
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]


# ****************************************************************************************************
# Function : mac_format 
# Description : This function maps the raw passed in mac address string with format selected and  
#               converts string to all same upper case and append : for readability  
# Input:   1) Mac address
# Returns: 1) Readable Mac address
# Note: Works!
# ****************************************************************************************************
def mac_format(mac):
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()


# ****************************************************************************************************
# Function : ipv4_dissect 
# Description : This function parses IPV4 captured packet header for IP: protocol, source, destination  
# Input:   1) Network Layer header portion
# Returns: 1) IP protocol
#          2) IP source address
#          3) IP destiantion address
# Note: Works!
# ****************************************************************************************************
def ipv4_dissect(ip_data):
    ip_protocol, source_ip, target_ip = struct.unpack('!9x B 2x 4s 4s', ip_data[:20])
    return ip_protocol, ipv4_format(source_ip), ipv4_format(target_ip), ip_data[20:]


# ****************************************************************************************************
# Function : ipv4_format
# Description : This function formats the data to strings and append dot for readability
# Input:   1) Raw Data from packet
# Returns: 1) Readable format
# Note: Works!
# ****************************************************************************************************
def ipv4_format(address):
    return '.'.join(map(str, address))


# ****************************************************************************************************
# Function :  tcp_dissect
# Description : This function parses TCP header for source and destination port number values
# Input:   1) Transport Data payload IE Port numbers
# Returns: 1) Source Port : First 2 Bytes
#          2) Destination Port : Second 2 Bytes
# Note: Works!
# ****************************************************************************************************
def tcp_dissect(transport_data):
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port


# ****************************************************************************************************
# Function : udp_dissect
# Description : This function parses a UDP header for source and destination port number values
# Input:   1) Transport Data payload IE Port numbers
# Returns: 1) Source Port : First 2 Bytes
#          2) Destination Port : Second 2 Bytes
# Note: Works!
# ****************************************************************************************************
def udp_dissect(transport_data):
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port


# ****************************************************************************************************
# Function :  updateTableEntry
# Description : This function updates table entry based on captured traffic between source and destination
# Input:   1) IP Source
#          2) IP Destination
#          3) Port Destination
# Returns: Nothing
# Note: Works!
# ****************************************************************************************************
def updateTableEntry(ip_src, ip_dest, port_dest):
    
    # Get correct index to update
    table_index = mapToIndex(ip_src, port_dest)

    # Tuples are immutable in python 
    temp = list(hashTable[table_index])
    temp[CURRENT_OR_STALE] = CURRENT_ENTRY
    temp[IPADDRESS_DESTINATION] = ip_dest
    temp[TIME_STAMP] = time.time()
 
    # Update table
    hashTable[table_index] = tuple(temp)




# ----------------------------- Thread 2 : Fan Out Rate Functions -----------------------------------#

# ****************************************************************************************************
# Function : fannerThread : Entry point for thread 2!!
# Description : This function is logic behind calculating fan out rate calculations.       
# Input:   Dummy string saying thread2. Can remove later...
# Returns: Nothing
# Note: TODO: Needs work !! 
# ****************************************************************************************************
def fannerThread(num): 
    print("Inside Fanner: {}".format(num))  # Dummy print
    detection_list = fannerCalculation()
    fannerOutput(5,100,300,"192.169.10.45") # Dummy test values


# ****************************************************************************************************
# Function : fannerOutput : 
# Description : This function displays calculations for fan out rate of newly detected port scanner      
# Input:   1) Display value for Second
#          2) Display value for Minute
#          3) Display value for Five minutes
#          4) Display value for IPAddress
# Returns: Nothing
# Note: None
# ****************************************************************************************************
def fannerOutput(second, minute, fiveminute, IPAddress):
    print("Port scanner detected on source IP {} ".format(IPAddress))
    print("Avg fan-out per second: {}, Avg fan-out per min: {}, Avg fan-out per 5min: {}".format(second,minute,fiveminute))


#****************************************************************************************************
# LOGIC BEHIND CHECKING THE TABLE FOR ENTRIES THAT TRIGGER AN IP ADDRESS AS A SCANNER 
# TODO: NEEDS WORK 
def fannerSecond(ipAddress, currentTime, totalTime)
    avg_time = totalTime/PORT_MATH
def fannerMinute(ipAddress, currentTime, totalTime)
def fannerFiveMinute(ipAddress, currentTime, totalTime)

def fannerCalculation()
{
    # Initial time prior to loop
    current_time = time.time()
    time_stamp = 0 
    scanner_detection_list = []

    # Loop Through Table adding entries
    for i in range(HASH_TABLE_SIZE): # Range = 262144
        
        # Check for first index divide by zero 
        if i != 0:
            # Determine when we move to next IPaddress 
            if PORT_MAX%i == 0: 
                fannerSecond(hashTable[i][IPADDRESS_SOURCE], currentTime, totalTime)
                fannerMinute(hashTable[i][IPADDRESS_SOURCE], currentTime, totalTime)
                fannerFiveMinute(hashTable[i][IPADDRESS_SOURCE], currentTime, totalTime)
                # Time for when we advance to next IPaddy
                current_time = time.time()
        
        time_stamp += hashTable[i][TIME_STAMP]
}
#****************************************************************************************************


# ----------------------------- Thread 3 : Table Time Out Functions ---------------------------------#

# ****************************************************************************************************
# Function : timerThread 
# Description : This function is the logic behind searching the hashtable and setting boolean value of
#               tuple for entries appropriatly based on timestamps greater than 5 minutes.
# Input:   
# Returns: Nothing yet
# Note: TODO Needs Testing!!
# ****************************************************************************************************
def timerThread():
    print("Inside Timer: {}".format(num))
    checkTimeOutTableEntry()


# ****************************************************************************************************
# Function : checkTimeOutTableEntry 
# Description : This function physically checks the table tuple entries timestamp value 
#               will zeroize entry greater than 5 minutes per instructions HW3
# Input:   Nothing
# Returns: Nothing 
# Note: TODO Needs Testing!!
# ****************************************************************************************************
def checkTimeOutTableEntry():
    
    # Loop through table, get current time ,get timestamp in table
    for i in range(HASH_TABLE_SIZE):
        current_time = time.time()
        entry_time = hashTable[i][TIME_STAMP]

        # If determine stale entry, which is table entry greater than five minutes
        # Zeroize entry back to state when it was populated at beginning of program
        if((current_time - entry_time) > OLD_ENTRY_TIME):
            
            # Tuples are immutable in python 
            temp = list(hashTable[i])
            temp[CURRENT_OR_STALE] = STALE_ENTRY
            temp[IPADDRESS_DESTINATION] = EMPTY_STRING
            temp[TIME_STAMP] = ZERO_TIME
 
            # Update table
            hashTable[i] = tuple(temp)




# ----------------------------------- Common Helper Functions ---------------------------------------#

# ****************************************************************************************************
# Function : mapkeyToIp 
# Description : This function maps the key value to an IPaddress
# Input:   1) Key value range 0 - 255
# Returns: 1) Full IPAddress 
# Note: Works, Logic verified, Example: Input = 108.168.10.1 , Returns 1
# ****************************************************************************************************
def mapkeyToIp(key):
    prefix = SUB_NET
    IPAddress = prefix + key
    return IPAddress


# ****************************************************************************************************
# Function : mapIpToKey 
# Description : This function maps the IPaddress to a key 
# Input:   1) IPaddress range 108.168.10.0 - 108.168.10.255
# Returns: 1) Key value
# Note: Works, Logic verified, Example: Input = 1 , Returns 108.168.10.1 , 
# ****************************************************************************************************
def mapIpToKey(IPAddress):
    postfix = IPAddress[11:]
    return postfix


# ****************************************************************************************************
# Function : mapToIndex 
# Description : This function maps the new table entry to the correct index in the hashtable
# Input:   1) IP address of source
#          2) Port number of destination
# Returns: 1) Index in hashtable
# Note: Works !!
# ****************************************************************************************************
def mapToIndex(ip_src, port_dest):

    index = int(mapIpToKey(ip_src))
    if index == 0:
        return port_dest

    if index == 1:
        return PORT_MATH + port_dest
    
    if index > 1:
        return (PORT_MATH * index) + port_dest




# ---------------------------------------- Main Function --------------------------------------------#

# ****************************************************************************************************
# Function : main
# Description : This function ...
# Input:   None
# Returns: Nothing
# **************************************************************************************************** 
def main():

    populateHashTable()     
    printHashTable()
    

# Program entry 
if __name__ == "__main__": 
    main()











