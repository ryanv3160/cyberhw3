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


SUB_NET = "192.168.10."
FAN_OUT_SEC = 5
FAN_OUT_MIN = 100
FAN_OUT_FIVEMIN = 300

table = []
srcIP1 = "192108101"
dstIP1 = "192108102"
dstPort1 = "10"
entry1 = (srcIP1,dstIP1,dstPort1)
    
srcIP2 = "192108103"
dstIP2 = "192108104"
dstPort2 = "11"
entry2 = (srcIP2,dstIP2,dstPort2)

table.append(entry1)
table.append(entry2)

x = 1569639485.272715
dicts = {}


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
    print("We have joined : Sniffer Thread and Fan Out Thread.")
    print("Program exit.")


#******************* Thread 1 : Sniff Traffic  Functions *******************#
def snifferThread(num): 
    print("Inside Sniffer: {}".format(num)) 

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

    # Check if entry exists in table 
    for tup in first_contact_list:
        if ((tup[0] == entry[0]) and (tup[1] == entry[1]) and (tup[2] == entry[2])):
            found = True
            return found
    return found 

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
    if dicts[index][0] == 0:
        return 

    # Get difference in time current minus table entry
    time_difference = time.time() - dicts[index][4]

    # If difference is greater or equal to 5 minutes
    # Zero out the entry 
    if time_difference >= 300.0:
        dicts[index][0] = 0
        dicts[index][2] = ""
        dicts[index][3] = ""
        dicts[index][4] = 0





# Main function 
def main():

    keys = range(256)
    for i in keys:
        dicts[i] = (0,mapkeyToIp(str(i)),"Empty","Empty",0) 
    print(dicts)
    print(dicts[1])
    

# Program entry 
if __name__ == "__main__": 
    main()











