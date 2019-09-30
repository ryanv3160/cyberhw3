# ****************************************************************************************************
# Name: Ryan Vacca
#       Matthew Moltzaou
#       Julia Vrooman
#
# Date: 10/08/2019
#
# Assignment: HW3
#
# Program Description: 
#
# Program Status: 
#
# ****************************************************************************************************

# Import libraries used in program
import socket
import re
import time
import sys


# ****************************************************************************************************
# Function : tcp_scanner
#
# Description : This function serves to attempt to connect to the target IP4 address's associated
# port number that is passed in.
#
# Input:   1) Port number
#
# Returns: 1) True: if tcp_sock can detect port index belonging to target IP4 Address
#          2) False: if tcp_sock can NOT detect port index belonging to target IP4 Address
#
# ****************************************************************************************************
def tcpScanner(port, target):
    try:
        # Connect to port
        tcp_sock.connect((target, port))
        # Close port
        tcp_sock.close()
        return True
    except:
        return False


# ****************************************************************************************************
# Function : recv_sig() ** Used logic from canvas example, Student: Kuntal Das 
#
# Description : Function to recieve reply from attempt UDP scan of port
#
# Input:   None
#
# Returns: 1) True: if data is recieved
#          2) False: if data is empty
#
# ****************************************************************************************************
def recvSig():
    while True:
        data, addr = udp_sock.recvfrom(4096)
        if data:
            return True
        else:
            return False


# ****************************************************************************************************
# Function : udp_scanner
#
# Description : This function serves to attempt to connect to the target IP4 address's associated
# port number that is passed in.
#
# Input:   1) Port number
#          2) Target IP address
#
# Returns: 1) True: if udp_sock can detect port index belonging to target IP4 Address
#          2) False: if udp_sock can NOT detect port index belonging to target IP4 Address
#
# ****************************************************************************************************
def udpScanner(port, target):
    try:
        # Create test message string and convert to byte
        message = "TEST"
        byteArr = bytes(message, 'utf-8')

        # Connect to target IP address and port number
        udp_sock.connect((target, port))
        # Set delay
        udp_sock.settimeout(1)

        # Send messaage to target IP and current port enumeration
        udp_sock.sendto(byteArr, (target, port))
        # Call function to recieve reply and close socket
        recvSig()
        udp_sock.close()

    # Dummy catch for exception raised
    except:
        return False




# ****************************************************************************************************
# Function : errorCheckInput
#
# Description : This function is designed to error check the user input by using pythons regular
# expression library. If valid input in format "xxxx.xxxx.xxxx.xxxx" then returns True to main
# if valid input or False if in-valid input
#
# Input is checked using a reqular expression that matches how format should be written.
# Checked for "Length" + "3 dots" + "only numbers 1-9 octet 1" + "only numbers 0-9 octet 2-3" +
# "first octet cannot be zero" + "other three octets can be zero".
# This is accomplished by a regular expression that took a long time to
# piece together.
#
# Input:   1)User entered string off IP4 address
#
# Returns: 1) True, if valid input
#          2) False, if in-valid input
#
# ****************************************************************************************************
def errorCheckInput(IP4Address):
    # Use python built in regular expression to check user input for malicous / careless input
    valid_input = re.match(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
        IP4Address)

    # Return true if valid input
    if valid_input:
        return True

    # Return false if invalid input
    else:
        return False


# ****************************************************************************************************
# Function : nextIpAddress 
#
# Description : Function to advance old IP address that has just had all ports scanned. We 
#               are ready for the next one. Logic icreases IPaddress by 1 until max "192.168.10.255"
#               then returns to "192.168.10.0" and contiues this cycle. 
#
# Input:   1) Old IPAddress to advance
#          2) Current index of "192.168.0.0"
#
# Returns: 1) True: if data is recieved
#          2) False: if data is empty
#
# Note: "192.168.10.0" --> "192.168.10.255" --> "192.168.10.0" ...Repeat ...
# ****************************************************************************************************
def nextIpAddress(IP4Address, IPIndex): 
    if IP4Address == "192.168.10.255":
        IP4Address = "192.168.10.0"
        IPIndex = 0
        return IP4Address, IPIndex
    else:
        IPIndex +=1
        IP4Address = "192.168.10." + str(IPIndex)
        return IP4Address, IPIndex


# ****************************************************************************************************
# Function : main
#
# Description : This function serves as the program entry point. The function begins by asking the
# user for input of an IP4 address. Then a while loop is used to loop until user enters valid input.
#
# Input:   1) IpAddress of this machine 
#          2) Wait time in milliseconds 
#
# Returns: Nothing
#
# ****************************************************************************************************
def main():

    # Boolean for enable or disable UDP port scanner 
    enable_UDP = True

    # Error check command line Args
    # If missing command line arguments, Display message to user, exit program
    if(len(sys.argv) < 3):
        print("Missing command line arguments!")
        print("Argument 1) = IpAddress of this machine.")
        print("Argument 2) = Wait time in milliseconds between scans.")
        print("Exiting Program Now !!!")
        sys.exit()

    # Error check user entered IP4 address from command line 
    # If in-valid IP format disable UDP scanner
    if errorCheckInput(sys.argv[1]) == False:
        print("Not valid IPAddress from command line argument")
        print("UDP port scanning is disabled for this scanner")
        print("Continue Program Execution..")
        enable_UDP = False

    # Else valid IP address format form command line
    else:
        # Now attempt to bind to address
        try:
            # First argument IP4, Then UDP
            # Set up UDP socket with type SOCK_DGRAM for connectionless protocol and domain AF_NET constant
            # for transport mechanism.
            # Need to set up UDP socket on our end for reply
            udp_rec=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Use random port on this machine
            srcport=5005
            # Bind to IP address on this machine
            udp_rec.bind(("192.168.0.33", srcport))

        # Catch exception if IP address of this machine cannot be binded to and disable UDP scanner
        except:
            enable_UDP = False
            print("Command line argument for this machine IPaddress is invalid")
            print("UDP port scanning is disabled for this scanner ***")
            print("Continue Program Execution..")

    # First argument IP4, Then TCP
    # Set up TCP socket with type SOCK_STREAM for connection oriented protocols and domain AF_NET constant
    # for transport mechanism.
    tcp_sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # First argument IP4, Then UDP
    # Set up UDP socket with type SOCK_DGRAM for connectionless protocol and domain AF_NET constant
    # for transport mechanism.
    udp_sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Only scanning on this LAN, start with port zero, default scan of 1 millisecond
    target = "192.168.10.0"
    ip_index = 0
    scan_wait = 1

    # Error checking for if wait time command line argument cannot be converted to float
    try:
        # Get command line argument for wait time between scans 
        scan_wait = float(sys.argv[2])

    # Catch exception if cannot convert to float
    except ValueError:
        print("Invalid command line argument for wait time")
        print("Keeping default scan time of 1 milliseconds ***")
        

    # Loop through all ports "TCP & UDP" of current IPaddress. 
    # Then Increase IP address by xxx.xxx.xxx.xx1 and repeat cycle until 192.168.10.255
    # Then Repeat by setting IP address back to 192.168.10.0 and repeat until ctrl-c entered
    while True:

        #************************** TCP *****************************
        # Loop through range of port numbers from 1 - 1023
        for portNumber in range(0, 1023):

            # Call TCP scanner function to determine if port is open
            if tcpScanner(portNumber, target):
                print("[*]Port", portNumber, "/tcp", "is open")

            # Set delay for one second
            time.sleep(scan_wait/1000)


        # ** TODO : Need to figure workaround for udp scan having to wait 2 seconds for replies
        # ** Answer could be using method in discussion on canvas kellen mendenhall implemented
        # ** NEED TO TEST ***
        #************************** UDP *****************************
        # Only enter UDP port scanner if enabled
        if enable_UDP == True:        
            
            # Loop through range of port numbers from 1 - 1023
            for portNumber in range(0, 1023):

                # Get time prior to sending message
                start_time = time.time()

                # Call UDP scanner function to determine if port is open
                udpScanner(portNumber, target)

                # Set delay for one second
                time.sleep(1)

                # Get time after sending message
                end_time = time.time()

                # Check if time difference is greater than 2 seconds then port is open else closed
                if end_time - start_time > 2:
                    print("[*]Port", portNumber, "/udp", "is open")

                # Set delay for one second
                time.sleep(1/scan_wait*1000)

        # Now we have scanned all ports on this IPaddress now advance to next IPaddress
        target, ip_index = nextIpAddress(target, ip_index)
        print(target)

# Main for entry
if __name__ == "__main__": main()