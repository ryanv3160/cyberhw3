#!/usr/bin/env python3

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
    # First argument IP4, Then TCP
    # Set up TCP socket with type SOCK_STREAM for connection oriented protocols and domain AF_NET constant
    # for transport mechanism.
    tcp_sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        tcp_sock.connect((target, port))
        tcp_sock.close()
        return True
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
        
    return True if valid_input else False


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
    
    # Error check command line Args
    # If missing command line arguments, display message to user and exit
    if(len(sys.argv) < 3):
        print("Missing command line arguments!")
        print("Argument 1) = Target IP address.")
        print("Argument 2) = Wait time in milliseconds between scans.")
        print("Exiting Program Now !!!")
        sys.exit()
    
    # Error check user entered IP4 address from command line 
    # If invalid IP format, display message to user and exit
    if errorCheckInput(sys.argv[1]) == False:
        print("Invalid IP address from first argument")
        print("Exiting Program Now !!!")
        sys.exit()
    
    # Only scanning on this LAN, start with port zero, default scan of 1 millisecond
    target = sys.argv[1]
    scan_wait = 1
    
    # Error checking for if wait time command line argument cannot be converted to float
    try:
        # Get command line argument for wait time between scans 
        scan_wait = float(sys.argv[2])
    
    # Catch exception if cannot convert to float
    except ValueError:
        print("Invalid command line argument for wait time")
        print("Keeping default scan time of 1 milliseconds ***")
    
    #************************** TCP *****************************
    # Loop through range of port numbers from 1 - 1023
    for portNumber in range(0, 1024):
        
        # Call TCP scanner function to determine if port is open
        if tcpScanner(portNumber, target):
            print("[*] Port", portNumber, "/tcp", "is open")
        
        time.sleep(scan_wait/1000)

# Entrypoint
if __name__ == "__main__":
    main()

