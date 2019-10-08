# Cybersecurity Homework 3
## Port Scanner Detector
### Ryan Vacca, Matthew Moltzau, Julia Vrooman

## Lan setup

Lan is set up using a virtual ethernet (vnet0) within the host machine. There are 2 Kali Linux machines running on VMWare on the host machine. Each Kali Linux instance is set to connect to the network through the virtual network established by the host. The network IP is 192.168.10.0\24. Therefore, the Kali Linux machines will be assigned IP addresses between 192.168.10.1 and 192.168.10.254, as .0 is reserved for the network and .255 is reserved for broadcast.

## Code description
### PortScanner.py

PortScanner.py reads in the target machine's IP address, followed by an integer value which represents the wait time between scans. Then, a TCP socket connection is created between the machine running PortScanner.py and the target machine's IP address and socket 0 to begin with. If the current port on the target's machine is open for TCP connections, the PortScanner's tcpScanner function returns true and then closes the established TCP socket connection. If no connection is established, it returns false. Upon return of a boolean, either the found responsive port is printed to the host machine's console or nothing is, and then the port number is increased after the wait time has elapsed to try the next port number on the target machine. Every time an open port is found, that port's number is printed to the screen of the host machine. This continues to iterate through all port numbers from 0 to 1023 until the POrtScanner.py program is exited with Ctrl^C.

### Detector (detector.py, main.py, psocket.py, sniffer.py)

The scanner detector is initiated by running main.py with python3. This file creates a queues in which to hold incoming connection requests and the channels of these requests, as well as a table in which to hold this data. The main.py file initiates the detector and creates separate threads to sniff the data, dissect what comes in, and perform calculations to detect a port scanner. As data comes in and is added to the table, the main.py function displays to the console what the change in the table's size has been since its last addition and updates the user as to the total number of entries in the table.

The sniffer.py file sniffs the data coming in and places it on the data queue to be processed by the dissector. It also passes the channel through which this data was received through to the detector. This is necessary so that incoming packets do not get lost while the sniffer attempts to process and decide if past packets need to be added to the table. The queue allows the data to be processed without causing a bottleneck or collisions as simply adding data to the queue does not block the data stream of the thread. This also prevents waiting for database access, as the queue will sort data into an easily manageable FIFO structure.

The detector.py file actually interprets the table to determine if port scanning is occuring. It considers the information added to the table within the last 5 minutes to determine whether a certain IP address has made too many requests to connect to the machine running the detector. If more than 5 requests are attempted per second, more than 100 requests are made on average per minute, or more than 300 requests have been made total, the IP address making these requests is reported to the screen as a port scanner. This is calculated by tracking the count of connections stored in the table over the last 5 minutes only. If an entry has been in the table for 5 minutes, it is removed.

This means that a port scanner making many requests but over the course of an amount of time that doesn't create an average of 100 per minute, or about every 17ms, the scanner will not be detected until 300 requests have been made. So, if the scanner attempts to connect every second, it will not cause the average/second to reach > 5, nor will it cause the average/minute to reach > 100, so it must then hit the requirement that 300 requests are made within the 5 minutes before data starts to be removed from the table, which would prevent the 300 threshhold to ever be reached. Because of this, the maximum time interval that can be detected by this detector is 1 second, because 5 minutes * 60 seconds = 300 seconds, and 300 requests must have been made in those 300 seconds in order to trigger a detection, or 1 request per second.

## Results
`insert screenshots of updated results`

### Discussion of results

At a scan interval of 1/1ms, the scanner detector detected the source IP as `192.168.10.131`, found an average fan-out per second to be `1.5667`, an average fan-out per minute to be `94.0` and an average fan-out per five minutes to be `470.0`. This follows the above paragraph, where it is claimed that an interval of < `16ms` will trigger a detection of a port scanner.


