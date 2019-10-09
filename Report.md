# Cybersecurity Homework 3
## Port Scanner Detector
### Ryan Vacca, Matthew Moltzau, Julia Vrooman

## Lan setup

Lan is set up using a virtual ethernet (vnet0) within the host machine. There are 2 Kali Linux machines running on VMware on the host machine. Each Kali Linux instance is set to connect to the network through the virtual network established by the host. The network IP is 192.168.10.0/24. Therefore, the Kali Linux machines will be assigned IP addresses between 192.168.10.1 and 192.168.10.254, as .0 is reserved for the network and .255 is reserved for broadcast.

## Code description
### PortScanner.py

PortScanner.py reads in the target machine's IP address, followed by an integer value which represents the wait time between scans. Then, a TCP socket connection is created between the machine running PortScanner.py and the target machine's IP address. If the current port on the target's machine is open for TCP connections, the PortScanner's tcpScanner function returns true and then closes the established TCP socket connection. If no connection is established, it returns false. Upon return of a boolean, either the found responsive port is printed to the host machine's console or nothing is, and then the port number is increased after the wait time has elapsed to try the next port number on the target machine. Every time an open port is found, that port's number is printed to the screen of the host machine. This continues to iterate through all port numbers from 0 to 1023 until all ports are exhausted.

### Port Scanner Detector (detector.py, main.py, psocket.py, sniffer.py)

The port scanner detector is initialized by running `./detector/main.py`. The main file has a succient view of all the threads and access patterns of the shared data between them. The primary tasks performed by the threads involve 1) sniffing data over the network 2) dissecting intercepted packets in order to give them semantic meaning 3) using the collected data to make decisions in filtering out non-malicous traffic and 4) reporting the results to the user with helpful statistics. Between threads there is a FIFO queue from the sniffer to the dissector, and a channel where the current record of entries is stored. As data comes in and is added to the table, the main.py function displays the change in the table's size since its last addition in order to update the user as to the total number of entries in the table.

The sniffer thread has the least code. After a packet is received, no time is spent dissecting the packet at that moment. This is necessary so that incoming packets do not get lost while the sniffer attempts to process and decide if past packets need to be added to the table. The setup of this queue makes the data access simpler since the sniffer thread only ever needs to send data. In the original implementation, sniffing and dissecting was done in a single thread and the thread was waiting to recieve both new packets and the table in order to insert new elements. After reworking the code this way, we went from only 400 packets being recieved to all 1024 that we scanned for. Even with this improved number however, we found that if the OS was running slowly it was still possible for packets to be dropped. In early tests, we were able to spin up multiple sniffer threads and scale the design, which is really cool since they can all use the same queue to send data.

Once the dissector is able to process a packet from the queue, it is able to filter out non-TCP packets and non-SYN packets. We only record TCP SYN packet requests since the SYN packet is used for the first contact request and the port scanner is only making first-contact requests. The dissector adds the remaining data to the table, which is a mapping from the source ip and destination port to the timestamp at which it was recorded.

Now with data to inspect, the detector.py file actually does the interpretation of the collected requests in order to determine if a port scanner is being run in the network. It considers the information added to the table within the last 5 minutes to determine whether a certain IP address has made too many requests to connect to the machine running the detector. If more than 5 requests are attempted per second, more than 100 requests are made on average per minute, or more than 300 requests have been made total, the IP address making these requests is reported as a port scanner. This is calculated by tracking the count of connections stored in the table over the last 5 minutes only. If an entry has been in the table for 5 minutes, it is removed.

This means that a port scanner making many requests will not be detected even if over an amount of time that doesn't create an average of 100 per minute, or about every 17ms, the scanner will not be detected until 300 requests have been made. So, if the scanner attempts to connect every second, it will not cause the average/second to reach > 5, nor will it cause the average/minute to reach > 100, so it must then hit the requirement that 300 requests are made within the 5 minutes before data starts to be removed from the table, which would prevent the 300 threshhold to ever be reached. Because of this, the maximum time interval that can be detected by this detector is 1 second, because 5 minutes * 60 seconds = 300 seconds, and 300 requests must have been made in those 300 seconds in order to trigger a detection, or 1 request per second.

## Results

### Important Assumption

The metrics used for the port scanner detector are comprised of 1) avg fanout per second 2) avg fanout per minute and 3) avg fanout per 5 minutes (ie. the total count). There was some confusion on whether or not these metrics were supposed to be used for detection, or if we were supposed to use the non-averaged fanouts for detection, then print the averages. Upon further inspection it appears this is the case, so a [branch](https://github.com/moltzaum/port-scanner-detector/commit/d05b0eebffb8a6dfd304d1c715a4915a70f143d0) with necessary changes have been created.

Because the discussion of results was complete before this change was made, we ask that you accept this assumption "as-is". The assignment description even states: "You can make your own assumptions if you think any required information is missing from the description".

### Discussion of results

![Detector at 1ms](https://drive.google.com/uc?id=1_vk2__C7SLb6BFV3o6-JfJhuNrGKG0mj)

At a scan interval of 1 scan per 1ms, the scanner detector detected the source IP as `192.168.10.133`, found an average fan-out per second to be `1.126667`, an average fan-out per minute to be `67.6` and an average fan-out per five minutes to be `338`. This follows the above paragraph, where it is claimed that an interval of < 17ms will trigger a detection of a port scanner at the 1 second threshold. However, we reach detection for a different reason due to the fact that only 1024 ports were scanned. Though the port scanner continually attempts to reach the ports in a loop, it fails by scanning over 300 ports before sufficient time has elapsed to calculate the average per second or per minute. 


![Detector at 500ms](https://drive.google.com/uc?id=1HvSISzPg9VhswjjPdI9GpgNXxEMA7CqW)

At a scan interval of 1 scan per 500ms, the scanner detector detected the source IP as `192.168.10.133`, found an average fan-out per second to be `1.023334`, an average fan-out per minute to be `61.4` and an average fan-out per five minutes to be `307`. This follows the above paragraph, where it is claimed that an interval of < 17ms will trigger a detection of a port scanner at the 1 second threshold. However, we reach detection for a different reason due to the fact that only 1024 ports were scanned. Though the port scanner continually attempts to reach the ports in a loop, it fails by scanning over 300 ports before sufficient time has elapsed to calculate the average per second or per minute. In this case, it scans 1024 ports in 61.4 seconds when the failure condition would be an average of 100 per minute. However, for the same reason as above, 300 total first connections are reached before the average per minute can be calculated. 

![Detector at 1000ms](https://drive.google.com/uc?id=15YabE3p2OR7uD_T_GdjdnGqz6HKMyvR9)

This also fails due to exceeding 300 attempted connections over a span of 5 minutes for similar reasons as listed above. There are 1024 ports being scanned, each at an interval of 1 second. There are a maximum 60 scans that can be completed in a minute, which is reflected by the fan-out per minute being 60.2. In five minutes, or 300 seconds, it is possible for 300 scans to be done on this interval. Therefore, anything with an interval greater than 1 second will fail to meet any of the scan conditions, regardless of how many ports are scanned. 

![Detector at 1010ms](https://drive.google.com/uc?id=1X362xfck5unOF-OY4Pf9TNprzB4fkF1F)

This was not a required output but is included to show the way the table of values will oscillate at just below 300 entries for a scan interval of just over 1 second. This is explained above.

![Detector at 5000ms](https://drive.google.com/uc?id=1U_0eN2ja82_S6RMb9aUID6C5FJJhh2KJ)

At a 5 second interval, there is a maximum of 60 entries added to the table within the 300 seconds allotted by the 5 minute saved state of an entry in the table. Because of this, there will never be a condition where the table consists of 300 entries in order to fail at the 5 minute interval, 5 seconds is already longer than the 1 second interval limit, and only 12 tests can possibly occur within the 1 minute interval, considerably less than the 100 required to fail for that time period.

![Detector at 10000ms](https://drive.google.com/uc?id=1cp8RSIEad29BnyjnSImKbs7EDy4PaLFt)

This is not detected for the reasons listed above, as any interval over 1000ms will not be detected by the port scanner detector.


