## Part 1: Analyze Your First Packet with Wireshark (Lab from Google Cybersecurity Certificate - Detection and Response Module)

### Activity Overview
As a security analyst, you’ll need to analyze network traffic in order to learn what type of traffic is being sent to and from systems on the networks you’ll be working with.

Previously, you learned about packet capture and analysis. Analyzing packets can help security teams interpret and understand network communications. Network protocol analyzers such as Wireshark, which has a graphical user interface or GUI, can help you examine packet data during your investigations. Since network packet data is complex, network protocol analyzers (packet sniffers) like Wireshark are designed to help you find patterns and filter the data in order to focus on the network traffic that is most relevant to your security investigations.

Now you’ll use Wireshark to inspect packet data and apply filters to sort through packet information efficiently.

### Scenario
In this scenario, you’re a security analyst investigating traffic to a website.

You’ll analyze a network packet capture file that contains traffic data related to a user connecting to an internet site. The ability to filter network traffic using packet sniffers to gather relevant information is an essential skill as a security analyst.

---

### Objectives
- Capture live network traffic.
- Apply filters to analyze specific packets.
- Examine key fields in network protocols (e.g., IPv4, TCP, UDP, ICMP).
- Identify potential security insights from packet data.

---

### Steps
1. **Setting Up Wireshark**
   - Install Wireshark on your system.
   - Configure network interfaces for packet capture.

2. **Capturing Traffic**
   - Start a packet capture session.
   - Generate network traffic (e.g., ping, browsing, file transfers).

3. **Applying Filters**
   - Use display filters (e.g., tcp, udp, icmp, ip.addr == X.X.X.X).
   - Analyze captured packets using protocol hierarchy statistics.

4. **Examining Packet Details**
   - Inspect Ethernet, IPv4, TCP/UDP headers.
   - Analyze fields like TTL, Flags, Source/Destination IP.
   - Identify handshake processes and anomalies.

### Wireshark Traffic Analysis Tasks

## Task 1: Explore data with Wireshark
In this task, you must open a network packet capture file that contains data captured from a system that made web requests to a site. You need to open this data with Wireshark to get an overview of how the data is presented in the application.

![setting up wireshark](https://i.imgur.com/9O6EDc1.png)

![Explore Wireshark](https://i.imgur.com/TWnHucB.jpeg)
**Question:** What is the protocol of the first packet in the list where the info column starts with the words 'Echo (ping) request'? 

- **Options:**
  - ICMP ✅
  - TCP
  - SSH
  - HTTP

---

## Task 2: Apply a Basic Wireshark Filter and Inspect a Packet

In this task, you’ll open a packet in Wireshark for more detailed exploration and filter the data to inspect the network layers and protocols contained in the packet.

Enter the following filter for traffic associated with a specific IP address. Enter this into the Apply a display filter... text box immediately above the list of packets:

ip.addr == 142.250.1.139

Press ENTER or click the Apply display filter icon in the filter text box.
The list of packets displayed is now significantly reduced and contains only packets where either the source or the destination IP address matches the address you entered. Now only two packet colors are used: light pink for ICMP protocol packets and light green for TCP (and HTTP, which is a subset of TCP) packets.

Double-click the first packet that lists TCP as the protocol.
This opens a packet details pane window:

![setting up wireshark](https://i.imgur.com/isFPncm.jpeg)

**Question:** What is the TCP destination port of this TCP packet? 

- **Options:**
  - 53
  - 80 ✅
  - 200
  - 66

---

## Task 3: Use Filters to Select Packets
In this task, you’ll use filters to analyze specific network packets based on where the packets came from or where they were sent to. You’ll explore how to select packets using either their physical Ethernet Media Access Control (MAC) address or their Internet Protocol (IP) address.


Enter the following filter to select traffic to or from a specific Ethernet MAC address. This filters traffic related to one MAC address, regardless of the other protocols involved:

eth.addr == 42:01:ac:15:e0:02

![Explore Wireshark](https://i.imgur.com/0VKEq7N.png)
![Explore Wireshark](https://i.imgur.com/7HxnPjt.jpeg)

**Question:** What is the protocol contained in the Internet Protocol Version 4 subtree from the first packet related to MAC address 42:01:ac:15:e0:02? 

- **Options:**
  - UDP
  - ICMP 
  - ESP
  - TCP✅

---

## Task 4: Use Filters to Explore DNS Packets
In this task, you’ll use filters to select and examine DNS traffic. Once you‘ve selected sample DNS traffic, you’ll drill down into the protocol to examine how the DNS packet data contains both queries (names of internet sites that are being looked up) and answers (IP addresses that are being sent back by a DNS server when a name is successfully resolved).
**Question:** Which of these IP addresses is displayed in the expanded Answers section for the DNS query for "opensource.google.com"? 

- **Options:**
  - 142.250.1.139 ✅
  - 169.254.169.254
  - 139.1.250.142
  - 172.21.224.1

---

## Task 5: Use Filters to Explore TCP Packets
In this task, you’ll use additional filters to select and examine TCP packets. You’ll learn how to search for text that is present in payload data contained inside network packets. This will locate packets based on something such as a name or some other text that is of interest to you.
**Question:** What is the Time to Live value of the packet as specified in the Internet Protocol Version 4 subtree? 

- **Options:**
  - 128 ✅
  - 64
  - 16
  - 32

---

**Question:** What is the Frame Length of the packet as specified in the Frame subtree? 

- **Options:**
  - 40 bytes
  - 54 bytes
  - 74 bytes ✅
  - 60 bytes

---

**Question:** What is the Header Length of the packet as specified in the Internet Protocol Version 4 subtree? 

- **Options:**
  - 20 bytes ✅
  - 54 bytes
  - 74 bytes
  - 60 bytes

---

**Question:** What is the Destination Address as specified in the Internet Protocol Version 4 subtree? 

- **Options:**
  - 169.254.169.254
  - 239.1.250.142
  - 172.21.224.2
  - 142.250.1.139 ✅
Here's a conclusion for your **"Analyze Your First Packet with Wireshark"** lab project:  

---

### **Conclusion**  
In this lab, I successfully analyzed network packet data using Wireshark, gaining hands-on experience in inspecting traffic, applying filters, and interpreting network protocols.  

Through structured tasks, I:  
- Explored raw packet data and identified key network traffic properties such as source/destination IPs, protocols, and packet length.  
- Applied filters to focus on specific IP addresses, MAC addresses, and protocols, enabling efficient data inspection.  
- Examined **ICMP traffic**, identifying an Echo (ping) request.  
- Investigated **TCP connections**, analyzing the destination port and TCP flags.  
- Used **MAC address-based filtering** to isolate packets and determine the protocol type (UDP).  
- Filtered and examined **DNS traffic**, identifying domain name queries and their resolved IP addresses.  

This lab reinforced my ability to use Wireshark effectively for security investigations, enhancing my understanding of packet structure, filtering techniques, and network communication patterns. These skills are essential for traffic analysis, threat detection, and incident response as a SOC analyst.  

---


