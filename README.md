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

**Question:** What is the protocol of the first packet in the list where the info column starts with the words 'Echo (ping) request'? 

- **Options:**
  - ICMP ✅
  - TCP
  - SSH
  - HTTP

---

## Task 2: Apply a Basic Wireshark Filter and Inspect a Packet

**Question:** What is the TCP destination port of this TCP packet? 

- **Options:**
  - 53
  - 80 ✅
  - 200
  - 66

---

## Task 3: Use Filters to Select Packets

**Question:** What is the protocol contained in the Internet Protocol Version 4 subtree from the first packet related to MAC address 42:01:ac:15:e0:02? 

- **Options:**
  - UDP
  - ICMP ✅
  - ESP
  - TCP

---

## Task 4: Use Filters to Explore DNS Packets

**Question:** Which of these IP addresses is displayed in the expanded Answers section for the DNS query for "opensource.google.com"? 

- **Options:**
  - 142.250.1.139 ✅
  - 169.254.169.254
  - 139.1.250.142
  - 172.21.224.1

---

## Task 5: Use Filters to Explore TCP Packets

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


