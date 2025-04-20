# Day 2 - Questions (Q91–Q180)
```
🟦 Domain 1.0 – Networking Concepts (23 Questions)

1. Which layer of the OSI model is responsible for flow control and error correction?
A. Data Link
B. Transport
C. Network
D. Session

2. Which of the following is a connectionless protocol?
A. TCP
B. FTP
C. UDP
D. HTTPS

3. What does TTL stand for in an IP packet?
A. Time Tracking Level
B. Transmission Tag Length
C. Time To Live
D. Transport Total Length

4. A switch forwards traffic based on which address?
A. IP Address
B. MAC Address
C. Port Address
D. Gateway Address

5. Which addressing type is used in one-to-many communication like streaming?
A. Broadcast
B. Anycast
C. Multicast
D. Unicast

6. Which protocol uses port 443?
A. FTP
B. Telnet
C. HTTP
D. HTTPS

7. Which layer is responsible for logical addressing?
A. Data Link
B. Physical
C. Network
D. Application

8. What protocol is used for email delivery?
A. POP3
B. SMTP
C. SNMP
D. HTTP

9. What is the purpose of ARP?
A. Resolves IP to MAC address
B. Resolves MAC to IP address
C. Provides encryption
D. Determines network route

10. Which of the following is a hybrid topology?
A. Ring
B. Star
C. Mesh
D. Tree

11. What type of IP address is 192.168.10.1?
A. Public
B. Multicast
C. Private
D. Loopback

12. Which type of routing uses manually configured paths?
A. Dynamic
B. Static
C. OSPF
D. RIP

13. Which protocol handles name resolution?
A. SNMP
B. DHCP
C. DNS
D. HTTP

14. Which of the following is a Layer 1 device?
A. Router
B. Switch
C. Hub
D. Firewall

15. What does ICMP do?
A. Encrypt traffic
B. Resolve hostnames
C. Report delivery issues
D. Assign IPs

16. Which of the following is a Layer 6 protocol?
A. HTTP
B. SSL
C. FTP
D. ICMP

17. What address does a switch learn and store in its CAM table?
A. IP address
B. Subnet
C. MAC address
D. Hostname

18. Which port is used by Secure Shell (SSH)?
A. 20
B. 21
C. 22
D. 23

19. What is used to segment a network logically without physical separation?
A. Switch
B. Hub
C. VLAN
D. NAT

20. What is a characteristic of UDP?
A. Reliable
B. Connection-oriented
C. Error-checked
D. Fast but unreliable

21. Which protocol is used for time synchronization?
A. SNMP
B. FTP
C. NTP
D. DNS

22. A packet arrives with a TTL of 1. What happens next?
A. Dropped
B. Sent again
C. Forwarded
D. NAT is applied

23. What topology uses a central hub to connect devices?
A. Ring
B. Bus
C. Star
D. Mesh

🟩 Domain 2.0 – Network Implementation (20 Questions)

24. What VLAN is used for voice traffic by default?
A. VLAN 10
B. Native VLAN
C. VLAN 100
D. VLAN 20

25. Which device connects two different networks together?
A. Switch
B. Hub
C. Router
D. Access Point

26. What is the function of 802.1Q?
A. Wireless encryption
B. VLAN tagging
C. Spanning tree
D. DHCP relay

27. What routing protocol uses hop count as a metric?
A. OSPF
B. BGP
C. EIGRP
D. RIP

28. Which cable is best for a 10Gbps network up to 100 meters?
A. Cat5e
B. Cat6a
C. Cat3
D. Coax

29. Which standard is used for PoE?
A. 802.3af
B. 802.1Q
C. 802.11ac
D. 802.3u

30. What is the purpose of a wireless controller?
A. Increases signal
B. Centralized management
C. Extends wired network
D. Hosts DHCP

31. What connector is used with fiber optic cables?
A. RJ45
B. LC
C. BNC
D. DB9

32. Which antenna type sends signal in all directions?
A. Directional
B. Yagi
C. Omnidirectional
D. Patch

33. Which is a benefit of link aggregation?
A. Lower cost
B. Redundancy and bandwidth
C. DHCP allocation
D. VLAN assignment

34. What is the purpose of spanning tree protocol?
A. Block IP spoofing
B. Prevent loops
C. Assign IPs
D. Encrypt traffic

35. What wireless frequency band has more non-overlapping channels?
A. 2.4 GHz
B. 3.6 GHz
C. 5 GHz
D. 6 GHz

36. What is the maximum length for a Cat6 Ethernet cable?
A. 50m
B. 100m
C. 150m
D. 200m

37. Which of these is a type of wireless network architecture?
A. Leaf-spine
B. Three-tier
C. Infrastructure
D. VLAN

38. A user cannot connect to a new VLAN. What should be checked first?
A. Patch panel
B. Firewall
C. Trunk port configuration
D. NAT rule

39. What type of cable should be used for backbone connections?
A. Coax
B. Multimode fiber
C. Cat5
D. Twinax

40. What kind of port carries multiple VLANs?
A. Access
B. Mirror
C. Trunk
D. Tagged

41. What is a BSSID in wireless networks?
A. Network name
B. Unique AP MAC
C. Client ID
D. SSID Alias

42. Which protocol is used to securely manage switches and routers?
A. HTTP
B. Telnet
C. SSH
D. SNMPv1

43. Which address translation method maps many internal to one external IP?
A. NAT
B. PAT
C. CIDR
D. VLSM

🟨 Domain 3.0 – Network Operations (19 Questions)

44. What is the purpose of configuration management?
A. Assign IP addresses
B. Monitor VLAN usage
C. Maintain system settings and backups
D. Control user access

45. Which document defines how quickly a service must be restored?
A. SLA
B. NDA
C. RPO
D. EULA

46. What log contains information about system crashes and restarts?
A. Security log
B. Application log
C. System log
D. Audit log

47. What protocol is used for monitoring network devices?
A. SNMP
B. FTP
C. SMTP
D. RDP

48. What tool is used to gather wireless signal strength in a location?
A. Syslog
B. Heat map
C. TDR
D. Traceroute

49. Which version of SNMP adds encryption?
A. v1
B. v2c
C. v3
D. None

50. What type of address assignment uses DHCP reservations?
A. Static
B. Automatic
C. Dynamic
D. Manual

51. What is a cold site in disaster recovery?
A. Fully operational site
B. Backup data-only site
C. Site with power and networking but no hardware
D. Site with real-time sync

52. What is MTTR?
A. Maximum Total Time Recovery
B. Measured Tunneling Time Recovery
C. Mean Time To Repair
D. Metric Time Table Rate

53. What is a reason for using a jump box?
A. Increase bandwidth
B. Filter broadcast traffic
C. Secure remote administration
D. Troubleshoot DHCP

54. What is IPAM used for?
A. Monitoring VLANs
B. IP address management
C. VPN authentication
D. Encrypting DNS

55. Which of the following helps identify end-of-life equipment?
A. Uptime report
B. Configuration file
C. Asset inventory
D. Heat map

56. What is port mirroring used for?
A. VLAN trunking
B. Logging login attempts
C. Forwarding traffic to a monitoring port
D. Controlling switch access

57. Which of the following stores event logs for correlation?
A. DNS
B. SIEM
C. DHCP
D. AAA

58. What does SLAAC do in IPv6?
A. Provides MAC-to-IP resolution
B. Assigns addresses via a server
C. Allows a device to self-configure
D. Encrypts data

59. What type of test validates a disaster recovery plan in real-time?
A. Tabletop
B. Drill
C. Simulation
D. Validation

60. What is the purpose of syslog?
A. Backup switch configs
B. Aggregate network logs
C. DNS lookup
D. Time sync

61. Which protocol is commonly used to relay DHCP requests?
A. NAT
B. DNS
C. IP Helper
D. ARP

62. What is a recursive DNS query?
A. A DNS query loop
B. DNS asking for repeated records
C. A client expects full resolution
D. DNS returns a loopback IP
🟥 Domain 4.0 – Network Security (14 Questions)

63. What security model focuses on least privilege?
A. Role-based
B. Mandatory access control
C. Discretionary access control
D. All of the above

64. What is the function of an ACL on a router?
A. Routing loop prevention
B. Traffic encryption
C. Filtering packets based on rules
D. VLAN tagging

65. Which protocol secures web traffic?
A. HTTP
B. Telnet
C. HTTPS
D. FTP

66. What is a honeypot?
A. Tool for hashing
B. Decoy system to trap attackers
C. Secure database
D. File backup server

67. What type of malware tricks users into installing it?
A. Worm
B. Ransomware
C. Trojan
D. Rootkit

68. What attack type floods a system to make it unavailable?
A. ARP spoofing
B. DoS
C. DNS poisoning
D. VLAN hopping

69. Which physical security control restricts physical access?
A. Firewall
B. IDS
C. Badge reader
D. Antivirus

70. What authentication protocol uses tickets?
A. Kerberos
B. RADIUS
C. TACACS+
D. LDAP

71. What does 802.1X provide?
A. Time sync
B. Port-based authentication
C. VLAN trunking
D. File transfer

72. Which zone typically separates public and private networks?
A. Guest
B. Untrusted
C. Screened subnet (DMZ)
D. Secure edge

73. What is the main goal of network segmentation?
A. Easier subnetting
B. Reduce cabling
C. Improve performance and isolate threats
D. Use fewer IPs

74. What is social engineering?
A. Firewall misconfiguration
B. Layer 7 attack
C. Manipulating people to gain information
D. Malware targeting IoT

75. What is geofencing in cybersecurity?
A. IP blocking
B. Wireless range limitation
C. Restricting access based on location
D. Physical fencing

76. What protocol uses digital certificates for identity?
A. SNMP
B. SSL/TLS
C. FTP
D. Telnet
🟪 Domain 5.0 – Network Troubleshooting (14%) (Q77–Q90)

77. What causes a "destination host unreachable" ping message?
A. Incorrect VLAN
B. No route to host
C. DNS timeout
D. Network loop

78. What tool helps identify duplicate IP issues?
A. ping
B. nmap
C. arp
D. ifconfig

79. What does a cable tester check?
A. DNS resolution
B. Gateway configuration
C. Pinouts and continuity
D. Subnet mask

80. What issue occurs with an incorrect duplex setting?
A. Full connectivity
B. High speed
C. Collisions and slow performance
D. DHCP failure

81. Which command helps validate DNS issues?
A. ping
B. traceroute
C. nslookup
D. netstat

82. A user has no IP address. What should you check first?
A. DNS
B. Cable connection
C. MTU
D. VLAN assignment

83. Which of the following causes excessive jitter in VoIP?
A. Low bandwidth
B. High encryption
C. Misconfigured VLAN
D. STP misalignment

84. You replaced a network card but still have no access. What's next?
A. Reset MAC address
B. Reboot router
C. Reassign IP and gateway
D. Replace cable

85. What does a "request timed out" message in ping mean?
A. Port unreachable
B. No internet
C. No ICMP reply
D. DHCP error

86. What does LLDP do?
A. Encrypt traffic
B. Monitor DNS
C. Discover neighboring devices
D. Filter IPs

87. Which tool shows port utilization on a switch?
A. nmap
B. SNMP
C. ipconfig
D. ping

88. What does a speed tester measure?
A. MTU
B. DNS resolution
C. Bandwidth and latency
D. TTL

89. What is a result of AP channel overlap?
A. Fast roaming
B. Signal boost
C. Interference
D. Extended range

90. What tool analyzes wireless signal strength and coverage?
A. Cable tester
B. Protocol analyzer
C. Heat map
D. Loopback plug
```