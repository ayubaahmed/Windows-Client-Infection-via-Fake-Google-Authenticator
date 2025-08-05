Incident Report: Fake Google Authenticator Malware Infection

PCAP Source

This report and analysis are based on the PCAP file provided by Malware-Traffic-Analysis.net:

- Website: [https://www.malware-traffic-analysis.net/2025/01/22/index.html](https://www.malware-traffic-analysis.net/2025/01/22/index.html)
- PCAP download: [https://www.malware-traffic-analysis.net/2025/01/22/2025-01-22-traffic-analysis-exercise.pcap.zip](https://www.malware-traffic-analysis.net/2025/01/22/2025-01-22-traffic-analysis-exercise.pcap.zip)

Summary

On 22-01-2025, a windows computer was infected by malware, the infection happened after the user searched for "Google Authenticator" and visted a website that was pretending to be legitmate. I retrieved the network traffic and analysed it, coming to a conlusion that the website delivered a malware using an HTTP C2 Sever at 5.252.153.241. This report will detail how the infection was identified, the suspicious activities observed and provide recommendations to contain and remediate the threat. 


Affected Computer Details

IP Address: 10.1.17.215
MAC Address: 00:d0:b7:26:4a:74
Hostname: DESKTOP-L8C5G5J
Domain: BLUEMOONTUESDAY.COM
User Account: shutcherson

Malicious Sites/C2 IP Addresses

These are the known malicious or suspicious sites/IP addresses involved:
google-authenticator.burleson-appliance.net – Fake website pretending to be Google Authenticator.
5.252.153.241 – Server contacted to download a PowerShell script (confirmed malicious).
45.125.66.32 – Suspicious server with encrypted traffic on an unusual port (2917).
45.125.66.252 – Another suspicious server in the same network range.
“Due to limited evidence, these last two IP addresses are currently classed as suspicious and warrant further monitoring.”


Investigation Steps and Visual Evidence
Each step below shows how I discovered what happened, along with the matching screenshot file.

1. Finding the Infected Computer
- Used Wireshark to filter DHCP traffic and watch the DHCP handshake.
- Found which IP address was assigned to which MAC by looking at the DHCP Request and ACK packets.
- Filtered HTTP traffic for that IP (10.1.17.215) to see what kind of communication it was doing.

Screenshot: 
- HTTP_Traffic.png
- DHCP_Handshake_Process.png
- DHCP_Client_Identification_Details.png

2. Identifying Hostname and User
- Filtered NBNS traffic to find the computer’s hostname and domain registrations.  
- Filtered Kerberos traffic, looking specifically at AS-REP packets to identify the user account (`shutcherson`). 

Screenshot: 
- NBNS_Hostname_and_Domain_Registrations.png
- Kerberos_Authentication_Traffic_Overview.png
- Kerberos_Authentication_User_shutcherson.png
- Network_Client_Discovery_DNS_Kerberos_Overview.png

3. DNS Query to Fake Site
- Applied HTTP and DNS filters with keywords like "google" and "auth" to narrow down relevant traffic.
- Spotted the domain names the computer requested before infection.
- Found DNS queries for the domain 'google-authenticator.burleson-appliance.net'.
- Established that visiting this site was the initial infection vector.

Screenshot: 
- DNS_Queries_FakeAuth_and_C2_Resolution.png
- DNS_Query_Fake_GoogleAuthenticator_Details.png
- Filtered_DNS_GoogleAuth_Query_View.png

4. HTTP Connection to C2 Server
- Filtered HTTP traffic in Wireshark to focus on web requests from the infected computer.  
- Found HTTP requests to the IP address 5.252.153.241.  
- Checked the details of the requests and saw that the computer was trying to download a PowerShell script.  
- The server’s response included a failed attempt with a 404 error.

Screenshot: 
- C2_HTTP_Requests_Overview_5.252.153.241.png
- C2_HTTP_Traffic_Summary_5.252.153.241.png
- C2_Payload_Request_PowerShell_Script.png
- C2_Payload_Download_Attempt_404_Response.png

5. Network Conversation Analysis
- Filtered all traffic involving the infected computer’s IP address.
- Used Wireshark’s Conversations window to see which ports the computer was communicating on.
- Noticed traffic going out on port 2917.
- Noticed the traffic was using port 2917, which isn’t a standard port.
  
Screenshot: 
- Network_Conversation_IPv4_Summary.png
- IP_Suspicious_Port.png

6. Communication to Suspicious IPs
- Checked the reputation of these IP addresses on VirusTotal and similar services.
- Found that the IPs were flagged as suspicious or malicious by multiple security sources.

Screenshot:
- IP_Reputation_45.125.66.32_Detection_Summary.png
- IP_Reputation_45.125.66.32_Malicious_Flags.png

Key Findings

- The user accessed a fake site posing as Google Authenticator.
- The infected computer communicated with several suspicious IP addresses.
- One of the servers attempted to deliver a PowerShell script.
- Some traffic was sent to unknown servers over an uncommon port.
- IP reputation checks confirmed the servers were flagged as malicious.


**Recommendations**

- Isolate and reinstall the infected computer.
- Block the bad website and IP addresses on the network.
- Change the password for the user shutcherson.
- Check all devices and accounts for signs of spread.
- Train users to recognize and avoid phishing and malicious ads.

