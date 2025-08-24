# Incident Report: Fake Google Authenticator Malware Infection  

---

## PCAP Source  

This report and analysis are based on the PCAP file provided by *Malware-Traffic-Analysis.net*:  

- Website: [https://www.malware-traffic-analysis.net/2025/01/22/index.html](https://www.malware-traffic-analysis.net/2025/01/22/index.html)  
- PCAP download: [https://www.malware-traffic-analysis.net/2025/01/22/2025-01-22-traffic-analysis-exercise.pcap.zip](https://www.malware-traffic-analysis.net/2025/01/22/2025-01-22-traffic-analysis-exercise.pcap.zip)  

---

## Summary  

On 22 January 2025, a Windows workstation was infected with malware. The compromise occurred after the user searched for Google Authenticator and visited a website pretending to be legitimate. The captured network traffic was examined, and it was concluded that the site delivered malware by contacting an HTTP command-and-control (C2) server hosted at **5.252.153.241**.  

This report explains how the infection was identified, the suspicious behaviour that followed, and sets out recommendations to contain and remediate the threat.  

By combining packet capture analysis in Wireshark with Splunk SIEM queries, I was able to follow the activity at both the host level and across the wider network. Looking at it from both perspectives confirmed with high confidence that the compromise originated from the fake site and its associated attacker servers.  

---

## Affected Computer Details  

- **IP Address:** 10.1.17.215  
- **MAC Address:** 00:d0:b7:26:4a:74  
- **Hostname:** DESKTOP-L8C5G5J  
- **Domain:** BLUEMOONTUESDAY.COM  
- **User Account:** shutcherson  

Splunk correlation confirmed that this host was one of the most active generators of HTTP traffic in the dataset, reinforcing that it was the compromised machine (/screenshots *Top_Hosts_HTTP_Requests.png*).  

---

## Malicious Sites and C2 IP Addresses  

- **google-authenticator.burleson-appliance.net** – Fake website masquerading as Google Authenticator.  
- **5.252.153.241** – Server contacted to retrieve a PowerShell script (confirmed malicious).  
- **45.125.66.32** – Suspicious server with traffic over port 2917 (non-standard).  
- **45.125.66.252** – Another suspicious server within the same address range.  

Due to limited supporting evidence, the last two IPs are considered suspicious rather than confirmed, but they require ongoing monitoring.  

Splunk time-series queries showed these addresses receiving abnormal volumes of traffic from the infected host, suggesting they formed part of the attacker’s infrastructure (see *Suspicious_IP_Communication_Timeline.png*).  

---

## Investigation Steps and Evidence  

### 1. Identifying the Infected Host  
- Used Wireshark to examine DHCP traffic and observe the handshake process.  
- Confirmed which IP address was assigned to which MAC address from the DHCP Request and ACK packets.  
- Filtered HTTP traffic for **10.1.17.215** to see what activity it was generating.  
- Splunk query (`stats count by ip_src, host | sort -count`) confirmed this same host as one of the most active in HTTP traffic.  

**Screenshots:**  
- HTTP_Traffic.png  
- DHCP_Handshake_Process.png  
- DHCP_Client_Identification_Details.png
- (./Images/HTTP_Traffic.png  )

---

### 2. Identifying Hostname and User  
- Examined NBNS traffic to identify the machine’s hostname and domain.  
- Reviewed Kerberos AS-REP traffic to determine the user account, which was confirmed as **shutcherson**.  

**Screenshots:**  
- NBNS_Hostname_and_Domain_Registrations.png  
- Kerberos_Authentication_Traffic_Overview.png  
- Kerberos_Authentication_User_shutcherson.png  
- Network_Client_Discovery_DNS_Kerberos_Overview.png  

---

### 3. DNS Query to Fake Site  
- Applied HTTP and DNS filters using keywords such as “google” and “auth” to focus on relevant queries.  
- Observed DNS lookups for **google-authenticator.burleson-appliance.net**.  
- Established that visiting this domain was the initial infection vector.  
- Splunk analysis confirmed that shortly after resolving this domain, the host began contacting suspicious IPs, matching the infection timeline.  

**Screenshots:**  
- DNS_Queries_FakeAuth_and_C2_Resolution.png  
- DNS_Query_Fake_GoogleAuthenticator_Details.png  
- Filtered_DNS_GoogleAuth_Query_View.png  

---

### 4. HTTP Connection to C2 Server  
- Filtered HTTP traffic to highlight communications between **10.1.17.215** and **5.252.153.241**.  
- Observed attempts to download a PowerShell script.  
- The server responded with repeated **404** errors, showing the file was not present at that time.  
- Splunk confirmed repeated requests for `.ps1` files from this IP. A time chart of HTTP status codes showed a series of 403/404 errors, consistent with C2 behaviour.  

**Screenshots:**  
- C2_HTTP_Requests_Overview_5.252.153.241.png  
- C2_HTTP_Traffic_Summary_5.252.153.241.png  
- C2_Payload_Request_PowerShell_Script.png  
- C2_Payload_Download_Attempt_404_Response.png
- ![Secrets](./C2_Payload_Download_Attempt_404_Response.png)

---

### 5. Network Conversation Analysis  
- Analysed all traffic involving **10.1.17.215**.  
- Wireshark’s Conversations view highlighted unusual outbound communication over **port 2917**.  
- Splunk confirmed spikes of traffic to **45.125.66.32** and **45.125.66.252**, suggesting fallback or secondary C2 infrastructure.  

**Screenshots:**  
- Network_Conversation_IPv4_Summary.png  
- IP_Suspicious_Port.png  

---

### 6. Communication with Suspicious IPs  
- Checked the reputation of the suspicious IPs in VirusTotal and other services.  
- Both addresses were flagged as malicious by several security vendors.  
- Splunk queries showed attempted downloads of `/pas.ps1` and `/TeamViewer`, indicating delivery of both payloads and remote access tools.  

**Screenshots:**  
- IP_Reputation_45.125.66.32_Detection_Summary.png  
- IP_Reputation_45.125.66.32_Malicious_Flags.png  

---

## Timeline of Events  

- **19:45:56** – First HTTP request from host **10.1.17.215** to **5.252.153.241**.  
- **19:47** – DNS query for **google-authenticator.burleson-appliance.net**.  
- **19:48** – HTTP GET requests sent to **5.252.153.241**.  
- **19:50** – Attempted PowerShell script download (`/pas.ps1`), server responded with 404.  
- **20:05** – Outbound communication to suspicious IP **45.125.66.32** over port 2917.  
- **20:10 onwards** – Continued traffic to **45.125.66.32** and **45.125.66.252**, indicating fallback C2 activity.  

---

## Key Findings  

- The user accessed a fake site pretending to be Google Authenticator.  
- The infected machine communicated with several suspicious IP addresses.  
- One of the servers attempted to deliver a PowerShell script.  
- Traffic was observed on a non-standard outbound port (2917).  
- IP reputation checks confirmed the addresses were flagged as malicious.  

By reviewing both Wireshark and Splunk data, it was possible to reconstruct the events in detail and confirm that the infection stemmed from the fake website and the attacker’s infrastructure.  

---

## Recommendations  

- Isolate and reimage the affected workstation.  
- Block the malicious domain and IP addresses at the firewall and proxy.
- Reset the password for the account **shutcherson**.
- Restrict PowerShell use to administrators only, reducing the chance of script-based attacks.
- Inspect other hosts and accounts for lateral movement or related activity.  
- Implement user awareness training to reduce the risk of future compromise.  
