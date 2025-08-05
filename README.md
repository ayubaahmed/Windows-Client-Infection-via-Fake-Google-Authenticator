# Windows-Client-Infection-via-Fake-Google-Authenticator

Incident Report: Fake Google Authenticator Malware Infection

Summary

On 2025-01-22, a Windows workstation within the BLUEMOONTUESDAY.COM domain was compromised after a user accessed a fake Google Authenticator website. The user unknowingly initiated malware communication with external Command and Control (C2) infrastructure. This report documents the infection indicators and network evidence.

Affected Host Details

Attribute	Value
IP Address	10.1.17.215
MAC Address	00:d0:b7:26:4a:74
Hostname	DESKTOP-L8C5G5J
Domain	BLUEMOONTUESDAY.COM
User Account	shutcherson

Malicious Infrastructure

Indicator	Type	Notes

google-authenticator.burleson-appliance.net	Domain	Fake site used to deliver payload
5.252.153.241	IP Address (C2)	PowerShell script downloads attempted
45.125.66.32	IP Address (C2)	Encrypted traffic over non-standard port 2917
45.125.66.252	IP Address (C2)	Related to .32; similar traffic pattern and subnet

🔎 Investigation Steps & Evidence

1. Initial DHCP Assignment
Identified IP and MAC of the infected host through DHCP traffic.
![DHCP Assignment](images/dhcp.png)

2. Host & Domain Discovery
NBNS and Kerberos packets confirmed hostname and domain.
![NBNS & Kerberos](images/kerberos.png)

3. Malicious Domain Contact
DNS queries to the fake domain were made by the infected host.
![DNS Query](images/dns-fake-site.png)

4. C2 Communication - HTTP Downloads
HTTP GET requests to 5.252.153.241 for .ps1 payloads.
![HTTP Traffic](images/http-get-ps1.png)

5. C2 Communication - Encrypted TLS
Encrypted traffic to 45.125.66.32 on port 2917 with self-signed cert.
[TLS Analysis](images/tls-c2.png)

Key Findings

The user accessed a malicious site impersonating Google Authenticator.
Multiple C2 servers were contacted for payload download and persistent communication.
TLS traffic on non-standard ports and IP reputation confirmed malicious behavior.

Recommendations

Isolate and reimage the infected host.
Block the malicious domain and C2 IPs at firewall and DNS level.
Rotate user credentials for shutcherson.
Conduct full endpoint and domain audit for lateral movement.
Improve user awareness and filtering of malicious ads/phishing.
