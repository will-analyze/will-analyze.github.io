---
layout: post
title: CyberOps Associate Guide (2.0 Security Monitoring)
subtitle: Based on "Cisco CyberOps Associate CBROPS 200-201 Official Cert Guide" by Omar Santos
thumbnail-img: /assets/img/01_cyberops_associate_300-2696517745.png
share-img: /assets/img/01_cyberops_associate_300-2696517745.png
tags: [cisco, cyberops, associate, certificate, cert, guide, security, monitoring]
author: Will
---
## 2.1 Compare attack surface and vulnerability
- vulnerability: individual threat within an org
- attack surface: a summary of the org's vulnerabilities on the whole
## 2.2 Identify the types of data provided by these technologies

### a. TCP dump
- grab all packets from a given NIC
- allows to identify traffic occurring over network
### b. NetFlow
- cisco tool
- traffic passes through it and it analyzes it
- can do:
	- anomaly detection, investigation, nonrepudiation
### c.Next-gen firewall
from: (https://www.geeksforgeeks.org/difference-between-traditional-firewall-and-next-generation-firewall/)
	- like a traditional firewall, but with additional features
	- can operate on layers 2-7
	- has application awareness
	- can inspect SSL traffic
	- extends protocols ike NAT, PAT, and VPN, integrates new threat management tech
	- IPS and IDS is usually integrated in
### d. Traditional stateful firewall
- from: (https://www.geeksforgeeks.org/difference-between-traditional-firewall-and-next-generation-firewall/)
	- looks at packet state, source IP, destination IP, port, and protocol
	- if any of these are blocked by a rule, the packet itself is blocked and the firewall raises an event
	- typically operates on layers 2,3,4
	- can't inspect ssl traffic
	- supports protocols like NAT, PAT, and VPN
	- IPS and IDS are typically separate instances
### e. Application visibility and control
from: (https://www.juniper.net/us/en/research-topics/what-is-application-visibility-and-control.html)
- Identify applications and allow, block, or limit applications – regardless of the port, protocol, decryption, or any other evasive tactic.
- Identify users, regardless of device or IP address, by using granular control of applications by specific users, groups of users, and machines. This helps organizations control the types of traffic allowed to enter and exit the network.
- Support inbound and outbound SSL decryption capabilities to identify and prevent threats and malware in encrypted network streams.
- Integrate with intrusion prevention systems (IPS) and apply appropriate attack objects to applications on nonstandard ports.
### f. Web content filtering
- prevents connections to dodgy site
### g. Email content filtering
- prevents dodgy emails
## 2.3 Describe the impact of these technologies on data visibility

### a. Access control list
- two main types:
	- file system
		- stores and delegates access to files and directories on an OS
		- examples are NFSv4 ACLs and POSIX ACLs
	- network
		- like a firewall, but it is specific to an interface 
		- typically just an allow/deny statement with the following info:
			- action (allow/deny), t4 protocol, source IP address, source IP wildcard, destination IP address, destination port
		- 
### b. NAT/PAT
- **N**etwork **A**ddress **T**ranslation: "translates" private IPs to public IP(s).
	- multiple styles but the most common is one-to-many where the hosts point to an endpoint (router/firewall), only one public IP exposed
- **P**ort **A**ddress **T**ranslation: Private IPs are translated to Public IP via port numbers
	- when a connection is made, PAT gives the connection a unique port
### c. Tunneling
- just refers to transporting data across network using protocols not supported by network
	- based on encapsulating packets
	- example: need to connect two networks, one only supports IPV6, one only supports IPv4. Encapsulate the packets from one network in packets supported by the other network (IPv4 in IPv6, IPv6 in IPv4)
- from: (https://www.cloudflare.com/learning/network-layer/what-is-tunneling/)
	-  What is a VPN tunnel?
		- A VPN is a secure, encrypted connection over a publicly shared network. Tunneling is the process by which VPN packets reach their intended destination, which is typically a private network.
		- Many VPNs use the [IPsec](https://www.cloudflare.com/learning/network-layer/what-is-ipsec/) protocol suite. IPsec is a group of protocols that run directly on top of IP at the [network layer](https://www.cloudflare.com/learning/network-layer/what-is-the-network-layer/). Network traffic in an IPsec tunnel is fully encrypted, but it is decrypted once it reaches either the network or the user device. (IPsec also has a mode called "transport mode" that does not create a tunnel.)
		- Another protocol in common use for VPNs is [Transport Layer Security (TLS)](https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/). This protocol operates at either layer 6 or layer 7 of the OSI model depending on how the model is interpreted. TLS is sometimes called SSL (Secure Sockets Layer), although SSL refers to an older protocol that is no longer in use.
	- What is split tunneling?
		- Usually, when a user connects their device to a VPN, all their network traffic goes through the VPN tunnel. Split tunneling allows some traffic to go outside of the VPN tunnel. In essence, split tunneling lets user devices connect to two networks simultaneously: one public and one private.
	- What is GRE tunneling?
		- Generic Routing Encapsulation (GRE) is one of several tunneling protocols. GRE encapsulates data packets that use one routing protocol inside the packets of another protocol. GRE is one way to set up a direct point-to-point connection across a network, for the purpose of simplifying connections between separate networks.
		- GRE adds two headers to each packet: the GRE header and an IP header. The GRE header indicates the protocol type used by the encapsulated packet. The IP header encapsulates the original packet's IP header and payload. Only the routers at each end of the GRE tunnel will reference the original, non-GRE IP header.
	- What is IP-in-IP?
		- IP-in-IP is a tunneling protocol for encapsulating IP packets inside other IP packets. IP-in-IP does not encrypt packets and is not used for VPNs. Its main use is setting up network routes that would not normally be available.
	- What is SSH tunneling?
		- The Secure Shell (SSH) protocol sets up encrypted connections between client and server, and can also be used to set up a secure tunnel. SSH operates at layer 7 of the OSI model, the application layer. By contrast, IPsec, IP-in-IP, and GRE operate at the network layer.
	- What are some other tunneling protocols?
		- In addition to GRE, IPsec, IP-in-IP, and SSH, other tunneling protocols include:
		- Point-to-Point Tunneling Protocol (PPTP)
		- Secure Socket Tunneling Protocol (SSTP)
		- Layer 2 Tunneling Protocol (L2TP)
		- Virtual Extensible [Local Area Network](https://www.cloudflare.com/learning/network-layer/what-is-a-lan/) (VXLAN)
### d. TOR
- **T**he **O**nion **R**outer: allows for more private communication 
	- done by encrypting packets in layers like an onion
	- uses a random exit node to increase privacy
### e. Encryption
- transforming readable data into unreadable data
### f. P2P
- **P**eer **2** **P**eer: Connection is directly to another computer with
### g. Encapsulation
- keeping things in one part of a program so the other parts don't need to know about them
### h. Load balancing
- distributing traffic to different endpoint based on a set of rules to prevent certain servers from being overwhelmed
## 2.4 Describe the uses of these data types in security monitoring

### a. Full packet capture
- most detailed, contains the full payload of each packet in the network for a specific amount of time
### b. Session data
- summary of network conversations based on IP 5-tuple
	- Source IP
	- Source Port
	- Dest IP
	- Dest Port
	- Protocol
### c. Transaction data
- second-most detailed, contains the messages exchanged during network sessions
### d. Statistical data
- more big-picture data about what general activity occurs when and where
- good to establish baselines and 
### e. Metadata
- literally "data about data"
	- i.e. time, size, abnormalities, etc.
### f. Alert data
- data created by Intrustion Detection systems that generates when certain conditions are met
## 2.5 Describe network attacks, such as protocol-based, denial of service, distributed denial of service, and man-in-the-middle
### Network Attacks:
- attack targeting the network of an organization
### Protocol-Based:
- an attack on or using a specific protocol i.e. FTP, telnet, SSH, etc.
### Denial of Service:
- flood site/server/etc. with an overwhelming amount of traffic in order to prevent others from connecting to site, effectively taking it down
### Distributed Denial of Service:
- type of DoS attack but it's when the attack is carried out by multiple, often compromised, hosts
### Man-in-the-Middle:
- when an attacker intercepts traffic on a network
- many different ways, but is often done by an attacker impersonating the site, wireless access point
## 2.6 Describe web application attacks, such as SQL injection, command injections, and cross-site scripting
### SQL Injection
- inserting a sql query into an input in order for the program to execute it and give the attacker unauthorized info
### Command Injections
- like a SQL injection, but for more general commands on a host
### Cross-site scripting
- sending malicious script to an unsuspecting user because the browser trusts the source
## 2.7 Describe social engineering attacks
- many types, but generally a way an attacker tricks a user or employee to give them access, credentials, or highly sensitive info
## 2.8 Describe endpoint-based attacks, such as buffer overflows, command and control (C2), malware, and ransomware
### buffer overflow
- inputting enough data into a program that the input buffer in the host memory overflows and sets the return pointer to point at malicious code
### command and control
-  the communications between a compromised host and a server 
### malware
- a piece of software that acts to damage, destroy, or otherwise compromise a host machine
### ransomware
- type of malware that focuses on encrypting a user or org's data and will unencrypt it for a fee
## 2.9 Describe evasion and obfuscation techniques, such as tunneling, encryption, and proxies
### tunneling
- allows attacker to obfuscate detection as packets are encapsulated within other packets and encrypted 
### encryption
- allows you to obscure data 
### proxies
- allows you to obscure original host by routing through others
## 2.10 Describe the impact of certificates on security (includes PKI, public/private crossing the network, asymmetric/symmetric)
### PKI
- **P**ublic **K**ey **I**nfrastructure 
- from (https://www.okta.com/identity-101/public-key-infrastructure/)
- Public key infrastructure is an important aspect of internet security. It is the set of technology and processes that make up a framework of encryption to protect and authenticate digital communications. 
- PKI uses cryptographic public keys that are connected to a digital certificate, which authenticates the device or user sending the digital communication. Digital certificates are issued by a trusted source, a certificate authority (CA), and act as a type of digital passport to ensure that the sender is who they say they are.
- Public key infrastructure protects and authenticates communications between servers and users, such as between your website (hosted on your web server) and your clients (the user trying to connect through their browser. It can also be used for secure communications within an organization to ensure that the messages are only visible to the sender and recipient, and they have not been tampered with in transit. 
- The main components of public key infrastructure include the following:
	- **Certificate authority (CA):** The CA is a trusted entity that issues, stores, and signs the digital certificate. The CA signs the digital certificate with their own private key and then publishes the public key that can be accessed upon request.
	- **Registration authority (RA):** The RA verifies the identity of the user or device requesting the digital certificate. This can be a third party, or the CA can also act as the RA.  
	- **Certificate database:** This database stores the digital certificate and its metadata, which includes how long the certificate is valid.
	- **Central directory:** This is the secure location where the cryptographic keys are indexed and stored.  
	- **Certificate management system:** This is the system for managing the delivery of certificates as well as access to them.  
	- **Certificate policy:** This policy outlines the procedures of the PKI. It can be used by outsiders to determine the PKI’s trustworthiness.
### public/private crossing the network
- key infrastructures can be private or public, private is limited to internal network
### asymmetric/symmetric encryption

## 2.11 Identify the certificate components in a given scenario
### a. Cipher-suite
[## What is a cipher suite?](https://www.keyfactor.com/blog/cipher-suites-explained/)

TLS 1.2 supported ciphers
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
- TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_DHE_RSA_WITH_AES_128_CBC_SHA
- TLS_DHE_RSA_WITH_AES_256_CBC_SHA
- TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
- TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305

### b. X.509 certificates
https://www.sectigo.com/resource-library/what-is-x509-certificate#Managing X.509 certificates
[link](https://www.sectigo.com/resource-library/what-is-x509-certificate#Managing X.509 certificates)

### c. Key exchange
https://cryptobook.nakov.com/key-exchange/diffie-hellman-key-exchange
[link](https://cryptobook.nakov.com/key-exchange/diffie-hellman-key-exchange)

### d. Protocol version
