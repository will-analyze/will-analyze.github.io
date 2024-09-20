---
layout: post
title: CyberOps Associate Guide (1.0 Security Concepts)
subtitle: Based on "Cisco CyberOps Associate CBROPS 200-201 Official Cert Guide" by Omar Santos
thumbnail-img: /assets/img/01_cyberops_associate_300-2696517745.png
share-img: /assets/img/01_cyberops_associate_300-2696517745.png
tags: tags: [cisco, cyberops, associate, certificate, cert, guide, security, concepts]
author: Will
---
# 1.0 Security Concepts

from: "Cisco CyberOps Associate CBROPS 200-201 Official Cert Guide" by Omar Santos
## 1.1 Describe the CIA triad
- **C**onfidentiality
	- ISO 27000: “confidentiality is the property that information is not made available or disclosed to unauthorized individuals, entities, or processes.”
	- commonly protected via encryption
	- **C**ommon **V**ulnerability **S**coring **S**ystem (CVSS) uses CIA triad principles within metrics used to calculate CVSS base score
- **I**ntegrity
	- ability to make sure system and data have not already been altered or compromised
	- data AND systems
	- i.e. data taken/changed, network/server config change, etc.
- **A**vailability
	- means system must be available to auth'd users at all times
	- CVSS Version 3 specification: measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability."
## 1.2 Compare security deployments
### a. Network, endpoint, and application security systems
- Traditional Firewall (https://www.geeksforgeeks.org/difference-between-traditional-firewall-and-next-generation-firewall/)
	- looks at packet state, source IP, destination IP, port, and protocol
	- if any of these are blocked by a rule, the packet itself is blocked and the firewall raises an event
	- typically operates on layers 2,3,4
	- can't inspect ssl traffic
	- supports protocols like NAT, PAT, and VPN
	- IPS and IDS are typically separate instances
- Next-Gen Firewall (NGFW) (https://www.geeksforgeeks.org/difference-between-traditional-firewall-and-next-generation-firewall/)
	- like a traditional firewall, but with additional features
	- can operate on layers 2-7
	- has application awareness
	- can inspect SSL traffic
	- extends protocols ike NAT, PAT, and VPN, integrates new threat management tech
	- IPS and IDS is usually integrated in
- Personal Firewall
	- firewall, but at the level of an individual computer
	- different from ACL as it is stateful (keeps track of context), stateless (doesn't keep track of historical context)
- Intrusion Detection System (IDS)
	- monitors traffic to search for known threats/suspicious/malicious activity
		- i.e. address spoofing, fragmentation, pattern evasion, coordinated attack
- Intrusion Prevention System (IPS/NGIPS)
	- analyzes real-time traffic by sitting in the direct communication path
	- takes automated preventative action
	- looks for suspicious traffic outside the baseline
- Anomaly Detection Systems
	- detects unusual traffic by comparing with the historical data trend
- Advanced Malware Protection (AMP)
	- is able to detect and flag malware that uses obfuscation techniques
	- not reliant on signatures
- Web Security Appliances
	- deployed at edge of network
	- specializes in web traffic and related threats
	- i.e. web secure gateway appliance can identify potential threats/data leaks
- Email Security Appliances
	- searches through email to look for spam, malicious attachemets/links, graymail (marketing mail, corporate spam, etc.) filtering, DLP (data loss prevention), outbound message control, etc.
- Identity Management Systems
	- AKA IAM (Identity and Access Management), helps control authentication, authorization, and accounting of users and their permissions
- Endpoint (AV, Antimalware, HIDS, Host-Based Firewall)
	- helps detect and prevent attacks on hosts and endpoints within a network:
		- antimalware: detects and sandboxes malware on endpoints
		- HIDS: **H**ost-Based **I**ntrusion **D**etection **S**ystem
		- Host-Based Firewall: firewall at the host level, allows for more granular and custom protections
### b. Agentless and agent-based protections
- agent based:
	- uses software installed on the host system to perform certain actions.
		- patching
		- scanning
		- rebooting
		- config changes
- agentless:
	- uses other infrastructure to monitor and control security on endpoints
### c. Legacy antivirus and antimalware
- detects malware and vriuses using a signature database
### d. SIEM, SOAR, and log management
- **S**ecurity **I**nformation and **E**vent **M**anagement
	- allows for detection and analysis of suspicious activity
	- collects and collates logs from different sources
	- compares this to historical traffic
- serves the following functions:
	- log collection:
		- receiving and centralizing logs from various devices
	- log normalization
		- takes logs in different formats and stores them into a common model
	- log aggregation
		- combines common info and prevents duplicates
	- log correlation
		- ability to correlate events across different systems 
	- reporting
		- compiling events into readable reports for analysts to act upon
- **S**ecurity **O**rchestration **A**utomation and **R**esponse
	- Automation of Security prevention and response for attacks
	- **Orchestration:** allows to coordinate automation tools from a centralized point
	- **Automation:** allows for certain tools and scripts to trigger by certain rules
- Log Management:
	- centralizes logs from across the environment
	- primarily used as a data source by a siem
	- ELK (Elastisearch, Logstash, Kibana) is a common way to collect and analyze logs
## 1.3 Describe security terms

### a. Threat intelligence (TI)
- collecting and understanding potential vulnerabilities and threats found within an organization
- aggregate, analyze, and correlate potential security threats from across an organization
### b. Threat hunting
- act of proactively and iteratively looking for threats in your org
- requires deep knowledge of network
- process:
	1. Hypothesis: what do you think is vulnerable? (based on Threat Intel, Internal Anomaly, Intuition)
	2. Investigation: use tools/methodologies, etc.
	3. Discovery: reveal new patterns, tactics, techniques, and procedures
	4. Tuning: refine and enrich using analytics
	5. Mitigation: threat identified and mitigated
- usually done by SOC analysts
	- aka threat hunters, tier 2/3 analyst, etc.)
- not incident response or vuln management
- ![[Screenshot from 2024-06-10 20-57-26.png]]
### c. Malware analysis
- detects and blocks malicious exploits
- detonates suspicious files (sandboxing)
- analyzes file behavior
- cisco advanced malware protection (AMP) networks and for endpoints
### d. Threat actor
- individuals that perform an attack/are responsible for security incident that impacts an org or individual
### e. Run book automation (RBA)
- runbook: collection of procedures and operations performed by sys admins, sec pros, and network operators
- runbook metrics:
	- MTTR: Mean time to repair
	- MTBF: Mean time between failures
	- Mean time to discover a security incident
	- mean time to contain/mitigate
	- automating the provisioning of IT resources
- rundeck is a good job scheduler and runbook automator
### f. Reverse engineering
- acquiring architectural info about anything originally created by someone else
- both a red/blue team technique
- used to understand malware, reversing cryptographic algorithms, reversing DRM or Digital Rights management solutions
- using system monitoring tools, disassembler (binary -> assembly code), debuggers, decompilers (binary to readable file), etc.
### g. Sliding window anomaly detection
- in order to save on compute, anomaly detection is limited to a given span of time
### h. Principle of least privilege
- people only have the exact permissions they need to do their job, no more no less 
### i. Zero trust
- "requires strict identity verification for every person and device on private network, regardless of whether they are sitting within or outside the network perimeter"
- https://www.cloudflare.com/learning/security/glossary/what-is-zero-trust/
### j. Threat intelligence platform (TIP)
#### Different Types:
- STIX: **S**tructured **T**hreat **I**nformation e**X**pression
	- structured language made to describe threats and allows threat hunters to share, store, and analyze this info:
	- 9 key constructs (from https://stixproject.github.io/about/)
		- [Observables](http://cyboxproject.github.io) describe what has been or might be seen in cyber
		- [Indicators](https://stixproject.github.io/data-model/1.2/indicator/IndicatorType) describe patterns for what might be seen and what they mean if they are
		- [Incidents](https://stixproject.github.io/data-model/1.2/incident/IncidentType) describe instances of specific adversary actions
		- [Adversary Tactics, Techniques, and Procedures](https://stixproject.github.io/data-model/1.2/ttp/TTPType) describe attack patterns, malware, exploits, kill chains, tools, infrastructure, victim targeting, and other methods used by the adversary
		- [Exploit Targets](https://stixproject.github.io/data-model/1.2/et/ExploitTargetType) describe vulnerabilities, weaknesses, or configurations that might be exploited
		- [Courses of Action](https://stixproject.github.io/data-model/1.2/coa/CourseOfActionType) describe response actions that may be taken in response to an attack or as a preventative measure
		- [Campaigns](https://stixproject.github.io/data-model/1.2/campaign/CampaignType) describe sets of incidents and/or TTPs with a shared intent
		- [Threat Actors](https://stixproject.github.io/data-model/1.2/ta/ThreatActorType) describe identification and/or characterization of the adversary
		- [Reports](https://stixproject.github.io/data-model/1.2/report/ReportType) collect related STIX content and give them shared context
- TAXII: **T**rusted **A**utomated e**X**change of **I**ndicator **I**nformation
	- defines how to exchange threat information and data i.e. message formats, protocols, requirements
	- two key concepts:
		- collection:
			- set of STIX packages organized by vendor/agency
		- channel:
			- a way for an org to access a specific collection (i.e. API, file exchange, etc.)
- CybOX: **Cyb**er **O**bservable e**X**pression
	- standardized lang for encoding/communicating high-fidelity security info 
	- specification, capture, characterization, and communication of security events
- OpenIOC: **Open** **I**ndicators of **C**ompromise
	- A Indicator of Compromise is any piece of information that allows for an analyst to determine if a compromise has happened. 
	- OpenIOC is a way for analysts to communicate their finding effectively
- OpenC2: **Open** **C**ommand and **C**ontrol
	- standardized lang for command and control of tech that provide/support defenses
	- conveys the "action" part of cybersecurity process
## 1.4 Compare security concepts

### a. Risk (risk scoring/risk weighting, risk reduction, risk assessment)
- **C**ommon **V**ulnerability **S**coring **S**ystem (CVSS) is the primary standard
	- Base Metric group:
		- exploitability metrics
			- attack vector
			- attack complexity
			- privileges required
			- user interaction
		-  impact metrics
			- confidentiality impact
			- integrity impact
			- availability impact
		- scope
	- Temporal Metric Group:
		- exploit code maturity
		- remediation level
		- report confidence
	- environment metric group:
		- modified base metrics
		- confidentiality requirement
		- integrity requirement
		- availability requirement
	- severity rating scale:
		- none: 0.0
		- low: 0.1-3.9
		- medium: 4.0-6.9
		- high: 7.0-8.9
		- critical: 9.0-10.0
- reduce risk by mitigating cvss's from your env in order of severity
### b. Threat
- potential danger to an asset
- latent threat: a threat that has not been realized
- threat actor: the individual or group that engages in malicious activity
- threat agent/vector: the path the threat actor used to leverage threat
- countermeasure: a safeguard that *mitigates* a potential risk
### c. Vulnerability
- an exploitable weakness in a system or its design
- vulnerabilities can be found in protocols, operating systems, applications, hardware, and system designs
- example:
	- sql injection
	- cross site scripting
	- buffer overflow
	- privilege escalation
	- cryptographic vulns
- **c**ommon **v**ulnerabilities, and **e**xposures
	- supported by US-CERT and MITRE 
	- naming convention allowing vulns to be easy to search
### d. Exploit
- software/ sequence of commands that takes advantage of a vuln to cause harm
- many classifications, but the two main ones are 
	- remote exploit
		- launches over network and carries out attack without prior access
	- Local exploit
		- requires prior access to vulnerable system
- exploit kit
	- compilation of exploits that are often served from a web server
	- main purpose is identifying software vulns in client machines and the exploiting such vulns to upload and execute malicious code on client
	- examples:
		- angler, MPack, Fiesta, Phoenix, Blackhole, Crimepack, RIG
## 1.5 Describe the principles of the defense-in-depth strategy
- "**Defense in depth** is a strategy that leverages multiple security measures to protect an organization's assets. The thinking is that if one line of defense is compromised, additional layers exist as a backup to ensure that threats are stopped along the way. Defense in depth addresses the security vulnerabilities inherent not only with hardware and software but also with people, as [negligence or human error](https://www.fortinet.com/content/dam/fortinet/assets/threat-reports/insider-threat-report.pdf) are often the cause of a security breach."
- source: https://www.fortinet.com/resources/cyberglossary/defense-in-depth
## 1.6 Compare access control models

### a. Discretionary access control
- each resource has clearly identified owner
- i.e. user creating file becomes owner of file
	- owner of resource can decide at their discretion to allow other user or subject access to that resource 
- users can be organized into groups and be granted access/privileges based on those groups
- maintain permissions by respecting need to know and least privileges
	- too many privileges can lead to "privilege/authorization creep"
		- privileges are going to users that don't need them, increasing attack surface
### b. Mandatory access control
- access auth is provided by OS
- owner has no control on who can access resource
- resource receives sensitivity/security label
- security classification of object and compartment that object belongs to
	- i.e. file is given "top secret" status only for a certain group 
### c. Nondiscretionary access control
- access is determined by central admin, not owner
### d.Authentication, authorization, accounting
- Authentication: process of proving the identity of a subject/user
	- authentication by knowledge: something the user knows (passwords, PINs)
	- authentication by ownership: something the user owns: (smart card, badge, token, 2fa app) 
	- authentication by characteristic: something user is/does. fingerprint, hand geometry, keystroke dynamic, etc.
- Authorization: process of granting access to object or resource to a subject. Typically after subject has completed the auth 
	- implicit deny:
		- if no rule is specified for transaction subject or an object, the auth policy should deny transaction
	- need to know:
		- subject should only be granted access to object only if the access is needed to carry out job of subject
- Accounting: auditing and monitoring what a user does once a specific resource is accessed
	- Audit Trail: 
		- start time?
		- what did the user do?
		- when user stopped using resource
### e. Role-based access control
- subject's role to take auth decision
- subject need to be assigned role (user assignment)
- role is then assigned permission over object (permission assignment)
- improves scalability and simplifies admin as subject can be just assigned to role
- subject can be assigned to several roles, role can include multiple subjects
- role can have multiple permissions and same permission can be assigned to multiple roles
- different types:
	- Flat RBAC
	- Hierarchical RBAC
	- Constrained RBAC
	- Symmetric RBAC
### f. Time-based access control
- can only access during specific times
- i.e. an office closing off wireless network outside of working hours to prevent unauthorized connections
### g. Rule-based access control
- not well defined
- just means things are rule-based, not role based
- i.e. only certain IPs or times of day can access

### Bonus:
- asset or data classification: process of classifying data based on risk for org related to confidentiality, integrity, and availability of data
	- Common Military/Government Classification:
		- top secret: unauthorized access to top secret info would cause grave damage to national security
		- secret: unauthorized access to a secret info would cause a severe damage to nation security
		- confidential: unauthorized access to confidential info would cause damage to national security
		- unclassified: unauthorized access to unclassified info would cause no damage to national security 
	- Common Commercial classification:
		- confidential/proprietary: unauthorized access to confidential or proprietary info could cause grave damage to org
			- i.e. source code, trade secret, etc.
		- private: unauthorized access to private info could cause damage to org 
			- i.e. employee salary, medical records, etc.
		- sensitive: unauthorized access to sensitive information could cause a damage to the org:
			- i.e. internal team email, financial info, etc.
		- public: unauthorized access to public info does not cause any significant damage
- asset marking: process of marking or labeling assets or data so that its classification is clear to the user
- access policy definition: process of defining policy and rules to govern access to an asset
- data disposal: the process of disposing or eliminating an asset or data
- access control policy: who can access what data? when? which modality? How are assets protected based on their state?
	- data states:
		- data at rest: data in a storage device such as hard drive, USB pen drive, etc.
			- data is in this state most of lifetime
			- data at rest are usually protected by using strong access controls and encryption
		- data in motion: data moving between two parties and is in transit
			- higher risk because it is outside security perimeter
			- end to end encryption and VPN technologies are usually used to protect data in motion
		- data in use: data being processed by apps/programs 
			- stored in temporary or volatile memory (i.e. RAM, CPU registers)
- attribute-base access control:
	- Subject (user): name, nationality, org, etc.
	- object (resource): name, owner, creation date
	- Environment: access location, access time, threat level of permission
## 1.7 Describe terms as defined in CVSS

### a. Attack vector
- in which context is the vulnerability exploitable?
	- Network (N): remotely exploitable
	- Adjacent (A): limited at protocol level to adjacent topology
	- Local (L): vuln is limited to local access
	- Physical (P): requires ability to touch/manipulate vuln system
### b. Attack complexity
- how many measurable actions need to be taken by attacker
- two categories:
	- low: attacker takes little to no measureable action to exploit vuln
	- high: attacker needs to take many measureable actions to exploit vlun
### c. Privileges required
- what privileges must an attacker possess prior to successful exploitation.
- levels:
	- none (N): attack is unauthorized 
	- Low (L): attack requires basic, low level privileges
	- High (H): provides significant control over vuln system allowing full access to vuln system settings and files
### d. User interaction
- amount of interaction needed from a user other than the attacker:
	- None (N): system can be exploited by attacker along
	- Passive (P): requires indirect user interaction
	- Active (A): requires active, specific interactions with vuln system
### e. Scope
- measure of impact of a vuln
	- outside of system, i.e. other systems, users, etc.

## 1.8 Identify the challenges of data visibility (network, host, and cloud) in detection

## 1.9 Identify potential data loss from provided traffic profiles

## 1.10 Interpret the 5-tuple approach to isolate a compromised host in a grouped set of logs

## 1.11 Compare rule-based detection vs. behavioral and statistical detection
