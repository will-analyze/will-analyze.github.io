---
layout: post
title: CyberOps Associate Guide (3.0 Host-Based Analysis)
subtitle: Based on "Cisco CyberOps Associate CBROPS 200-201 Official Cert Guide" by Omar Santos
thumbnail-img: /assets/img/01_cyberops_associate_300-2696517745.png
share-img: /assets/img/01_cyberops_associate_300-2696517745.png
tags: [cisco, cyberops, associate, certificate, cert, guide, security, monitoring]
author: Will
---

## 3.1 Describe the functionality of these endpoint technologies in regard to security monitoring

### a. Host-based intrusion detection
- monitors individual devices for behavior/states that indicate intrusion
### b. Antimalware and antivirus
- antimalware: uses heuristics to identify threats by proactively detecting source codes
- antivirus: identifies known threats using signature based detection
### c. Host-based firewall
- allows for more detailed and specific prevention like, URL filtering, intrusion prevention, malware protection, etc.
### d. Application-level whitelisting/blacklisting
- blacklist: less secure, you have to specify what is blocked
- whitelist: more secure, you have to specify what is allowed
### e. Systems-based sandboxing (such as Chrome, Java, Adobe Reader)
- code that makes calls to the OS gets automatically sandboxed
- adds another layer for the attacker to need to exploit
## 3.2 Identify components of an operating system (such as Windows and Linux) in a given scenario
## Windows:
### Process:
- program system is running
- starts with one thread (primary thread) and spins up more as necessary
- Windows: processes need permission to run 
	- **CreateProcessWithTokenW:** you can use a windows token to specify current security context for process
	- **Windows Token:** windows stores data in a token, describes security context of all processes associated with particular user role
- fun fact: many process/thread ids are in multiples of 4 because kernel handles are and often the same code used to allocate kernel handles allocates other ids
### Threads:
- smaller units that an OS allocates time to
- make up processes
### Thread Pool:
- group of worker threads that efficiently executes asynchronous callbacks for the app
### Job:
- group of processes
### Volatile Memory (VRAM):
- loses contents when hardware loses power
### Non-Volatile Memory (NVRAM):
- content stays regardless of power
### Static Memory Allocation:
- allocates memory at compile time
### Dynamic Memory Allocation:
- allocates memory at runtime
### Heap:
- memory set aside for dynamic allocation
### Stack:
- memory set aside as spare space for a thread of execution
### Windows Registry:
- hierarchical database, stores config data for the users, apps, and hardware
- some functions include: loading device drivers, run startup programs, set env vars, user settings and operating system params
- **hives**: contain values pertaining to OS or apps within key
	- five main folders in reg are hives
### Windows Management Instrumentation Key Concepts
- **W**indows **M**anagement **I**nstrumentation (WMI):
	- sys management infra that is scalable, extensible, standards-based, and object oriented
	- data must be pulled in with scripting or tools, WMI doesn't show data itself
### System handle concepts:
- abstract reference value to resource
- hides real memory address from API user, allows system to reorg memory more safely
- handle can both identify and associate access rights
	- handle leak occurs if handle is not released
### Event logs:
- contains many system and application logs for windows
	- many logs that can be turned on/off as needed
	- three main ones are Application, Security, and System
- five main event types: error, warning, information, success audit, failure audit
- typically in c:\windows\system32\config
## Linux:
### ### Process:
- program system is running
- starts with one thread (primary thread) and spins up more as necessary
- Linux: different types of processes:
	- **child:** all processes are child processes to a parent process. Except for the init process (PID 1)
	- **init:** short for initialization, kernel starts init process to create/take down the user space. If kernel can't find init process, this is called kernel panic ![[Pasted image 20240623203325.png]]
		- source: https://linuxtldr.com/init-linux/
	- **orphan:** when parent process is terminated and child process continues
	- **zombie:** process that releases its associated memory/resources, stays in entry table
### threads:
- smaller units that an OS allocates time to
- make up processes
### Thread Pool:
- group of worker threads that efficiently executes asynchronous callbacks for the app
### Job:
- group of processes
### Volatile Memory (VRAM):
- loses contents when hardware loses power
### Non-Volatile Memory (NVRAM):
- content stays regardless of power
### Static Memory Allocation:
- allocates memory at compile time
### Dynamic Memory Allocation:
- allocates memory at runtime
### Heap:
- memory set aside for dynamic allocation
### Stack:
- memory set aside as spare space for a thread of execution
### Forks:
- when a parent creates child process
- fork command returns PID 
- entire virtual space of parent is replicated in child process, including all mem space
### Linux File Permissions:
- **Read (r):** reading, opening, viewing, and copying file
- **Write (w):** writing, changing, deleting, and saving file
- **Execute (x):** executing and invoking file are permitted, also search access
### Key Permissions Concepts:
- **chmod:** changes permission for file/directory
	- read (r) = 4
	- write(w)= 2
	- execute (x) = 1
- **group:** changes group ownership of file using chgrp command
- **chown:** changes owner of file
- note: permissions in Linux are top down, denying access for directory will include all files/subdirectories
- **Super User (sudo):** highest permissions, only used for admin tasks, NO PROCESS SHOULD RECEIVE SUDO UNLESS ABSOLUTELY NECESSARY
### Symlinks:
- any file that contains reference to other file/directory
	- symlink is only a reference
- removal of symlink doesn't impact file it references
- orphan symlink is just a reference to something that no longer exists
### Linux Daemons:
- background programs
- typically created by the init process
- just run by the system with only necessary permissions, away from the active user
- some are started automatically, some are not
- init children processes can be terminated/restarted
### Linux Syslog:
- default log location in linux is /var/log
- facility describes app or process creating the logs
- priority indicates importance of message
- **Transaction Logs:** record all transactions
- **session logs:** track changes made on managed hosts
- **alert logs:** collect errors for startup, shutdown, space, etc.
- **threat logs:** trigger when action matches a security profile attached to security rule
- **selectors:** monitor for combinations of facility and levels and perform an action when combo is found
- **actions:** result of selector triggering on match
- **config file (/etc/syslog.conf):** controls what syslogd does with log entries
	- **Newsyslog:** mitigates management issues by rotating and compressing files
### Apache Access Log Concepts:
- **ErrorLog:** records any errors and any diagnostic info associated with that error to the ErrorLog
- **Access Log:** apache servers record all incoming requests and all requests to access log 
	- combined log format lists access, agent, and referrer fields
## 3.3 Describe the role of attribution in an investigation
### a. Assets
- anything of value to an org
- personnel, software, proprietary knowledge, equipment, hardware, data
### b. Threat actor
- the person or group that carries out an attack
### c. Indicators of compromise
- a piece of evidence that has a high probability of indicating a compromise
- examples (from:https://www.crowdstrike.com/cybersecurity-101/indicators-of-compromise/):
	- Unusual inbound and outbound network traffic
	- Geographic irregularities, such as traffic from countries or locations where the organization does not have a presence
	- Unknown applications within the system
	- Unusual activity from administrator or privileged accounts, including requests for additional permissions
	- An uptick in incorrect log-ins or access requests that may indicate brute force attacks
	- Anomalous activity, such as an increase in database read volume
	- Large numbers of requests for the same file
	- Suspicious registry or system file changes
	- Unusual Domain Name Servers (DNS) requests and registry configurations
	- Unauthorized settings changes, including mobile device profiles
	- Large amounts of compressed files or data bundles in incorrect or unexplained locations
### d. Indicators of attack
- signs/activities that a potential security threat/attack is in progress
- aim to identify/mitigate a threat before it occurs
- examples (from:https://www.crowdstrike.com/cybersecurity-101/threat-intelligence/indicators-of-attack-ioa/):
	- **Anomalous network activities:** IOAs include unusual patterns in data flow or unexpected external communications that deviate from the norm. For example, a sudden spike in data transferred to an unknown IP address could be a red flag. Network administrators need to be vigilant about such anomalies, as they often precede more overt forms of cyberattacks, such as data breaches or system infiltrations.
	- **Suspicious user behavior:** Security teams also need to be on the lookout for activities such as logins at odd hours, repeated attempts to access restricted areas, or an unusual surge in data access requests. These activities might indicate that a user’s account has been compromised or that an insider threat exists.
		- Continuous monitoring of user behavior is essential in identifying these IOAs early. It helps prevent potential insider threats or mitigate the damage caused by compromised user credentials.
	- **System-level indicators:** These IOAs include unexpected changes in file integrity, unauthorized modifications to system configurations, or the installation of unknown software. These indicators often suggest that an attacker is attempting to gain a foothold in the system. Early detection of these system-level changes can prevent further exploitation, stopping an attacker in their tracks.
		- Regular system audits and real-time monitoring are effective strategies for identifying these types of IOAs.
### e. Chain of custody
- from: https://www.geeksforgeeks.org/chain-of-custody-digital-forensics/
- The chain of custody in digital cyber forensics is also known as the paper trail or forensic link, or chronological documentation of the evidence.
- Chain of custody indicates the collection, sequence of control, transfer and analysis.
- It also documents details of 
	- how the evidence was collected, transferred, and stored
	- each person who handled the evidence, 
	- date and time it was collected or transferred, 
	- and the purpose of the transfer.
- It demonstrates trust to the courts and to the client that the evidence has not tampered.
## 3.4 Identify type of evidence used based on provided logs
### a. Best evidence
- the evidence directly proving the offence occurred and can be presented in its original form
### b. Corroborative evidence
- evidence that supports the validity of another piece of evidence
### c. Indirect evidence
- does not inherently prove the offence, but builds the case for guilt beyond a reasonable doubt
## 3.5 Compare tampered and untampered disk image.
- main method for testing for tampering is comparing the stored and computed hash
	- if the two do not match up that means tampering is likely 
- only images with evidence of no tampering can be used as evidence
## 3.6 Interpret operating system, application, or command line logs to identify an event
- check for event ids/logs that line up with known IoCs or IoAs 
## 3.7 Interpret the output report of a malware analysis tool (such as a detonation chamber or sandbox)

### a. Hashes
- use hash of malware file (often SHA256) and use it to see if it is a known hash for a certain malware
### b. URLs
- find the URLs that the malware talks to, can help indicate who threat actors are
### c. Systems, events, and networking
- look at certain system logs, events, and network logs that line up with known IoCs and IoAs.
- sandboxes are great for this as it allows the malware to carry out its actions
	- allows responders to understand what to look for to determine compromise
