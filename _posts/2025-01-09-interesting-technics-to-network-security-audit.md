---
layout: post
title: "Interesting technics to network security audit"
date: 2025-01-09
---

## Table of Contents
1. [Introduction](#introduction)
2. [Banner Grabbing](#banner-grabbing)
3. [Anonymous Login](#anonymous-login)
4. [Pivoting](#pivoting)

## Introduction
A computer network security audit is a crucial aspect of protecting sensitive data and information, aiming at the integrity of an organization's systems. With the increase in cyber threats, performing security audits has become an indispensable practice for administrators to identify vulnerabilities and strengthen defense against cyber attacks. In this article, we will explore three interesting computer network security audit techniques that can be used to assess and improve the security of a digital environment.

## Banner Grabbing
Banner grabbing is a technique for obtaining information about the states of ports running on the host and the versions of network services. `netcat` is known to be a versatile tool for the purpose of using banner grabbing. The bash one-liner below iterates over the sequence 1 to 100 to go through the first 100 ports of the host address and print the network service protocol version:

```bash
for i in $(seq 1 100); do nc 10.129.1.14 $i -zv; done
```

![Output of netcat one-liner in bash]({{ site.baseurl }}/assets/img/ftp_exploit_vuln.jpg)

**NOTE**: When you specify the `-z` parameter for netcat, the tool will enable TCP/IP port scanning mode. In this mode, netcat will not establish a full connection with the host, but will only check whether the port is open or closed.

**Why try Banner Grabbing?**

Cyber ​​threats often emerge from incorrect configurations in network service protocols, such as open ports and outdated versions. Banner Grabbing provides this information so that network administrators can quickly verify and take security measures.

**Which services should you test Banner Grabbing on?**

- FTP port 20, 21 TCP: Typically used as a file server with anonymous access enabled.
- Telnet port 23 TCP: Typically used for insecure remote access with anonymous access enabled.
- SMB 137, 138 UDP and 139, 445 TCP: Typically used as a network resource share with anonymous access enabled.

**NOTE**: It will not always be possible to establish a successful connection to a host through these ports. As a security recommendation, administrators can configure these services to run on non-standard ports, for example, an FTP file server running on ports 2222 and 3333 instead of 20 and 21. In this case, it is advisable to use port scanning techniques with tools adapted for this purpose.

## Anonymous Login
Anonymous Login is a setting that network administrators often enable to allow a host to be accessed remotely anonymously. This practice is common on internal networks between private addresses, but this approach can open up gaps for an external threat if they gain access to the network infrastructure.

The following command refers to anonymous access in the SMB (Server Menssage Blok) network service protocol for each operating system (Linux and Windows).

```bash
smbclient //host_ip_address/samba_share -U guest # for linux
net use Z: \\host_ip_address\samba_share /user:guest "" # for windows
```

![SMB anonymous login example on linux]({{ site.baseurl }}/assets/img/smb_anonymous_login.png)

**NOTE**: When you provide the username, no password is entered for the login prompt that follows. This is the default for any type of anonymous authentication.

**Why test Anonymous Login?**

The Anonymous Login technique is convenient in network service protocols listed in the Banner Grabbing technique, since they are of particular interest to hackers, since in addition to allowing anonymous authentication, the services themselves have the potential to store important information, such as backup copies, system configuration files, access credentials, among other assets related to the organization's network infrastructure.

## Pivoting
Pivoting is a technique used by hackers to move laterally within an internal network after gaining access to a compromised host. This technique allows the hacker to exploit other devices and services on the network, often bypassing security measures that might be in place, such as access controls.

The following command describes pivoting between hosts on the internal network:

```bash
ssh -L 8080:localhost:80 user@target_host
```

**What's happening?**

- The -L parameter indicates that you are creating a local port forwarding.
- What happens here is that port 8080 on the local machine (where the command is executed) is mapped to port 80 of the localhost address (127.0.0.1) through the target_host.
- This means that, when you access http://localhost:8080, you will actually be accessing the service that is running on port 80 of the target_host address (using he as an intermediary).

![stablish conection with ssh port]({{ site.baseurl }}/assets/img/ssh_local_pivoting.jpg)
![pivoting on http port]({{ site.baseurl }}/assets/img/http_local_pivoting.jpg)

**How is it performed??**

Usualy, pivot runs on organizational network infrastructures to gain access to file servers, applications, or domains. In this process, privilege escalation techniques can be employed to gain administrator permissions while bypassing defense mechanisms. Finally, pivoting can be used to transfer data through tunnels encrypted with proxies, VPN, DNS, and spoofed SSL certificates. This strategy is often used by black hat hackers to make it difficult to detect their attacks.

## Conclusion

All of these techniques combined can help network administrators perform security audits on computer networks to ensure that the correct configurations are in place as per recommended security policies in an organizational network infrastructure.

**Summary**

- **Banner Grabbing**: Banner grabbing is a crucial technique for gathering information about the services and systems running on a network. By identifying software versions and service configurations, an attacker can discover known vulnerabilities and plan targeted attacks. This technique highlights the importance of keeping systems up-to-date and implementing security measures that make it difficult to expose sensitive information, such as service banners. 

- **Anonymous Login**: Anonymous login represents a significant vulnerability in systems that allow access without proper authentication. This technique can be exploited by attackers to gain unauthorized access to critical resources, compromising network security. Implementing strict authentication policies and disabling anonymous logins are essential to protect organizational infrastructure from unwanted access and potential exploits.

- **Pivoting**: Pivoting is a technique that allows an attacker to move laterally within a network after gaining initial access. This ability to infiltrate additional systems can lead to the exposure of sensitive data and the compromise of critical assets. To mitigate the risks associated with pivoting, organizations must adopt effective network segmentation, continuous monitoring, and strict access controls, ensuring that a single point of failure does not compromise the entire infrastructure.

