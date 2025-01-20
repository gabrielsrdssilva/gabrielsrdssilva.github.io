---
layout: post
title: "Most common cyberattacks to web applications"
date: 2025-01-19
tag: study
---

## Table of contents
1. [Introduction](#introduction)
2. [Discovery content](#discovery-content)
3. [Injection](#injection)
4. [Broken](#broken)
5. [Final considerations](#final-considerations)
6. [Conclusion](#conclusion)

## Introduction
Web applications have become vital in internet communication today. Websites often store large amounts of their users' data, so attacking hackers target specific components and features of these frameworks.

We'll show you the most common cyberattacks that can put user and organizational data and information at risk. We will carry out some attacks from the perspective of cybercriminals, but understand that to work as a professional in the field of cybersecurity, you must understand the mindset of your adversary.

> **WARNING**: The targets tested in this article are part of the HackerOne platform's bug bounty program. Testing was conducted in accordance with the program guidelines, the standards set by the platform, and the scope determined by the target owners. Penetration testing without authorization is illegal and unethical, so I do not encourage the performance of any of these techniques outside the professional scope. I thank you all for your understanding.

## Discovery content
Content discovery is a technique classified in the category of reconnaissance attack that aims to obtain information from a target for the strategic, tactical, and operational planning of more complex cyberattacks, such as injection and cracking, which we will see later in this article. 

**Enumeration**

Enumeration is a branch of the content discovery technique that aims to discover the resources that make up a web application, usually credentials, directories, and other resources common in Internet web applications. It is also possible to find vulnerability payloads to perform targeted injection attacks on specific web application components, such as parameters and forms. 

The `gobuster` is the tool most used by attacking hackers to perform the enumeration technique. Gobuster is a program written in golang that automates enumerations of different resources of a web application, as well as cloud resources such as buckets and virtual machines.

```bash
gobuster dns -d target_dns -w /path/to/wordlist # Sub domain enumeration
gobuster dir -u target_url -w /path/to/wordlist # Sub directory enumeration
```

![use gobuster to enumerate subdomains of target]({{ site.baseurl }}/assets/img/gobuster_dns_enum_subdomains.png)
![use gobuster to enumerate subdirectory of web application server]({{ site.baseurl }}/assets/img/gobuster_http_enum_subdirectory.png)

**Others contents**

- Headers: Web application headers can contain information such as session cookies, user agents, server versions, and custom headers that prevent exploitation of vulnerabilities such as Cross-Site Scripting (XSS), Cross-Origin Resource Sharing (CORS), and Clickhijacking (represented by the X-Frame-Options header). 
- Cookies: Session cookies can be tracked and monitored with more advanced tools such as Burpsuite to test entropy and other security issues in users' navigation in a web application.

## Injection
An injection attack is a flaw in the source code of a web application that allows users to execute malicious code on the client side that will be arbitrarily interpreted on the server side. The flaw in the source code that opens the door to this type of attack is due to the lack of sanitization and cleanliness in data entry, allowing any command to be executed on the server system. 

**Insecure Design**

Although injection failures are fixed through package dependencies and frameworks specific to the programming languages in use in the web application, it is quite common for injection failure to happen through the insecure design that the website is using in the backend. The example below shows a query in the SQL database being executed insecurely with PHP: 

```php
<?php
// Connecting to the MySQL database service
$conn = new mysqli($servername, $username, $password, $dbname);

// Checking connection
if ($conn->connect_error) {
    die("Conection failure: " . $conn->connect_error);
}

// Querying the database without sanitization
$username = $_POST['username'];
$password = $_POST['password'];
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    echo "Login Welcome!";
} else {
    echo "Invalid username or password.";
}

$conn->close();
?>
```

> **NOTE**: In addition to PHP, other backend programming languages such as Node.js and Python can expose injection vulnerabilities depending on the web application framework in use. It is important to ensure that all package dependencies are met and that the framework version has no known vulnerabilities.

**SQL Injection**

SQL (Structured Query Language) is a markup language used to interact with database components, as well as to manipulate and manage management systems (DBMS) resources. SQL injection is considered to be the most impactful vulnerability in a web application, because when the system is compromised, attacking hackers can take advantage of the following assets: 

- Access credentials: Usernames, passwords, emails, and phone numbers can be dumped from the database and used in password attacks, e.g., brute force and rainbow table. See the case of a data leak from [RockYou](https://en.wikipedia.org/wiki/RockYou) that originated the list of words [rockyou.txt](https://github.com/zacheller/rockyou), popularly used in credential guessing techniques. 
- System access information: Session tokens and API keys can be dumped from the database and used by attacking hackers in other procedures, e.g., denial of service (DoS), privilege escalation, attack on supply chains, and cyberattack automations. 
- Personal Identity Information (PII): Financial, medical, and educational information can be dumped from the database and used by attacking hackers in identity thefts to perform phishing and social engineering.

`sqlmap` is the most conventional tool used by attackers to perform reconnaissance and exploit injection vulnerabilities. As an example, I'll use sqlmap to perform the reconnaissance attack and discover potential attack vectors in the parameters of the target URL to test SQLI payloads.

![use nmap to discovery mysql service running on web application server]({{ site.baseurl }}/assets/img/nmap_mysql_scan_port.png)
![use sqlmap to crawl url target and reconnaissance potentials attack vectors]({{ site.baseurl }}/assets/img/sqlmap_mysql_crawl_url.png)

> **WARNING**: It is worth remembering that before performing any exploitation of vulnerabilities in bug hunting and vulnerability disclosure programs, always check the scope of the program and see if such a vulnerability can be exploited. Automated tools for injection vulnerability exploits can cause irreversible damage to the target web application. The guidelines of platform programs that offer bug bounty hunting and vulnerability disclosure repudiate this performance. For this reason, it is recommended not to use these and other invasive automated security testing tools for the sole purpose of compromising the target's systems

**Others injections**

- RCE/LFI: Injection of arbitrary client-side commands that are misinterpreted on the server side. Linux commands are usually ones that attacking hackers usually execute by exploiting this type of vulnerability, as most web application servers run GNU/Linux as the default operating system. 
- XXE: XML data manipulation, markup digitization often used in system configurations. XXE involves modifying XML entities, allowing attacking hackers to access system files or execute code remotely, depending on the settings applied on the server system. 
- XSS: Dynamic code injection into the web application. Javascript language programming is used in dynamic code injections and is often accompanied by clickhijacking and defigurement, attacks that can be carried out with political and/or religious motivations from a cybercriminal group or individual.

## Broken
Broken refer to the alternative methods that attacking hackers find to exploit authentication mechanisms and access controls in network service protocols. In web applications particularly, it is common for these attacks to be accompanied by passive/active reconnaissance attacks, which use strategic techniques to gather information from the target, as well as advanced tactics to hide malicious activity from the attacking hackers, usually proxies and decoys.

The combination of both attacks becomes a weapon of war for cybercriminals to carry out cyberattacks with greater impacts on a web application. This line drawn by attacking hackers aims to compromise systems and/or website user accounts, so it is of special importance that information security analysts identify patterns that correspond to these actions of cybercriminals and apply proactive security measures to protect the data and information of users and the organization, respectively.

**Web Crawl**

The web crawling technique is classified in the passive reconnaissance attack category and exploits the web application's broken access control vulnerability, as it seeks to find specific locations and fields on the website that could reveal sensitive information to attackers. 

The `Burpsuite` shown earlier in the injection technique, is a graphical user interface (GUI) tool that has extremely efficient functionalities to perform web crawling, as well as site mapping, link redirection and session cookie tracking. While Burpsuite is a tool for web application security auditing professionals, attacking hackers can benefit from its capabilities to plan more efficient and complex cyberattacks.

![use foxyproxy extension to redirect web browser requests for burpsuite proxy]({{ site.baseurl }}/assets/img/firefox_http_forward_proxy.jpg)

**Web Scraping**

Web scraping is a technique classified in the category of active reconnaissance attack, and depending on the security settings applied on the server of the target web application, it can exploit the vulnerability of broken access control, as well as misconfigurations and information disclosure, as some vulnerable web applications allow users to scrape sensitive data from the website, which in many cases is caused by incorrect settings. 

`wget` and `grep` are utility tools of the GNU/LINUX operating system that can be used in conjunction with extracting data from a web application. In the example below, we are using wget recursively to pull a website and its respective pages, we are also using grep recursively to filter the content corresponding to personal information identity (PII):

```bash
wget https://www.exemplo.com -P site -r -l 2 --no-parent --no-verbose
grep -E -r -f pii.txt -o site 
```

![Use wget to extract content discovery data and use grep to filter discovered content]({{ site.baseurl }}/assets/img/gnu_http_scrapy_url.png)

> **HINT**: Other GNU/LINUX utility tools, such as find, tail, awk, sed, can be used to filter content in files. There are many patterns for discovering sensitive content on websites. The [FuzzDB](https://github.com/fuzzdb-project/fuzzdb/tree/master/regex) project can be an interesting feature in this case.

**Spraying**

Password spraying is a technique classified in the category of password cracking attack and exploits authentication mechanisms in network service protocols. Password spraying usually uses simple combinations to carry out its attacks, such as emails and usernames, however, this technique aims to find out the password security policies in place in the target network service protocol to generate word lists with custom passwords.

`cewl` is a tool that collects login data such as email and username in content discovered in the web app. In more specific cases, `crunch` can also be used to generate a standardized wordlist according to the website's current password security policy. For now, we will use cewl to collect login data and crunh to make padronize wordlist 

![use cewl to scrapy data and crunch to generate padronized wordlist]({{ site.baseurl }}/assets/img/cewl_http_scrapy_url.png)

> **HINT**: Password spraying can also be performed manually using default passwords. Usually, in content management systems like WordPress, administrators can misconfigure the site by exposing the admin panels in /admin, /login or /wp-admin, in addition, default passwords with weak policies can also be set. In this case, the spraying technique can come into play with default passwords commonly used or provided by these systems...

**Brute Force**

The difference between brute force and spraying is that the targets vary, for example, spraying aims to compromise users' passwords, while brute force aims to compromise both. Therefore, brute force, in general, tries several possible user/password combinations using more invasive iteration modes. 

> **NOTE**: Due to the high resource consumption, attacking hackers often use proxie chains or zombie machines to use brute force, either to hide the source of their activities or to consume the host's operational resources.

Since the target scope of the bug bounty program prevents exploitation of the cracked authentication vulnerability, we will run the tests of the tools on our personal local server, we are using the following authentication logic:

```py
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

ADMIN = "support@acme.com"
LOGIN = "letmein"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == ADMIN and password == LOGIN:
            flash("Success")
            session["logged_in"] = True
            return redirect(url_for("admin"))
        else:
            flash("Invalid username or password")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/admin")
def admin():
    if not session.get("logged_in"):
        flash("You must be logged in to access this page")
        return redirect(url_for("login"))
    return render_template("admin.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    flash("You have been dismissed from the session")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
```

The `ffuf` can perform brute force in both Clusterbomb and Pitchfork iteration modes. Learn more about these modes [here](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/attack-types). ffuf is a fuzzing tool for testing input data in web applications, as well as headers, parameters, and forms. In our case, we will audit the authentication mechanism of our web application by forwarding all requests from ffuf to Burpsuite Proxy. 

![Use ffuf with the retry proxy option to forward retries of brute-force requests in the authentication mechanism]({{ site.baseurl }}/assets/img/ffuf_http_forward_proxy.jpg)
![Use Burpsuite Proxy to capture and analyze server responses as requests from ffuf are forwarded to the proxy]({{ site.baseurl }}/assets/img/burpsuite_http_forward_proxy.jpg)

> **HINT**: Burpsuite Intruder also allows you to brute-force web applications more efficiently. Using some ffuf strategies such as the replay proxy, it is possible to audit passwords and web applications manually, which in my opinion is much better. However, be aware of brute force techniques, as they often take a long time to validate a username/password combination. For this reason, try not to use lists of words that are too long so that the security auditing process on web applications or passwords takes less.

**Others breaks**

Exploits related to vulnerabilities in brokens web application are difficult to detect, and audits require appropriate methods and strategies. The above techniques and technologies can be used by both cybersecurity professionals and cybercriminals. The following vulnerabilities also exploit the breach in access control: 

- IDOR: Occurs when an app allows users to access objects directly through references (such as IDs/UUIDs) without verifying that the user has permission to access them. ffuf can be used to test token and UUID payloads on web application parameters. 
- CSRF: Occurs when a malicious link forwarded by a third party hijacks the session cookie in the user's browser. Burpsuite can be used to analyze cookie entropy from cross-site sessions. In addition to Burpsuite, 'BeFF' is also commonly used for CSRF/XSRF exploits. 
- SSRF: Occurs when an application allows an attacker to make HTTP requests from the application's server. ffuf can be used to test URL payloads in web application headers and, with recursion strategies, forward requests to Burpsuite Proxy and manually parse server-to-server redirection based on the responses returned in the web application header.

## Final considerations

1. Content discovery:
    - Secure server configuration: Ensure that your server configuration is adequate to prevent the exposure of sensitive directories and files. Use `.htaccess` files or server configurations and content management systems to restrict access to unauthorized areas.
    - Input validation: Implement strict input validation in your web application source code to prevent malicious users from accessing unauthorized information through URL or parameter manipulation.

2. Injections:
    - Use of parameterized queries: Whenever possible, use parameterized queries or ORM (Object-Relational Mapping) to interact with databases, avoiding SQL injection. 
    - Data filtering and escaping: Properly filter and escape all input data, especially data that will be processed as commands or queries, to prevent code injections.

3. Broken:
    - Implement multi-factor authentication (MFA): Adopt multi-factor authentication to add an extra layer of security, making unauthorized access more difficult even if user credentials, such as email and password, are compromised.
    - Permission review: For administrators, perform regular audits of access permissions, ensuring that users only have the privileges required for their roles. Implement the principle of least privilege wherever possible.
    - Activity monitoring and logging: Establish a monitoring system to record suspicious activity and respond quickly to unauthorized access attempts.

## Conclusion
Cyberattacks against web applications may seem endless, but there's good news: a few simple security measures can prevent attackers from exploiting the vulnerabilities presented in this article. Always be vigilant about threats and their attacks to learn how to defend yourself from the tactics, techniques, and procedures that accompany them.

**Summary**

1. **Discovery Content**: Enumerations in web applications are the first step for attackers to discover content on the website, usually features and components that open security holes in the website that allow attackers to expand their exploits into vulnerabilities.

2. **Injection**: Injections in web applications are the second step for attackers to exploit holes discovered with enumeration techniques performed in the previous step (reconnaissance attack). Here, code payloads and computer commands are tested against data inputs from the website and in case of insecure design, database leaks can expose sensitive user information.

3. **Broken**: Cracking of web applications can involve reconnaissance attacks and the cracked web application.
    * Reconnaissance: Crawling and data scraping are performed by attackers to gather information about potential assets in the web application. 
        - Active: Operational tactics are used to gather intelligence about technologies and other sensitive information of particular interest for attackers to exploit. 
        - Passive: Methods and strategies are used to stealthily collect sensitive information from web application targets. More advanced tactics are often used to hide malicious, suspicious, and/or anomalous activity from attacking hackers, making it harder for cybersecurity analysts to identify them.
    * Cracked: Attacking hackers generate standardized wordlists to brute force and spray passwords targeted at web application targets or their users.
        - Authentication: Attacking hackers use the data collected and analyzed in the reconnaissance attack to guess valid access credentials for host systems or user accounts.
        - Access control: Attacking hackers use the information collected and analyzed in the reconnaissance attack to discover data entries in the web application that are vulnerable to injection attacks.
