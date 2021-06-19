# WAF WAF V1.1
<div align="center">
![waf waf logo](misc/logo.png)
</div>

# Summary
WAF WAF is an open-source advanced web application firewall that works with a smart and new detection technology, achieving 99% of precise answers!<br>
With an interactive CLI you can easily scan weaknesses on your local network, configure WAF WAF, and see what is happening on your server.

## Installation
You are able to use WAF WAF from both, your local machine and [docker](https://docs.docker.com/).

### Local Machine
After downloading WAF WAF, you first need to run the following command to install requirements:
```bash
pip install -r requirements.txt
```
After running the command, you will be able to run WAF WAF.

### Docker
Use the following command to install WAF WAF from docker:
```bash
docker pull wafwafdetective/waf_waf:V1.1
```

## Usage
Can be found in the [WAF WAF Manual](https://gitlab.com/magshimim-markez-2021/10/1003/pardes-hana-1003-waf/-/blob/fifth_sprint/manual/manual.md).<br>
The manual is also installed with WAF WAF at `waf_waf/manual/manual.md`.

## Features & Technology
At the end of each day, an email attached with a detailed log will be sent, containing information about all the attempted attacks on the server.<br>

WAF WAF Version 1.1 is capable of protecting servers from the following attacks:
- Brute Force
- Command Injection
- File Inclusion
- SQL Injection
- XSS
- XXE

## Flow
```mermaid
graph LR

Client--Request-->WAF{WAF WAF}
WAF--Secured and Harmless Request-->Server
WAF--Malicious Request-->D&B(Drop Request & Block Connection)
```

## WAF WAF Notifications
Information about the different notifications can be found in the WAF WAF manual.<br>
If using WAF WAF on your local machine, the notifications are already installed.<br>
If using docker, you may download an extension on your local machine that will display the notifications.<br>
On top of that, you may also download icons that will make the notifications more interactive.<br>
Click [here](https://drive.google.com/drive/folders/11Bm9YtwWrHXmXJhasSBlUgZx7g0BBXRN?usp=sharing) to download the notifications. If downloaded, make sure to place the icons folder in the same path as the notifications server file.<br>

## WAF WAF Automation
Still not convinced WAF WAF is the best?<br>
Click [here](https://drive.google.com/drive/folders/1pBd6fWv1kkBuKZqtJfThHg1Jn0sRj42d?usp=sharing) to download a VM we have made for you, showing what WAF WAF can really do.

# Contact
We would like to hear reviews about WAF WAF!<br>
Contact us at [wafdetectivebot@gmail.com](mailto:wafdetectivebot@gmail.com).

### All rights reserved to our developers, Noam Mizrahi & Ron Konis
