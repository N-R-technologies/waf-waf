# WAF Project V1.0

![waf logo](logo.png)




![RN|INDUSTRIES](https://cldup.com/dTxpPi9lDf.thumb.png)

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://gitlab.com/magshimim-markez-2021/10/1003/pardes-hana-1003-waf/-/tree/master)

# Summary
The waf is a proxy based waf, that is mean that all the pakcet that are go into
your server are passing through the waf. 
Version 1.0 of the waf project, can protect your server from couple of web attacks:
- SQL Injection
- XXE - XML External Entities
    Our project works with a smart and new detection technology, that achieves 99% of precise answers
    
```mermaid  
graph LR  
A[Client] -- Packet --> B{WAF}
B--A Secure And Harmless Packet-->C[Server]
B--Detect Dangerous Packer--Block The Client-->D(Black List)
```


> There are more versions of the WAF that are 
> gonna publish very soon, wait for it!
> The next versions are going to contain
>- Interactive GUI
>- Internet scanner
>- advanced detection of more web attacks


# Contact
We would love to hear your review about our project!
Contact us in our official mail: [wafdetectivebot@gmail.com](mailto:wafdetectivebot@gmail.com)

### all the rights belong to Noam Mizrahi & Ron Konis