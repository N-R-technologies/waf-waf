# **This file is very important to read before installing and running the WAF project**
## Summary
The program makes her own ip tables rules when it start and close, just like that, it directs all the packet
in your computer to move through the queue, and when you close it, it automatically delete the new ip table rule it created before
and then, your transportation doesnt move through the waf anymore.
