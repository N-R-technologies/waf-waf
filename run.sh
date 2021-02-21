#!/bin/bash
if [ $# -eq 0 ]; then
  read -p 'Enter site url: ' url
  read -p "Enter the port you want to redirect the site's users url: " port
  mitmproxy -p "$port" -m reverse:"$url" -s waf_waf.py
elif [ $# -eq 2 ]; then
    mitmproxy -p "$2" -m reverse:"$1" -s waf_waf.py
else
  echo "Usage: ./run.sh <site's URL> <port of users redirection>"
fi
