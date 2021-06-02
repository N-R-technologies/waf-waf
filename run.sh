#!/bin/bash

main()
{
    h_flag="-h"
    help_flag="--help"

    cd waf_waf
    if [ $# -eq 0 ]; then
        read -p "Enter site's URL: " url
        read -p "Enter users accessing port: " port
        mitmproxy -p "$port" -m reverse:"$url" -s waf_waf.py
    elif [ $# -eq 2 ]; then
        mitmproxy -p "$2" -m reverse:"$1" -s waf_waf.py
    elif [ "$1" = "$h_flag" ] || [ "$1" = "$help_flag" ]; then
        print_help
    else
        echo "Invalid option."
        echo "Try './run.sh --help' for more information."
    fi
}

print_help()
{
    echo "Usage: ./run.sh <URL> <PORT>"
    echo "Starts WAF WAF, the servers watchdog."
    echo
    echo "Examples:"
    echo "./run.sh localhost:7777 7891"
    echo "./run.sh http://localhost:80 1234"
    echo
    echo "When URL is -, read standard input."
    echo "  -h, --help     Display this message and exit."
    echo
    echo "Report bugs to: wafdetectivebot@gmail.com."
    echo "Full documentation in the docker at: waf_waf/manual/manual.md."
}

main "$@"; exit
