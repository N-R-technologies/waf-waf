#!/bin/bash

main()
{
    h_flag="-h"
    help_flag="--help"

    if [ $# -eq 0 ]; then
        read -p "Enter site's URL: " url
        read -p "Enter site's users redirection port: " port
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
    echo "Activates the WAF WAF, your server's watchdog."
    echo "Example: ./run.sh http://localhost 80"
    echo
    echo "When URL is -, read standard input."
    echo "  -h, --help     display this help and exit"
    echo
    echo "Report bugs to: wafdetectivebot@gmail.com"
    echo "Full documentation in the docker at: manual/executing_info.md"
}

main "$@"; exit
