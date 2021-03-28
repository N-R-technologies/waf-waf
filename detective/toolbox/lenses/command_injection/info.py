category = "Command Injection"

general_info = "Command injection is an attack in which the goal is execution of\n" \
               "arbitrary commands on the host operating system via a vulnerable\n" \
               "application. Command injection attacks are possible when an\n" \
               "application passes unsafe user supplied data\n" \
               "(forms, cookies, HTTP headers etc.) to a system shell.\n" \
               "In this attack, the attacker-supplied operating system\n" \
               "commands are usually executed with the privileges of the vulnerable application.\n" \
               "Command injection attacks are possible largely due to insufficient input validation.\n"

deep_info = {
    "server_information": "* Server Information: With using one of the commands 'whoami' or 'ls'\n  "
                          "in linux terminal, a potential attacker can see information\n  "
                          "about the server's system and files.\n",

    "server_sensitive_information": "* Server Sensitive Information: With using the command 'uname -s',\n  "
                                    "a potential attacker can see sensitive information about the\n  "
                                    "system of the server.\n",

    "network_information": "* Network Information: With using the 'ifconfig' or 'ipconfig' commands,\n  "
                           "a potential attacker can see useful information about the server\n  "
                           "network and connections.\n",

    "network_statistics": "* Network Statistics: With using the 'netstat' command, a potential attacker\n  "
                          "can see the network statistics of the server.\n",

    "process_information": "* Process Information: With using the 'ps' command in linux terminal\n  "
                           "or the 'tasklist' command in windows command line, a potential attacker\n  "
                           "can see all the running processes on the server side, and information about them.\n",

    "basic_terminal_commands": "* Basic Terminal Commands: With using the 'ping' command, an attacker\n  "
                               "may try to connect to his machine, and by echo attack, he may\n  "
                               "see if he can execute basic commands on the server side.\n",

    "nslookup": "* nslookup: With using the 'nslookup' command, an attacker can reach ip addresses of\n  "
                "unreachable servers or machines, that only the local server has access to.\n",

    "show_file": "* Show File: With using the 'cat' command in linux terminal, a potential\n  "
                 "attacker can see content of a file that exists on the server side.\n",

    "show_sensitive_file": "* Show Sensitive File: With using the 'cat' command on sensitive file that\n  "
                           "exist on /etc path, an attacker can see sensitive information about the server.\n",

    "netcat_communication": "* netcat communication: With using the 'nc' command, a potential attacker\n  "
                            "can communicate with his machine, and even pass sensitive data into it.\n",

    "server_running_path": "* Server Running Path: With using the 'pwd' command on linux terminal,\n  "
                           "an attacker can see the path which the server is running on.\n",

    "server_groups": "* Server Groups: With using the 'id' command, a potential attacker can\n  "
                     "see all the groups that the server machine is a part of them.\n",

    "modify_file": "* Modify File: With using the 'touch', 'cp' or 'rm' commands in linux terminal,\n  "
                   "a potential attacker can create, copy or even delete files\n"
                   "that exists on the server machine.\n",

    "delete_file": "* Delete File: With using the 'rm' commands with flags, a potential\n  "
                   "attacker can delete all the files on the server side.\n",

    "server_sleep": "* Server Sleep: Using the 'sleep' command, a potential attacker can delay\n  "
                    "the server response, and check his injection.\n",

    "php_single_char_flag": "* PHP Single Character Flag: With using PHP flag commands, a potential\n  "
                            "attacker can receive sensitive and useful information about\n  "
                            "the PHP the server is currently running.\n",

    "php_multiple_char_flag": "* PHP Multiple Character Flag: With using PHP flag commands, a potential\n  "
                              "attacker can receive sensitive and useful information about\n  "
                              "the PHP the server is currently running.\n",

    "php_info": "* PHP Info: With using PHP flag commands, a potential attacker can receive\n  "
                "sensitive and useful information about the PHP the server is currently running.\n",

    "upload_download_internet_files": "* Upload/Download Internet Files: With using the 'wget' command, a potential\n  "
                                      "attacker can download malicious files on the server, and force\n  "
                                      "the server to execute them. With the 'curl' command, he can send\n  "
                                      "sensitive data from the server, to his local machine.\n"
}

links_for_info = "For more information about Command Injection, check the following links:\n" \
                 "https://owasp.org/www-community/attacks/Command_Injection\n" \
                 "https://portswigger.net/web-security/os-command-injection\n"
