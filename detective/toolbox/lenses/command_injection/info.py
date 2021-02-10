category = "Command Injection"

general_info = "Command injection is an attack in which the goal is execution of\n" \
               "arbitrary commands on the host operating system via a vulnerable\n" \
               "application. Command injection attacks are possible when an\n" \
               "application passes unsafe user supplied data\n" \
               "(forms, cookies, HTTP headers etc.) to a system shell.\n" \
               "In this attack, the attacker-supplied operating system\n" \
               "commands are usually executed with the privileges of the vulnerable application.\n" \
               "Command injection attacks are possible\n" \
               "largely due to insufficient input validation.\n"

deep_info = {
    "server_information": "Using the commands whoami or lst in linux terminal\n"
                          "a potential attacker can see information about the server's\n"
                          "system and files.\n",
    "server_sensitive_information": "Using the command uname -s a potential attacker\n"
                                    "can see sensitive information about the\n"
                                    "system of the server.\n",
    "network_information": "Using the ifconfig or ipconfig commands\n"
                           "a potential attacker can see useful information about the server\n"
                           "network and connections.\n",
    "network_statistics": "Using the netstat command, potential attacker can see network\n"
                          "statistics of the server.\n",
    "process_information": "Using the ps command in linux terminal or tasklist command in windows\n"
                           "command line, a potential attacker can see all the running\n"
                           "processes on the server side, and information about them.\n",
    "basic_terminal_commands": "Using ping command, attacker may try to connect to his machine\n"
                               "and by echo attack he may try yo see if he can execute basic commands\n"
                               "on the server side.\n",
    "nslookup": "Using the nslookup command, attacker can reach some ip of unreachable\n"
                "servers or machine, that only the server can reach and ask for their ip.\n",
    "show_sensitive_file": "Using the cat command on sensitive file that exist on etc path\n"
                           "attacker can see sensitive information about the server.\n",
    "netcat_communication": "Using netcat communication, a potential attacker can communicate his\n"
                            "machine, and even pass sensitive data to it.\n",
    "server_running_path": "Using the pwd command on linux terminal, attacker can see the path\n"
                           "which the server is running on.\n",
    "show_file": "Using the cat command in linux terminal, a potential attacker can see\n"
                 "content of file that exists on the server side.\n",
    "server_groups": "Using the id command, a potential attacker can see all the groups\n"
                     "that the server machine is part of them.\n",
    "modify_file": "Using the touch or cp or rm commands in linux terminal\n"
                   "a potential attacker can create, copy or even delete files\n"
                   "that exists on the server machine.\n",
    "delete_file": "Using the rm + flag, a potential attacker can delete all the file\n"
                   "on the server side.\n",
    "sleep_server": "Using the sleep command, a potential attacker can delay\n"
                    "the server response, and check his injection.\n",
    "php_single_char_flag": "Using php with flag commands, a potential attacker can recieve\n"
                            "sensitive and useful information about the php the server\n"
                            "is currently running.\n",
    "php_multiply_char_flag": "Using php with flag commands, a potential attacker can recieve\n"
                            "sensitive and useful information about the php the server\n"
                            "is currently running.\n",
    "php_info": "Using php with flag commands, a potential attacker can recieve\n"
                            "sensitive and useful information about the php the server\n"
                            "is currently running.\n",
    "upload_download_files_from_internet": "Using the wget command, a potential attacker can\n"
                                           "download malicious files on the server, and force the\n"
                                           "server to execute and then he can penetrate the server.\n"
                                           "With the curl command, a potential attacker can send some sensitive\n"
                                           "data from the server, to his local machine.\n"
}

links_for_info = "For more information about Command Injection, check the following links:\n" \
                 "https://owasp.org/www-community/attacks/Command_Injection\n" \
                 "https://portswigger.net/web-security/os-command-injection\n"
