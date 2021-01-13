category = "remote file inclusion"

general_info = "Remote file inclusion (RFI) is an attack targeting vulnerabilities in\n"\
               "web applications that dynamically reference external scripts.\n"\
               "The goal of the attack is to exploit the \n"\
               "referencing function in an application to upload malware\n"\
               "(e.g., backdoor shells) from a remote URL located within a different domain.\n"\
               "when the attacker uploaded the script to the server, this script can \n"\
               "harm the server in a couple ways:\n"\
               "a. harm the website, malware is installed and the pages are defaced or deleted.\n"\
               "b. harm the server, make him to act like DDos bot.\n"\
               "c. harm the database of the server, steal sesitive data.\n"\
               "Remote file inclusion attacks usually occur when an application\n"\
               "receives a path to a file as input for a web page and \n"\
               "does not properly sanitize it. This allows an external\n"\
               "URL to be supplied to the include function.\n"

deep_info = {
    "include_site": "The attacker tried to include some other site in the url, in order to\n"
                    "inject your server with malicious code\n",
    "q_mark_after_url": "The attacker tried to inject your server with ending with question mark\n"
                        "this question mark, like a comment, disable everything comes after it\n",
    "off_site_url": "A potential attacker can enter to the parameter to the server, some\n"
                    "url to malicious code, or even ip address\n",
    "malicious_file_injection": "Attacker can use rfi, in order to inject to your database\n"
                                "some malicious file\n"

}

links_for_info = "For more information about remote file inclusion, check the following links:\n" \
                 "https://www.zaproxy.org/docs/alerts/7/\n" \
                 "https://www.imperva.com/learn/application-security/rfi-remote-file-inclusion/\n"
