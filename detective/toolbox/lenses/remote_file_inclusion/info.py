category = "Remote File Inclusion"

general_info = "Remote file inclusion (RFI) is an attack targeting vulnerabilities in\n" \
               "web applications that dynamically reference external scripts.\n" \
               "The goal of the attack is to exploit the \n" \
               "referencing function in an application to upload malware\n" \
               "(e.g. backdoor shells) from a remote URL located within a different domain.\n" \
               "When the attacker uploads the script to the server, this script can\n" \
               "harm the server in different ways:\n" \
               "1. Harm the website, malware is installed and the pages are defaced or deleted.\n" \
               "2. Harm the server, make him acts like a DDos bot.\n" \
               "3. Harm the database of the server, steal sensitive data.\n" \
               "Remote file inclusion attacks usually occur when an application\n" \
               "receives a path to a file as input for a web page and\n" \
               "does not properly sanitize it. This allows an external\n" \
               "URL to be supplied to the include function.\n"

deep_info = {
    "include_site": "* Include Site: An attacker tried to include other\n  web site in the URL, in order to "
                    "inject your server a malicious code.\n",

    "q_mark_after_url": "* A '?' After the URL: An attacker tried to inject your\n  server with ending with "
                        "question mark. This question mark,\n  like a comment, disable everything comes after it.\n",

    "off_site_url": "* Off Site URL: A potential attacker can enter to the server's\n  parameter a "
                    "URL or even an IP address which leads to a malicious code.\n",

    "malicious_file_injection": "* Malicious File Injection: An attacker can use RFI\n  in order to inject to "
                                "your database malicious files.\n"
}

links_for_info = "For more information about Remote File Inclusion, check the following links:\n" \
                 "https://www.zaproxy.org/docs/alerts/7/\n" \
                 "https://www.imperva.com/learn/application-security/rfi-remote-file-inclusion/"
