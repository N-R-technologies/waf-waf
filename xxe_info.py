links_for_info = "For more information about XXE, check the following links:\n" \
                 "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing\n" \
                 "https://portswigger.net/web-security/xxe"

# TODO: add information to the general
general_info = "XXE (XML External Entities) attack can occur when your application " \
               "accepts any kind of xml parsing and input from the user.\nXXE may lead to:\n" \
               "* Disclosure of confidential data\n* Denial of service (DOS)\n" \
               "* Server-side request forgery (SSRF)\n* Port scanning from the perspective " \
               "of the machine where the parser is located\n* Local system shutdown\n* Other system impacts"

deep_info = {
    "information_disclosure": "If you get this message, it seems like some attacker tries to get some data from you.\n" \
                              "It can happen when the attacker create an entity inside the xml request, so the parser " \
                              "will return this entity to the screen. Unfortunately, this entity can be a file from your local machine\n",

    "blind_xxe": "If you get this message apparently some hacker or bad user tries to get some of your files from your" \
                 "local computer. Bind XXE is just like a simple XXE attack, but unlike the regular attack it results" \
                 "with the server sending the data to the hacker's machine instead of displaying it on the screen\n",

    "xxe_comment": "For themselves, comment are not dangerous in any kind of attack, but if you see this message, " \
                   "probably there are not the only thing the user put on his malicious packet. This is another" \
                   "sign that the packet is dangerous\n",

    
    "billion_laughs": "If you get this message, it seems like some attacker tries to allocate \"billion\" variables " \
                      "into your system memory\nThe purpose of this action is to overtake your system memory and to " \
                      "shutdown your local machine."
}
