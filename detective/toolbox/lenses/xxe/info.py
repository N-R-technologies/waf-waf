category = "XXE"

general_info = "XXE (XML External Entities) attack can occur when your application " \
               "accepts any\nkind of xml parsing and input from the user.\nXXE may lead to:\n" \
               "* Disclosure of confidential data.\n* Denial of service (DOS).\n" \
               "* Server-side request forgery (SSRF).\n* Port scanning from the perspective " \
               "of the machine where the parser is located.\n* Other system impacts.\n"

deep_info = {
    "data_disclosure": "* Data Disclosure: It seems like some attacker tries to retrieve some data "
                       "from you.\n  It can happen when the attacker creates an entity inside the xml request, "
                       "and then the parser\n  returns the entity's value to the screen.\n  Unfortunately, "
                       "the value of the entity can be a file from your local machine.\n",

    "billion_laughs": "* Billion Laughs: It seems like some attacker tries to allocate potentially endless "
                      "variables into\n  your system memory. The purpose of this action is to overtake your\n  "
                      "system memory and to shutdown your local machine.\n",

    "endless_file": "* Endless File: It seems like some attacker tries to allocate potentially endless "
                      "file into\n  your system memory. The purpose of this action is to overtake your "
                      "system memory\n  and to shutdown your local machine.\n",

    "xinclude": "* XInclude: A part of the XML specification that allows you to create an XML document from nested\n "
                "documents. Unfortunately, if you see this, you should know that someone tried to specify a "
                "local\n  system file, hence retrieve the file.\n",

    "svg_uploading": "* SVG Uploading: Some sneaky user tried to attack you with regular XXE via uploading svg image.\n",

    "base64_encoded": "* Base64 Encoded: Someone tried to encode files with base64 "
                      "on your server and then retrieve them on\n  the receiving end.\n",

    "utf7": "* UTF-7: UTF-7 is an encryption type that can help the attacker to hide is attack.\n  "
            "Luckily, our WAF can detect this kind of encryption and block the request.\n",

    "xxe_comment": "* XXE Comment: For themselves, comments are not dangerous in any kind of attack.\n  But if you see "
                   "this message, probably there are not the only thing the user put on his malicious\n  packet. "
                   "This is another sign that the packet is dangerous.\n",

    "blind_xxe": "* Blind XXE: Just like a simple XXE attack, but unlike the regular attack it results with "
                 "the\n  server sending the data to the hacker's machine instead of displaying it on the screen.\n",

    "inject_file": "* Inject File: The user tries to inject the server side a code containing malicious file\n  "
                   "or program in the request.\n"
}

links_for_info = "For more information about XXE, check the following links:\n" \
                 "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing\n" \
                 "https://portswigger.net/web-security/xxe"
