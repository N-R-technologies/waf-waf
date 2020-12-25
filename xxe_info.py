links_for_info = "For more information about XXE, check the following links:\n" \
                 "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing\n" \
                 "https://portswigger.net/web-security/xxe"

general_info = "XXE (XML External Entities) attack can occur when your application " \
               "accepts any kind of xml parsing and input from the user.\nXXE may lead to:\n" \
               "* Disclosure of confidential data.\n* Denial of service (DOS).\n" \
               "* Server-side request forgery (SSRF).\n* Port scanning from the perspective " \
               "of the machine where the parser is located.\n* Other system impacts."

deep_info = {
    "data_disclosure": "* Data Disclosure: It seems like some attacker tries to retrieve some data "
                       "from you.\n  It can happen when the attacker creates an entity inside the xml request, "
                       "and then the parser returns the entity's value to the screen.\n  Unfortunately, "
                       "the value of the entity can be a file from your local machine.\n",

    "blind_xxe": "* Blind XXE: Just like a simple XXE attack, but unlike the regular attack it results with "
                 "the server sending\n  the data to the hacker's machine instead of displaying it on the screen.\n",

    "billion_laughs": "* Billion Laughs: It seems like some attacker tries to allocate potentially endless "
                      "variables into your system memory.\n  The purpose of this action is to overtake your "
                      "system memory and to shutdown your local machine.\n",

    "endless_file": "* Endless File: It seems like some attacker tries to allocate potentially endless "
                      "file into your system memory.\n  The purpose of this action is to overtake your "
                      "system memory and to shutdown your local machine.\n",

    "xinclude": "* XInclude: A part of the XML specification that allows you to create an XML document from nested "
                "documents.\n  Unfortunately, if you see this, you should know that someone tried to specify a "
                "local system file, hence retrieve the file.\n",

    "svg_uploading": "* SVG Uploading: Some sneaky user tried to attack you with regular XXE via uploading svg image.\n",

    "base64_encoded": "* Base64 Encoded: Someone tried to encode files with base64 "
                      "on your server and then retrieve them on the receiving end.\n",

    "xxe_comment": "* XXE Comment: For themselves, comments are not dangerous in any kind of attack.\n  But if you see "
                   "this message, probably there are not the only thing the user put on his malicious packet. "
                   "This is another sign that the packet is dangerous.\n",

    "utf7": "* UTF-7: UTF-7 is an encryption type that can help the attacker to hide is attack.\n  "
            "Luckily, our WAF can detect this kind of encryption and block the request.\n",

    "inject_file": "* Inject File: The user can inject the server side a code containing malicious file or program\n  "
                   "in the xml request.\n"
}
