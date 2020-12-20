class SqlInjectionInfo:
    """the purpose of the class is to give the user much more information about the attack, for the daily log"""
    _links_for_info = "for more information about the attack, check this links:\nhttps://owasp.org/www-community/attacks/SQL_Injection\n" \
                     "https://portswigger.net/web-security/sql-injection"
    _general_info = "SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.\n" \
                    "It generally allows an attacker to view data that they are not normally able to retrieve.\n" \
                    "also with this atttack the attacker can modify the database or even inject some malicious code to\n"
    _deep_info = []

    def information_disclosure_info(self):
        self._deep_info.append("if you get this message, it seems like some attacker tries to get from you some data\n" \
                    "it can happen when the attacker create an entity inside the xml request, so the parser\n" \
                    "will return this entity to the screen, unfortunately, this entity can be a file from your server machine\n")

    def blind_xxe_info(self):
        self._deep_info.append("if you get this message apparently some hacker or bad user tries to get some of your files from your\n" \
                    "server computer. bind xxe it just like a simple xxe attack, but unlike the regular attack, the result\n" \
                    "of this attack the website doesn't represent to the screen, but send it to the hacker's machine\n")

    def xxe_comment_info(self):
        self._deep_info.append("for themselves comment are not dangerous in any kind of attack, but if you see this message\n" \
                                "probably there are not the only thing the user put on his malcious packet. this is another"
                                "sign that the packet is dangerous")

    def get_info(self):
        return "General information: " + self._general_info + "More info: " + ''.join(self._deep_info) + self._links_for_info

    def set_attack_info(self, risk_name):
        switcher = {
            "xxe_information_disclosure": self.information_disclosure_info,
            "blind_xxe": self.blind_xxe_info,
            "xxe_comment": self.xxe_comment_info
        }
        switcher[risk_name]()
