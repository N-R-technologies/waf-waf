class SqlInjectionInfo:
    """the purpose of the class is to give the user much more information about the attack, for the daily log"""
    _links_for_info = "for more information about the attack, check this links:\nhttps://owasp.org/www-community/attacks/SQL_Injection\n" \
                     "https://portswigger.net/web-security/sql-injection"
    _general_info = "SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.\n" \
                    "It generally allows an attacker to view data that they are not normally able to retrieve.\n" \
                    "also with this atttack the attacker can modify the database or even inject some malicious code to\n"
    _deep_info = []
    """all the functions below add to the _deep_info list, the specific info about each attack that the 
    detector detect. for example, write_into_outfile_info add to _deep_info the information about
    the write into file function"""
    def find_master_access_info(self):
        self._deep_info.append("master is a scheme table that contains all the informations, values and indexes about the\n"
                               "table. the attacker can prepare his attack with getting some information about the database\n")

    def user_disclosure_info(self):
        self._deep_info.append("the user table is a global table in every mySql database, so we make sure the attacker"
                               "doesn't try to access it and get the information about the users\n")

    def mongo_db_command_info(self):
        self._deep_info.append("the attacker may use some of the common commands in mongoDB, that are not so\n"
                               "frequent, so it is suspicious he use this characters\n")

    def cstyle_comment_info(self):
        self._deep_info.append("the user is trying to add some Cstyle comments into your sql query maybe in order\n"
                               "to delete the info after the comments")

    def blind_benchmark_info(self):
        self._deep_info.append("blind sql injection are the type that doesn't shown screen, attacker\n"
                               "can reach this goal by the benchmark function which make a delayed response only\n"
                               "if the injection succeed. also he doesnt need high privileges for that\n")

    def load_file_disclosure_info(self):
        self._deep_info.append("load file function generally Reads the file and returns the file contents as a string\n"
                               "it can be harmful when the user load some important file and then select it with a\n"
                               "regular query\n")

    def load_data_disclosure_info(self):
        self._deep_info.append("The LOAD DATA statement reads rows from a text file into a table\n"
                               "attacker can use this function in order to inject some malicious script into the database\n")

    def write_into_outfile_info(self):
        self._deep_info.append("this function writes the selected rows to a file, so the attacker can write some\n"
                               "parts of the database to a specific file and then some how take it\n")

    def blind_sql_sleep_info(self):
        self._deep_info.append("with this function the attacker can delayed the server's response and see if his\n"
                               "injections work")

    def concat_command_info(self):
        self._deep_info.append("the concat command is another way for the attacker to check if his injection can work\n"
                               "this command is basically concat couple of strings together into one string\n")

    def information_disclosure_info(self):
        self._deep_info.append("INFORMATION_SCHEMA provides access to database metadata.\n"
                               "with this function the attacker can see all the information about the MySQL server such as the name of a database or table, the data type of a column, or access privileges.\n")

    def sleep_pg_command_info(self):
        self._deep_info.append("with this function the attacker can delayed the server's response and see if his\n"
                               "injections work")

    def blind_tsql_info(self):
        self._deep_info.append("with this function the attacker can delayed the server's response and see if his\n"
                               "injections work\n")

    def substr_command_info(self):
        self._deep_info.append("the substr function is not so dangerous for its self, but generally it parse the string\n"
                               "return from the database, and the attacker can use it for manipulate the output from the database\n")

    def user_command_info(self):
        self._deep_info.append("the user function can allow the attacker to manipulate the users permissions\n"
                               "and also see all users exist in the database and more info about the users\n")

    def version_command_info(self):
        self._deep_info.append("the version function seems very nice and harmless but you should be careful\n"
                               "the attacker can see the version of the database and this info can be very useful for\n"
                               "the next steps of the attack")

    def system_variable_info(self):
        self._deep_info.append("system variables that store information about the running package and its objects\n"
                               "this information can be very useful for future attacker")

    def if_command_info(self):
        self._deep_info.append("the if statement can use for check some condition in it,\n"
                               "with that said, attacker can use this statement to check\n")

    def ifnull_command_info(self):
        self._deep_info.append("the if statement can use for check some condition in it,\n"
                               "with that said, attacker can use this statement to check\n")

    def case_command_info(self):
        self._deep_info.append("the case statement check for each case if its true\n"
                               "just like the if condition, the case can show the attacker if the injection\n"
                               "work as he expected to\n")

    def exec_command_info(self):
        self._deep_info.append("the exec function is a very dangerous one, you should be careful\n"
                               "with this function the user can execute wide range of functions and scripts\n"
                               "on your server side\n")

    def create_command_info(self):
        self._deep_info.append("with the create function the attacker can create procedure or function\n"
                               "that could run on your database.\n")

    def user_info_disclosure_info(self):
        self._deep_info.append("pg_user is a specific command that can return info about all the users\n"
                               "in a specific database, in the wrong hands, this information about users can be dangerous\n")

    def db_info_disclosure_info(self):
        self._deep_info.append("pg_database stores information about the available databases\n"
                               "this information should not reach the attacker\n")

    def shadow_info_disclosure_info(self):
        self._deep_info.append("The view pg_shadow exists for backwards compatibility: it emulates a catalog that existed in PostgreSQL\n"
                               "this option could be used by an attacker that runs his own catalog\n")

    def db_command_info(self):
        self._deep_info.append("The DATABASE() function returns the name of the current database.\n"
                               "this information can help the attacker so it should not reach the attacker\n")


    def or_custom_info(self):
        self._deep_info.append("or is a logical statement, that can be very dangerous to your database\n"
                               "in order to make any query he wants, the attacker can add an or statement to the\n"
                               "query, that will be always true, like 1=1\n")
    def alter_custom_info(self):
        self._deep_info.append("with alter table function, the attacker can modify the database\n")

    def delete_custom_info(self):
        self._deep_info.append("with delete function, the user can delete, rows, values and even database\n"
                               "that can be vary dangerous for the server\n")

    def update_custom_info(self):
        self._deep_info.append("the update command just modify and change values appear in the database\n"
                               "the attacker can even put a malicious code in a single row, and then other users\n"
                               "that will run this row will run his virus as well\n")

    def create_custom_info(self):
        self._deep_info.append("create function just create a new row or database, this can be very dangerous\n"
                               "if the attacker will try to add some malicious code in a row, or even a fake database\n")

    def exist_custom_info(self):
        self._deep_info.append("the exist function check if a row or database are exist, that can be useful\n"
                               "for a future hacker, in order ti set his environment for hacking, and check the\n"
                               "settings of the database\n")

    def truncate_custom_info(self):
        self._deep_info.append("truncate table delete a data inside a table\n"
                               "hacker can use it for deleting very important information from the database\n"
                               "like credit cards number of ids number\n")

    def insert_custom_info(self):
        self._deep_info.append("the insert function add row to a database\n"
                               "a hacker can add some malicious code into the database with this command\n")

    def select_union_custom_info(self):
        self._deep_info.append("function get and return values or raw from a database\n"
                               "user can use it to see secret information, that he shouldn't see\n"
                               "like credit cards number, that function can be very dangerous and it is very common among sqlinjection hackers")

    def select_into_custom_info(self):
        self._deep_info.append("function get and return values or raw from a database\n"
                               "user can use it to see secret information, that he shouldn't see\n"
                               "like credit cards number, that function can be very dangerous and it is very common among sqlinjection hackers")

    def select_from_custom_info(self):
        self._deep_info.append("function get and return values or raw from a database\n"
                               "user can use it to see secret information, that he shouldn't see\n"
                               "like credit cards number, that function can be very dangerous and it is very common among sqlinjection hackers")

    def drop_custom_info(self):
        self._deep_info.append("function drop can delete raw, table and even database, potential hacker can use it for\n"
                               "disabling the whole website, therefore this command is very dangerous for any database\n")

    def get_info(self):
        return "General information: " + self._general_info + "More info: " + ''.join(self._deep_info) + self._links_for_info

    def set_attack_info(self, risk_name):
        switcher = {
            0: self.find_master_access_info,
            1: self.user_disclosure_info,
            2: self.mongo_db_command_info,
            3: self.cstyle_comment_info,
            4: self.blind_benchmark_info,
            5: self.load_file_disclosure_info,
            6: self.load_data_disclosure_info,
            7: self.write_into_outfile_info,
            8: self.blind_sql_sleep_info,
            9: self.concat_command_info,
            10: self.information_disclosure_info,
            11: self.sleep_pg_command_info,
            12: self.blind_tsql_info,
            13: self.substr_command_info,
            14: self.user_command_info,
            15: self.version_command_info,
            16: self.system_variable_info,
            17: self.if_command_info,
            18: self.ifnull_command_info,
            19: self.case_command_info,
            20: self.exec_command_info,
            21: self.create_command_info,
            22: self.user_info_disclosure_info,
            23: self.db_info_disclosure_info,
            24: self.shadow_info_disclosure_info,
            25: self.db_command_info,
        }
        switcher[risk_name]()

    def set_attack_info_custom(self, risk_name):
        switcher = {
            "or_custom": self.or_custom_info,
            "alter_custom": self.alter_custom_info,
            "delete_custom": self.delete_custom_info,
            "create_custom": self.create_custom_info,
            "update_custom": self.update_custom_info,
            "exist_custom": self.exist_custom_info,
            "truncate_custom": self.truncate_custom_info,
            "insert_custom": self.insert_custom_info,
            "select_union_custom": self.select_union_custom_info,
            "select_into_custom": self.select_into_custom_info,
            "select_from_custom": self.select_from_custom_info,
            "drop_custom": self.drop_custom_info
        }
        switcher[risk_name]()

