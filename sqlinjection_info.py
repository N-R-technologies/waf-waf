

links_for_info = "for more information about the attack, check this links:\n" \
                  "https://owasp.org/www-community/attacks/SQL_Injection\n" \
                  "https://portswigger.net/web-security/sql-injection"
general_info = "SQL injection is a web security vulnerability that allows an attacker to interfere with the" \
                " queries that an application makes to its database.\n" \
                "It generally allows an attacker to view data that they are not normally able to retrieve.\n" \
                "also with this the attacker can modify the database or even inject some malicious code to\n"

"""
all the variables below contains the specific info about each attack that the 
detector detect.
"""
deep_info = {
    "find_master_access": "master is a scheme table that contains all the information, values and indexes about the\n"
                          "table. the attacker can prepare his attack with getting "
                          "some information about the database\n",

    "user_disclosure": "the user table is a global table in every mySql database, so we make sure the attacker"
                             "doesn't try to access it and get the information about the users\n",

    "mongo_db_command": "the attacker may use some of the common commands in mongoDB, that are not so\n"
                              "frequent, so it is suspicious he use this characters\n",

    "cstyle_comment": "the user is trying to add some Cstyle comments into your sql query maybe in order\n"
                            "to delete the info after the comments\n",

    "blind_benchmark": "blind sql injection are the type that doesn't shown screen, attacker\n"
                             "can reach this goal by the benchmark function which make a delayed response only\n"
                             "if the injection succeed. also he doesnt need high privileges for that\n",

    "load_file_disclosure": "load file function generally Reads the file and returns the "
                                  "file contents as a string\n"
                                  "it can be harmful when the user load some "
                                  "important file and then select it with a\n"
                                  "regular query\n",

    "load_data_disclosure": "The LOAD DATA statement reads rows from a text file into a table\n"
                                  "attacker can use this function in order to inject some "
                                  "malicious script into the database\n",

    "write_into_outfile": "this function writes the selected rows to a file, so the attacker can write some\n"
                          "parts of the database to a specific file and then some how take it\n",

    "blind_sql_sleep": "with this function the attacker can delayed the server's response and see if his\n"
                             "injections work\n",

    "concat_command": "the concat command is another way for the attacker to check if his injection can work\n"
                            "this command is basically concat couple of strings together into one string\n",

    "information_disclosure": "INFORMATION_SCHEMA provides access to database metadata.\n"
                                    "with this function the attacker can see all the information about\n"
                                    "the MySQL server such as the name of a database or table,\n"
                                    "the data type of a column, or access privileges.\n",

    "sleep_pg_command": "with this function the attacker can delayed the\n"
                              "server's response and see if his injections work\n",

    "blind_tsql": "with this function the attacker can delayed the server's response and see if his\n"
                                "injections work\n",

    "substr_command": "the substr function is not so dangerous for its self,\n"
                              "but generally it parse the string return from the database\n"
                              "and the attacker can use it for manipulate the output from the database\n",

    "user_command": "the user function can allow the attacker to manipulate the users\n"
                          "permissions and also see all users exist in\n"
                          "the database and more info about the users\n",
    "length_command"
    "hex_command"
    "base64_command"
    "version_command": "the version function seems very nice and harmless "
                             "but you should be careful\n"
                             "the attacker can see the version of the database and this info\n"
                             "can be very useful for the next steps of the attack\n",
    "oct_command"
    "ord_command"
    "ascii_command"
    "bin_command"
    "char_command"
    "system_variable": "system variables that store information about the running "
                             "package and its objects\n"
                             "this information can be very useful for future attacker",

    "if_command": "the if statement can use for check some condition in it,\n"
                        "with that said, attacker can use this statement to check\n",

    "ifnull_command": "the if statement can use for check some condition in it,\n"
                            "with that said, attacker can use this statement to check\n",

    "case_command": "the case statement check for each case if its true\n"
                          "just like the if condition, the case can show the attacker if the injection\n"
                          "work as he expected to\n",

    "exec_command": "the exec function is a very dangerous one, you should be careful\n"
                            "with this function the user can execute wide range of functions and scripts\n"
                            "on your server side\n",

    "create_procedure_command": "with the create function the attacker can create procedure or function\n"
                                      "that could run on your database.\n",

    "user_info_disclosure": "pg_user is a specific command that can return"
                                  " info about all the users\n"
                                  "in a specific database, in the wrong hands,"
                                  "this information about users can be dangerous\n",

    "db_info_disclosure": "pg_database stores information about the available databases\n"
                                "this information should not reach the attacker\n",

    "shadow_info_disclosure": "The view pg_shadow exists for backwards compatibility:\n"
                                    "it emulates a catalog that existed in PostgreSQL\n"
                                    "this option could be used by an attacker that runs his own catalog\n",

    "db_command": "The DATABASE() function returns the name of the current database.\n"
                            "this information can help the attacker so it should not reach the attacker\n",


    "or_statement": "or is a logical statement, that can be very dangerous to your database\n"
                        "in order to make any query he wants, the attacker can add an or statement to the\n"
                        "query, that will be always true, like 1=1\n",
    "grant_revoke": "the grant or revoke functions are letting the attacker the option\n"
                          "of manipulate and change the permissions of the database\n",

    "alter": "with alter table function, the attacker can modify the database\n",

    "delete": "with delete function, the user can delete, rows, values and even database\n"
                        "that can be vary dangerous for the server\n",

    "update": "the update command just modify and change values appear in the database\n"
                    "the attacker can even put a malicious code in a single row, and then other users\n"
                    "that will run this row will run his virus as well\n",

    "create": "create function just create a new row or database, this can be very dangerous\n"
                    "if the attacker will try to add some malicious code in a row, or even a fake database\n",

    "exist": "the exist function check if a row or database are exist, that can be useful\n"
                   "for a future hacker, in order ti set his environment for hacking, and check the\n"
                   "settings of the database\n",

    "truncate": "truncate table delete a data inside a table\n"
                      "hacker can use it for deleting very important information from the database\n"
                      "like credit cards number of ids number\n",

    "insert": "the insert function add row to a database\n"
                    "a hacker can add some malicious code into the database with this command\n",

    "select_union": "function get and return values or raw from a database\n"
                          "user can use it to see secret information, that he shouldn't see\n"
                          "like credit cards number, that function can be very dangerous and it is very "
                          "common among sqlinjection hackers",

    "select_into": "function get and return values or raw from a database\n"
                         "user can use it to see secret information, that he shouldn't see\n"
                         "like credit cards number, that function can be very dangerous and"
                         " it is very common among sqlinjection hackers",

    "select_from": "function get and return values or raw from a database\n"
                         "user can use it to see secret information, that he shouldn't see\n"
                         "like credit cards number, that function can be very dangerous and"
                         "it is very common among sqlinjection hackers",

    "drop": "function drop can delete raw, table and even database, potential hacker can use it for\n"
                  "disabling the whole website therefore this command is very dangerous for any database\n"
}
