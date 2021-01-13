category = "local file inclusion"

general_info = "Local file inclusion (also known as LFI) is the process of including files,\n" \
               "that are already locally present on the server, through the exploiting of vulnerable inclusion\n" \
               "procedures implemented in the application. This vulnerability occurs, for example,\n" \
               "when a page receives, as input, the path to the file that has to be included and this input\n" \
               "is not properly sanitized, allowing directory traversal characters (such as dot-dot-slash)\n" \
               "to be injected."

deep_info = {
    "etc_files": "The etc path contains a lot files, and also sensitive ones\n"
                 "like paswd, and other.  Many networking configuration files are in /etc as well\n"
                 "The attacker can get information about the server in this path\n",
    "home_files": "A home directory, also called a login directory, is the directory on Unix-like\n"
                  "operating systems that serves as the repository for a user's personal files,\n"
                  "directories and programs.\n"
                  "It is also the directory that a user is first in after logging into the system.\n",
    "root_files": "/ directory called as Root Directory sits on the top of the file system hierarchy.\n"
                  "That means that from the access to the root directory,\n"
                  "an attacker can access all the files on the server\n",
    "proc_files": "The proc directory special directory holds all the details about your Linux system,\n"
                  "including its kernel, processes, and configuration parameters\n"
                  "a potential attacker can access an information within this path in order\n"
                  "to get data about the server process\n",
    "var_files": "/var directory contains things that are prone to change, such as websites,\n"
                 "temporary files (/var/tmp) and databases. The var directory contains useful\n"
                 "information and data that is used by the server\n",
    "information_files": "Be careful! if you see this it means that the user probably tried to access some\n"
                         "very sensitive files like php configurations or authorized keys for the server\n",
    "windows_files": "In the windows directory you can found some really important files that belongs\n"
                     "to the operating system in windows. This files should not reach the attacker\n"
                     "and give him a lot of information about the server's environment\n",
    "php_files": "This path contains all the php configuration files, and also information\n"
                 "about the php version and the server settings\n",
    "program_files": "Program Files is the directory name of a standard folder\n"
                     "in Microsoft Windows operating systems\n"
                     "in which applications that are not part of the operating system are\n"
                     "conventionally installed. This path can contain the files that belong to the server\n",
    "sensitive_windows_files": "Be careful! if you see this it means that the user probably tried to access some\n"
                         "very sensitive files \n",
    "url_encoding_unicode": "The attacker may hide the url and encode the path of the file he\n"
                            "try to access. It is very smart hacker but possible scenario\n",
    "php_stream_filter": "php stream filter is a final piece of code which may perform operations on data\n"
                         "as it is being read from or written to a stream\n"
                         "Attacker may use this to manipulate your php functions on the server side\n",
    "stream_filter_base64": "php stream filter is a final piece of code which may perform operations on data\n"
                         "as it is being read from or written to a stream\n"
                         "Attacker may use this to decrypt his path or output\n",
    "stream_filter_zlib": "php stream filter is a final piece of code which may perform operations on data\n"
                         "as it is being read from or written to a stream\n"
                         "Attacker may use this to manipulate your php functions on the server side\n",
    "windows_variables": "An environment variable is a dynamic-named value that can affect the\n"
                         "way running processes will behave on a computer.\n"
                         "They are part of the environment in which a process runs.\n"
                         "The access to this variables can give the user useful information\n"
                         "and even permissions to edit the process on the server\n",
    "local_chrome_files": "there is option is chrome to see and check the local files that can provide\n"
                          "the user information that seem harmless but can be very useful to a potential attacker\n",
    "apache_server_side_inclusion": "The attacker can pass through the url some functions he wants the server to\n"
                                    "like exec in order to execute some script or include for include file\n",
    "php_functions": "php functions can modify some php content on the server\n"
                     "if its read or write\n",
    "php_file_get_put_content": "This php function get or set content to file\n",
    "php_edit_files_function": "This php function edit server's file and can interrupt its running\n",

}

links_for_info = "For more information about local file inclusion, check the following links:\n" \
                 "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application\n" \
                 "_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion\n" \
                 "https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/"
