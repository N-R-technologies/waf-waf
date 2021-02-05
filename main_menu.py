from os import path
import toml
from curtsies import Input
from menu import Menu
from network_scanner import NetworkScanner
from email_manager import EmailManager
from colors import Colors


class MainMenu:
    _main_menu = Menu()
    _ignore_input = False
    LOGIN_URL_FILE = "detective/toolbox/lenses/brute_force/url_login.toml"

    def _start_scan(self, router_username, router_password):
        """
        This function will start the network scan
        :param router_username: the username of the router
        :param router_password: the password of the router
        :type router_username: tkinter.Entry
        :type router_password: tkinter.Entry
        """
        router_username = router_username.get()
        router_password = router_password.get()
        self._main_menu.close_input()
        scanner = NetworkScanner()
        scanner.scan(router_username, router_password)

    def _call_start_scan(self):
        """
        This function will call the start_scan function
        with the appropriate parameters
        """
        self._main_menu.get_input(self._start_scan, "Enter Router Credentials", '*',
                                  "Router's username. If you don't know, leave blank",
                                  "Router's password. If you don't know, leave blank")

    def _create_login_url_configuration(self):
        if not path.exists(self.LOGIN_URL_FILE):
            return toml.load(self.LOGIN_URL_FILE).get("login_url", None)
        return None

    def _get_login_url(self):
        self._create_login_url_configuration()
        self._main_menu.get_input(self._edit_login_url, "Enter your website's login url", "Login url")

    def _edit_login_url(self, login_url_entity):
        login_url = login_url_entity.get()
        with open(self.LOGIN_URL_FILE, 'w') as login_url_file:
            toml.dump({"login_url": login_url}, login_url_file)
            login_url_file.close()

    def _manage_emails(self):
        """
        This function will start the emails manager menu
        """
        email_manager = EmailManager()
        email_manager.start_manage_emails()

    def _print_help(self):
        """
        This function will print information about the program
        """
        print("Our project can do couple of useful stuff to your server.\n"
              "Our WAF (Web Application Firewall) runs in the background and protects your server\n"
              "from web attacks and hackers. In addition, our tool can scan your network and see if its safe.\n"
              "More than that, every 24 hours our WAF will send to your email a log containing information about all "
              "the attacks it blocked.\nYou have the option to see the current Emails the WAF will send to them "
              "the log, or even add Email or remove Email from the list.\nThis is an open source project, "
              "if you would like to see the source, enter to the link below:\n"
              "https://gitlab.com/magshimim-markez-2021/10/1003/pardes-hana-1003-waf\n")

    def start_menu(self):
        """
        This function will start the main menu of the program
        """
        self._main_menu.clear()
        self._main_menu.add_option("1. Start the network scan", self._call_start_scan)
        self._main_menu.add_option("2. Manage your emails configuration file", self._manage_emails)
        self._main_menu.add_option("3. Get help and explanation about our tool", self._print_help)
        self._main_menu.add_option("4. Add your site's url. In order to improve and to be more precise\n"
                                   "in our brute force detection, we should now what is your login url", self._get_login_url)
        self._main_menu.add_option("5. Exit (or simply press Q)", "exit")
        for menu_item in range(len(self._main_menu.menu)):
            if self._main_menu.controller[menu_item] == 1:
                print(Colors.YELLOW + self._main_menu.menu[menu_item])
            else:
                print(Colors.BLUE + self._main_menu.menu[menu_item])
        with Input(keynames="curses") as input_generator:
            for user_input in input_generator:
                self._main_menu.clear()
                if self._main_menu.get_ignore():
                    self._main_menu.handle_menu_navigation("")
                    self._main_menu.reset_ignore()
                else:
                    self._main_menu.handle_menu_navigation(repr(user_input))
                if self._main_menu.exit:
                    break


if __name__ == "__main__":
    main_menu = MainMenu()
    try:
        main_menu.start_menu()
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print("\nAn error has occurred...")
        print(e)
