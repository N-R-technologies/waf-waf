from os import path
import toml
from curtsies import Input
from .menu import Menu
from .network_scanner import NetworkScanner
from .email_manager import EmailManager
from misc import Colors
from tkinter import messagebox


class MainMenu:
    LOGIN_URL_FILE = "detective/toolbox/brute_force/brute_force_configuration.toml"
    WRONG_DIAGNOSIS_FILE = "waf_data/wrong_diagnosis.waf_waf"
    ATTACKS_LOG_FILE = "detective/attacks_logger/attacks.waf_waf"

    _main_menu = Menu()
    _ignore_input = False

    def _start_scan(self, router_username, router_password):
        router_username = router_username.get()
        router_password = router_password.get()
        self._main_menu.close_input()
        scanner = NetworkScanner()
        scanner.scan(router_username, router_password)

    def _call_start_scan(self):
        self._main_menu.get_input(self._start_scan, "Enter Router Credentials", '*',
                                  "Router's username. If you don't know, leave blank",
                                  "Router's password. If you don't know, leave blank")

    def _get_wrong_diagnosis_attack(self, client_ip_address):
        client_ip_address = client_ip_address.get()
        if not path.exists(self.ATTACKS_LOG_FILE):
            open(self.ATTACKS_LOG_FILE, "w").close()
        with open(self.ATTACKS_LOG_FILE, "r") as attacks_file:
            for attack in attacks_file:
                attack_info = tuple(attack.split(","))
                if attack_info[0] == client_ip_address:
                    print(f"attack date: {attack_info[1]}, the attack packet:\n"
                          f"{attack_info[2]}\n")
            attacks_file.close()
        self._main_menu.close_input()

    def _call_get_attacks_ip(self):
        self._main_menu.get_input(self._get_wrong_diagnosis, "Enter the attacker ip you are looking for:", "", "Attacker ip")

    def _print_wrong_diagnosis(self):
        if not path.exists(self.WRONG_DIAGNOSIS_FILE):
            open(self.WRONG_DIAGNOSIS_FILE, "w").close()
        with open(self.WRONG_DIAGNOSIS_FILE, "r") as wrong_diagnosis_file:
            for wrong_diagnosis in wrong_diagnosis_file:
                wrong_diagnosis_info = tuple(wrong_diagnosis.split(","))
                print(f"attacker ip: {wrong_diagnosis_info[0]}, attack date: {wrong_diagnosis_info[1]}")
            wrong_diagnosis_file.close()

    def _create_login_url_configuration(self):
        if not path.exists(self.LOGIN_URL_FILE):
            return toml.load(self.LOGIN_URL_FILE).get("login_url", None)
        return None

    def _get_login_url(self):
        self._create_login_url_configuration()
        self._main_menu.get_input(self._edit_login_url, "Enter your website's login url", "", "Login url")

    def _edit_login_url(self, login_url_entity):
        login_url = login_url_entity.get()
        if login_url == "":
            messagebox.showerror("Invalid Input", "Login url cannot be empty!")
        else:
            brute_force_configuration = toml.load(self.LOGIN_URL_FILE)
            brute_force_configuration["login_url"] = login_url
            with open(self.LOGIN_URL_FILE, 'w') as login_url_file:
                toml.dump(brute_force_configuration, login_url_file)
                login_url_file.close()
            messagebox.showinfo("Success", f"Successfully modified the login url!")
        self._main_menu.close_input()

    def _manage_emails(self):
        email_manager = EmailManager()
        email_manager.start_manage_emails()

    def _print_help(self):
        print("Our project can do couple of useful stuff to your server.\n"
              "Our WAF (Web Application Firewall) runs in the background and protects your server\n"
              "from web attacks and hackers. In addition, our tool can scan your network and see if its safe.\n"
              "More than that, every 24 hours our WAF will send to your email a log containing information about all "
              "the attacks it blocked.\nYou have the option to see the current Emails the WAF will send to them "
              "the log, or even add Email or remove Email from the list.\nThis is an open source project, "
              "if you would like to see the source, enter to the link below:\n"
              "https://gitlab.com/magshimim-markez-2021/10/1003/pardes-hana-1003-waf\n")

    def start_menu(self):
        self._main_menu.clear()
        self._main_menu.add_option("1. Start the network scan", self._call_start_scan)
        self._main_menu.add_option("2. Manage your emails configuration file", self._manage_emails)
        self._main_menu.add_option("3. Get help and explanation about our tool", self._print_help)
        self._main_menu.add_option("4. Modify your site's URL. In order to improve and to be more precise\n   "
                                   "in our brute force detection, we should know what is your sites' login URL", self._get_login_url)
        self._main_menu.add_option("5. Get all users whose complainant that our waf made a mistake by blocking them", self._print_wrong_diagnosis)
        self._main_menu.add_option("6. Get specific ip attacks", self._call_get_attacks_ip)
        self._main_menu.add_option("7. Exit (or simply press Q)", "exit")
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
