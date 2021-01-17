import os
from curtsies import Input
from menu import Menu
import toml
import re
from tkinter import messagebox


class MailManager:
    def __init__(self):
        self._manage_mails = Menu()

    def _clear(self):
        """
        function clear the screen
        """
        os.system("clear")

    def call_add_mail(self):
        self._manage_mails.get_input(self.add_mail, "Add User Mail", "Name", "Mail Address")

    def add_mail(self, name, address):
        """
        function add one mail to the mails file
        """
        if not self._is_mail_valid(address):
            messagebox.showerror("Invalid Email", "Your email address is invalid")
        else:
            with open("log_related/data/user_addresses.toml", 'a') as email_file:
                toml.dump({name: address}, email_file)
            email_file.close()
        self._manage_mails.close_input()

    def remove_mail(self):
        """
        function remove one mail from the mails file
        """
        self.display_mails()
        exit_flag = False
        user_addresses = toml.load("log_related/data/user_addresses.toml").get("addresses", {})
        mail_index = input("Enter the index of the mail which you want to remove\n")
        while not (mail_index.isdigit() and 1 <= int(mail_index) <= len(user_addresses)) or exit_flag:
            print("Invalid index")
            print("Press Q to quit")
            mail_index = input("Enter the index of the mail which you want to remove\n")
            if mail_index.lower() == 'q':
                exit_flag = True
        if exit_flag:
            return
        index = 1
        for name in user_addresses:
            if index == int(mail_index):
                del user_addresses[name]
                break
            index += 1
        with open("log_related/data/user_addresses.toml", 'w') as email_file:
            toml.dump(toml.loads("[addresses]"), email_file)
            for name in user_addresses:
                toml.dump({name: user_addresses[name]}, email_file)
        email_file.close()

    def display_mails(self):
        """
        function display all the emails
        """
        user_addresses = dict()
        if os.path.exists("log_related/data/user_addresses.toml"):
            user_addresses = toml.load("log_related/data/user_addresses.toml").get("addresses", {})
        else:
            open("log_related/data/user_addresses.toml", 'w').close()
        index = 1
        for name in user_addresses:
            print(f"{index}. {name}, {user_addresses[name]}")
            index += 1

    def _is_mail_valid(self, mail):
        """
        function checks if the argument mail is valid
        :param mail: the mail to check
        :type mail: str
        :return: True if its valid, otherwise False
        :rtype: bool
        """
        return re.search(r"""^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$""", mail)

    def start_manage_mails(self):
        """
        function start the manage mails menu
        """
        self._manage_mails.add_menu('1. Display all the emails', self.display_mails)
        self._manage_mails.add_menu('2. Delete email from the list', self.remove_mail)
        self._manage_mails.add_menu('3. Add email to the list', self.call_add_mail)
        self._manage_mails.add_menu('4. Exit or press Q', 'exit')
        for menu_item in range(len(self._manage_mails.menu)):
            if self._manage_mails.controller[menu_item] == 1:
                print(self._manage_mails.WARNING + self._manage_mails.menu[menu_item])
            else:
                print(self._manage_mails.OKBLUE + self._manage_mails.menu[menu_item])
        with Input(keynames='curses') as input_generator:
            for user_input in input_generator:
                self._clear()
                self._manage_mails.handle_menu(repr(user_input))
                if self._manage_mails.exit:
                    break
