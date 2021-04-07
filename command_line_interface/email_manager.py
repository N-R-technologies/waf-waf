import os
import toml
import re
from curtsies import Input
from tkinter import messagebox
from .menu import Menu
from misc import Colors


class EmailManager:
    USER_EMAILS_FILE_PATH = "logger/data/user_emails.toml"

    _user_emails = dict()

    def __init__(self):
        self._email_manager_menu = Menu()
        if os.environ.get('DISPLAY', '') == '':
            print('no display found. Using :0.0')
            os.environ.__setitem__('DISPLAY', ':0.0')

    def _display_emails(self):
        self._user_emails = dict()
        if os.path.exists(self.USER_EMAILS_FILE_PATH):
            self._user_emails = toml.load(self.USER_EMAILS_FILE_PATH).get("emails", {})
        if len(self._user_emails) == 0:
            print("There are no registered emails.\nYou might want to add some.")
        index = 1
        for name, address in self._user_emails.items():
            print(f"{index}. {name}, {address}")
            index += 1

    def _add_email(self, name, address):
        name = name.get()
        address = address.get()
        valid_email = True
        if not os.path.exists(self.USER_EMAILS_FILE_PATH):
            with open(self.USER_EMAILS_FILE_PATH, 'w') as email_file:
                toml.dump(toml.loads("[emails]"), email_file)
                email_file.close()
        user_emails = toml.load(self.USER_EMAILS_FILE_PATH).get("emails", {})
        if name == "":
            messagebox.showerror("Invalid Name", "Please enter a name for the user")
            valid_email = False
        elif not self._is_valid_name(name, user_emails.keys()):
            messagebox.showerror("Invalid Name", f"A user named {name} already exists!")
            valid_email = False
        if not self._is_valid_address(address):
            messagebox.showerror("Invalid Address", "Email address is not valid!")
            valid_email = False
        if valid_email:
            with open(self.USER_EMAILS_FILE_PATH, 'a') as email_file:
                toml.dump({name: address}, email_file)
                email_file.close()
            messagebox.showinfo("Success", f"Successfully added {name} to the list!")
        self._email_manager_menu.close_input()

    def _call_add_email(self):
        self._email_manager_menu.get_input(self._add_email, "Add Email", "", "Name", "Address")

    def _remove_email(self, email_index):
        email_index = email_index.get()
        user_emails = toml.load(self.USER_EMAILS_FILE_PATH).get("emails", {})
        if not email_index.isdigit():
            messagebox.showerror("Invalid Input", "Please enter a number")
        else:
            email_index = int(email_index)
            if not 1 <= email_index <= len(user_emails):
                messagebox.showerror("Invalid Input", "Index out of range!")
            else:
                index = 1
                user_name = ""
                for name in user_emails.keys():
                    if index == email_index:
                        del user_emails[name]
                        user_name = name
                        break
                    index += 1
                with open(self.USER_EMAILS_FILE_PATH, 'w') as email_file:
                    toml.dump(toml.loads("[emails]"), email_file)
                    for name, address in user_emails.items():
                        toml.dump({name: address}, email_file)
                    email_file.close()
                messagebox.showinfo("Success", f"Successfully removed {user_name} from the list!")
        self._email_manager_menu.close_input()

    def _call_remove_email(self):
        self._display_emails()
        if len(self._user_emails) > 0:
            print("\nPlease enter the index of the email you wish to remove")
            self._email_manager_menu.get_input(self._remove_email, "Remove Email", "", "Index")

    def _is_valid_address(self, address):
        return re.search(r"""^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$""", address)

    def _is_valid_name(self, name, user_names):
        for existing_name in user_names:
            if name == existing_name:
                return False
        return True

    def start_manage_emails(self):
        self._email_manager_menu.add_option("1. Display all the emails", self._display_emails)
        self._email_manager_menu.add_option("2. Add an email to the list", self._call_add_email)
        self._email_manager_menu.add_option("3. Remove an email from the list", self._call_remove_email)
        self._email_manager_menu.add_option("4. Exit (or simply press Q)", "exit")
        for menu_item in range(len(self._email_manager_menu.menu)):
            if self._email_manager_menu.controller[menu_item] == 1:
                print(Colors.YELLOW + self._email_manager_menu.menu[menu_item])
            else:
                print(Colors.BLUE + self._email_manager_menu.menu[menu_item])
        with Input(keynames="curses") as input_generator:
            for user_input in input_generator:
                self._email_manager_menu.clear()
                if self._email_manager_menu.get_ignore():
                    self._email_manager_menu.handle_menu_navigation("")
                    self._email_manager_menu.reset_ignore()
                else:
                    self._email_manager_menu.handle_menu_navigation(repr(user_input))
                if self._email_manager_menu.exit:
                    break
