import os

class Menu:
    """
    this is a class that represent menu, this cass can used for any menu we want
    to display in our program
    """
    def __init__(self):
        """
        function initialize the class values
        """
        self.OKBLUE = '\033[94m'
        self.WARNING = '\033[93m'
        self.exit = False
        self.menu = []
        self.functions = []
        self.controller = []

    def add_menu(self, str_display, function):
        """
        function add function to the menu
        :param str_display: the option display in the menu
        :param function: the function we want to add to the menu
        :type str_display: str
        :type function: function
        :return: None
        """
        self.menu.append(str_display)
        self.functions.append(function)
        if len(self.controller) == 0:
            self.controller.append(1)
        else:
            self.controller.append(0)

    def clear(self):
        """
        function clear the terminal
        """
        os.system("clear")

    def handle_menu(self, event):
        """
        function handle user input for the menu
        :param event: the user's input
        :type event: str
        :return: None
        """
        event = event[1:-1]
        if event == "KEY_DOWN":
            if self.controller.index(1) != (len(self.controller) - 1):
                self.controller.insert(0,0)
                self.controller.pop()
        elif event == "KEY_UP":
            if self.controller.index(1) != 0:
                self.controller.append(0)
                self.controller.pop(0)
        elif event == "q":
            self.exit = True
            return
        for menu_item in range(len(self.menu)):
            if self.controller[menu_item] == 1:
                print(self.WARNING + self.menu[menu_item])
            else:
                print(self.OKBLUE + self.menu[menu_item])
        if event == "\\n":
            if self.functions[self.controller.index(1)] == 'exit':
                self.exit = True
                return
            self.clear()
            self.functions[self.controller.index(1)]()
            print("**press any button for return to the menu**")
