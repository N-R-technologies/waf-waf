import os
import random
import tkinter as tk


class Menu:
    OK_BLUE = '\033[94m'
    WARNING = '\033[93m'
    _colors = (("#000000", "#00FF00"), ("#000000", "#23F7F7"), ("#000000", "#FFFF00"),
               ("#4D004D", "#FFEE00"), ("#00203F", "#ADEFD1"), ("#11004D", "#FF77FF"))

    def __init__(self):
        self._ignore = False
        self.menu = []
        self.controller = []
        self.exit = False
        self._functions = []
        self._input_window = None

    def clear(self):
        """
        This function will clear the terminal's screen
        """
        os.system("clear")

    def add_option(self, str_display, function):
        """
        This function will add a new option to the menu
        :param str_display: the option which will be displayed in the menu
        :param function: the function which will be called when the user choose the given option
        :type str_display: string
        :type function: function
        """
        self.menu.append(str_display)
        self._functions.append(function)
        if len(self.controller) == 0:
            self.controller.append(1)
        else:
            self.controller.append(0)

    def handle_menu_navigation(self, event):
        """
        This function will handle the user's navigation in the menu
        :param event: the user's input
        :type event: string
        """
        event = event[1:-1]
        if event == "KEY_DOWN":
            if self.controller.index(1) != (len(self.controller) - 1):
                self.controller.insert(0, 0)
                self.controller.pop()
        elif event == "KEY_UP":
            if self.controller.index(1) != 0:
                self.controller.append(0)
                self.controller.pop(0)
        elif event == 'q':
            self.exit = True
            return
        for menu_item in range(len(self.menu)):
            if self.controller[menu_item] == 1:
                print(self.WARNING + self.menu[menu_item])
            else:
                print(self.OK_BLUE + self.menu[menu_item])
        if event == '\\n':
            if self._functions[self.controller.index(1)] == "exit":
                self.exit = True
                return
            self.clear()
            self._functions[self.controller.index(1)]()
            print("\n**Press any button to return to the menu**")
            self._ignore = True

    def get_ignore(self):
        """
        the function return the ignore property
        """
        return self._ignore

    def get_input(self, function_on_submit, title, first_input_text, second_input_text):
        """
        This function will open a tiny GUI window
        in order to receive input from the user
        :param function_on_submit: the function that will be execute when submit is pressed
        :param title: the title of the input
        :param first_input_text: the first input text
        :param second_input_text: the second input text
        """
        input_window = tk.Tk()
        colors = random.choice(self._colors)
        background_color = colors[0]
        font_color = colors[1]
        self._input_window = input_window
        self._input_window.configure(bg=background_color)
        input_window.title(title)
        first_label = tk.Label(input_window, text=first_input_text, pady=5, bg=background_color, fg=font_color)
        first_label.grid(row=0, sticky=tk.W)
        first_entry = tk.Entry(input_window, width=30, bg=background_color, fg=font_color)
        first_entry.grid(row=1)
        second_label = tk.Label(input_window, text=second_input_text, pady=5, bg=background_color, fg=font_color)
        second_label.grid(row=2, sticky=tk.W)
        second_entry = tk.Entry(input_window, width=30, bg=background_color, fg=font_color)
        second_entry.grid(row=3)
        submit_button = tk.Button(input_window, text="Submit", bg=background_color, fg=font_color, command=lambda: function_on_submit(first_entry.get(), second_entry.get()))
        submit_button.grid(row=4)
        input_window.mainloop()

    def reset_ignore(self):
        """
        function reset the ignore property to false
        """
        self._ignore = False

    def close_input(self):
        """
        This function will close the tiny input GUI window
        """
        self._input_window.destroy()
