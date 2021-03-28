import os
import random
import tkinter as tk
from misc import Colors


class Menu:
    _colors = (("#000000", "#00FF00"), ("#000000", "#23F7F7"), ("#000000", "#FFFF00"),
               ("#4D004D", "#FFEE00"), ("#00203F", "#ADEFD1"), ("#11004D", "#FF77FF"))

    def __init__(self):
        self.menu = []
        self.controller = []
        self.exit = False
        self._functions = []
        self._input_window = None
        self._ignore = False
        if os.environ.get('DISPLAY', '') == '':
            print('no display found. Using :0.0')
            os.environ.__setitem__('DISPLAY', ':0.0')
    
    def clear(self):
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
        event = event[1: -1]
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
                print(Colors.YELLOW + self.menu[menu_item])
            else:
                print(Colors.BLUE + self.menu[menu_item])
        if event == '\\n':
            if self._functions[self.controller.index(1)] == "exit":
                self.exit = True
                return
            self.clear()
            self._functions[self.controller.index(1)]()
            self._ignore = True
            print("\n**Press any button to return to the menu**")

    def get_input(self, function_on_submit, title, entries_show, *args):
        """
        This function will open a tiny GUI window
        in order to receive input from the user
        :param function_on_submit: the function that will be execute when submit is pressed
        :param title: the title of the input
        :param entries_show: what entry boxes will show when they receive input
        :param args: the packed input texts
        :type function_on_submit: function
        :type title: string
        :param entries_show: string
        :type args: tuple
        """
        input_window = tk.Tk()
        colors = random.choice(self._colors)
        background_color = colors[0]
        font_color = colors[1]
        self._input_window = input_window
        self._input_window.configure(bg=background_color)
        input_window.title(title)

        row_index = 0
        entries = []
        for arg in args:
            label = tk.Label(input_window, text=arg, pady=5, bg=background_color, fg=font_color)
            label.grid(row=row_index, sticky=tk.W)
            row_index += 1
            entry = tk.Entry(input_window, width=30, show=entries_show, bg=background_color, fg=font_color)
            entry.grid(row=row_index, pady=2)
            row_index += 1
            entries.append(entry)
        submit_button = tk.Button(input_window, text="Submit", bg=background_color, fg=font_color, command=lambda: function_on_submit(*entries))
        submit_button.grid(row=row_index)
        input_window.mainloop()

    def close_input(self):
        self._input_window.destroy()

    def get_ignore(self):
        return self._ignore

    def reset_ignore(self):
        self._ignore = False
