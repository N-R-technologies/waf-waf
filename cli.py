from command_line_interface import MainMenu
from misc import Colors


def main():
    main_menu = MainMenu()
    try:
        main_menu.start_menu()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print("\nAn error has occurred...")
        print(e)
    print("\nGoodbye!")
    print(Colors.WHITE)


if __name__ == "__main__":
    main()
