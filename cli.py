from command_line_interface import MainMenu


def main():
    main_menu = MainMenu()
    try:
        main_menu.start_menu()
    except Exception as e:
        print("\nAn error has occurred...")
        print(e)
    finally:
        print("\nGoodbye!")


if __name__ == "__main__":
    main()
