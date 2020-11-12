import toml


def main():
    file_content = """
    [emails]
    noam = "noammizrahi@gmail.com"
    ron = "ronkonis@gmail.com"     
    """
    parsed_content = toml.loads(file_content)  # parsing our data into toml format

    with open("example_file.toml", 'w') as write_file:  # open the file for writing, if doesn't exist create it
        print("Writing content to file...")
        toml.dump(parsed_content, write_file)  # write content to file
        print("Done!\nClosing the file...")
        write_file.close()
        print("File closed successfully\n")

    with open("example_file.toml", 'r') as read_file:  # open the file for reading
        print("Reading content from file...")
        toml_content = toml.loads(read_file.read())
        print("Done!")
        print("File's content:")
        print(toml_content)
        print("Closing the file...")
        read_file.close()
        print("File closed successfully")


if __name__ == "__main__":
    main()
