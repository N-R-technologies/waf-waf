def findInFile(signature, file):
    signature += '\n'
    with open(file, 'r') as f:
        for line in f:
            if line == signature:
                return True
    return False
def main():
    print(findInFile("marcia", "commonssids.txt"))
if __name__ == "__main__":
    main()