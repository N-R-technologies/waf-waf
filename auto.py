import os
def foo(path):
     lst = ["git", "__pycache__", "venv", "idea"]
     for root, dirs, files in os.walk(os.path.abspath(path)):
         for file in files:
             if not file_to_ignore(root):
                 full_path = os.path.join(root[root.find("pardes-hana-1003-waf/")+len("pardes-hana-1003-waf/"):], file)
                 print(f'ADD {full_path} {full_path}')
        

def file_to_ignore(root):
    lst = ["git", "__pycache__", "venv", "idea"]
    for suffix in lst:
        if suffix in root:
            return True

    return False

foo(os.path.abspath(os.getcwd()))
