import subprocess


FILES_TO_DELETE = ("geckodriver.log", "waf_data/blacklist.toml", "waf_data/server_info.toml",
                   "waf_data/wrong_diagnosis.waf_waf", "detective/attacks_logger/attacks.waf_waf")
PROCESSES_TO_KILL = ("geckodriver", "firefox", "selenium")


def run_command(command):
    subprocess.call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    for file in FILES_TO_DELETE:
        run_command(f"rm {file}")
    for process in PROCESSES_TO_KILL:
        run_command(f"pkill {process}")


if __name__ == "__main__":
    main()
