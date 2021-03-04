from threading import Thread
from selenium import webdriver
import subprocess
from os import environ, system
from time import sleep
from sys import argv


class DemoProject:

    def __init__(self, with_waf_waf):
        self._start_website(with_waf_waf)
        self._with_waf_waf = with_waf_waf
        self._driver = webdriver.Firefox()
        if with_waf_waf:
            self._driver.get("http://localhost:1234/login.php")
        else:
            self._driver.get("http://localhost:7777/login.php")

    def _start_website(self, with_waf_waf):
        if with_waf_waf:
            waf_waf_thread = Thread(target=self._run_waf_waf)
            waf_waf_thread.start()
        gecko_driver_path = subprocess.Popen(["realpath", "automation/geckodriver"], stdout=subprocess.PIPE).communicate()[0].decode()[:-1]
        gecko_driver_path = gecko_driver_path[:gecko_driver_path.find("/geckodriver")]
        environ["PATH"] += "$PATH:" + str(gecko_driver_path)

    def _run_waf_waf(self):
        system("mitmproxy -p 1234 -m reverse:http://localhost:7777 -s waf_waf.py")

    def automation(self):
        self._click_button("Login")
        self._click_button("Create / Reset Database")
        sleep(8)
        self._click_button("Login")
        self._fill_input("username", "admin")
        self._fill_input("password", "password")
        self._click_button("Login")
        self._automate_attack("SQL Injection", "id", "' or '1' = '1")
        if self._with_waf_waf:
            self._scroll_down_click(True)
        self._automate_attack("XSS (Reflected)", "name", "<script>document.write(document.cookie)</script>")
        if self._with_waf_waf:
            self._scroll_down_click(False)
        self._automate_attack("Command Injection", "ip", "; pwd")

    def _click_button(self, input_value):
        button = self._driver.find_elements_by_xpath(f"//input[@value='{input_value}']")[0]
        button.click()

    def _click_link(self, link_name):
        self._driver.find_element_by_link_text(link_name).click()

    def _fill_input(self, input_name, input_text):
        input_field = self._driver.find_element_by_name(input_name)
        for character in input_text:
            input_field.send_keys(character)
            sleep(0.2)

    def _automate_attack(self, attack_link_name, attack_input_name, attack_content):
        self._click_link(attack_link_name)
        self._fill_input(attack_input_name, attack_content)
        sleep(1.5)
        self._click_button("Submit")
        sleep(3)

    def _scroll_down_click(self, made_false_detection):
        sleep(8)
        self._driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        sleep(5)
        if made_false_detection:
            self._click_button("You made a false detection")

        else:
            self._click_link("Return to the site")
        sleep(3)

    def __del__(self):
        self._driver.close()


def main():
    if argv[1] != "waf_waf":
        system("docker run --rm -d -p 7777:80 vulnerables/web-dvwa")
        automation = DemoProject(False)
    else:
        system("docker rm -f $( docker ps -a -q)")
        system("docker run --rm -d -p 7777:80 vulnerables/web-dvwa")
        try:
            automation = DemoProject(True)
        except Exception:
            pass
            system("docker rm -f $( docker ps -a -q)")
            # finish automation
    automation.automation()


if __name__ == "__main__":
    main()

