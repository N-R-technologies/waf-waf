from selenium import webdriver
import subprocess
from os import environ, system
from time import sleep
from sys import argv


class DemoProject:

    def __init__(self, with_waf_waf):
        if with_waf_waf:
            system("mitmproxy -p 7891 -m reverse:http://localhost:7777 -s waf_waf.py")
        else:
            gecko_driver_path = subprocess.Popen(["realpath", "geckodriver"], stdout=subprocess.PIPE).communicate()[0].decode()[:-1]
            gecko_driver_path = gecko_driver_path[:gecko_driver_path.find("geckodriver")]
            environ["PATH"] = "$PATH:" + gecko_driver_path
        self._with_waf_waf = with_waf_waf
        self._driver = webdriver.Firefox()
        self._driver.get("http://localhost:7891/login.php")

    def automation(self):
        self._click_button("Login")
        self._click_button("Create / Reset Database")
        self._click_button("login")
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
        sleep(10)

    def _click_button(self, input_value):
        login = self._driver.find_elements_by_xpath(f"//input[@value='{input_value}']")[0]
        login.click()

    def _click_link(self, link_name):
        self._driver.find_element_by_link_text(link_name).click()

    def _fill_input(self, input_name, input_text):
        input_field = self._driver.find_element_by_name(input_name)
        for character in input_text:
            input_field.send_keys(character)
            sleep(0.3)

    def _automate_attack(self, attack_link_name, attack_input_name, attack_content):
        self._click_link(attack_link_name)
        self._fill_input(attack_input_name, attack_content)
        sleep(1.5)
        self._click_button("Submit")
        sleep(3)

    def _scroll_down_click(self, made_false_detection):
        sleep(10)
        self._driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        sleep(10)
        if made_false_detection:
            self._click_button("wrong diagnosis")
        else:
            self._click_link("Return to the site")

    def __del__(self):
        self._driver.close()


def main():
    if argv[1] == "waf_waf":
        automation = DemoProject(True)
    else:
        automation = DemoProject(False)
    automation.automation()


if __name__ == "__main__":
    main()

