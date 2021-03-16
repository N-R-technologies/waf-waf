from os import environ
from sys import argv
from time import sleep
import subprocess
from selenium import webdriver
from selenium.common.exceptions import WebDriverException


class Automation:
    WITH_WAF_WAF_ADDRESS = "http://localhost:7777/login.php"
    WITHOUT_WAF_WAF_ADDRESS = "http://localhost:1234/login.php"

    _driver = None
    _with_waf_waf = None

    def __init__(self, with_waf_waf):
        self._with_waf_waf = with_waf_waf
        self._start_website()
        if self._with_waf_waf:
            self._driver.get(self.WITH_WAF_WAF_ADDRESS)
        else:
            self._driver.get(self.WITHOUT_WAF_WAF_ADDRESS)

    def _start_website(self):
        gecko_driver_path = subprocess.Popen(["realpath", "automation/geckodriver"], stdout=subprocess.PIPE).communicate()[0].decode()[:-1]
        gecko_driver_path = gecko_driver_path[:gecko_driver_path.find("/geckodriver")]
        environ["PATH"] += "$PATH:" + str(gecko_driver_path)
        environ["LANG"] = "en_US.UTF-8"
        self._driver = webdriver.Firefox()

    def run(self):
        self._fill_input("username", "admin")
        self._fill_input("password", "password")
        self._click_button("Login")
        self._automate_attack("SQL Injection", "id", "' or '1' = '1")
        if self._with_waf_waf:
            self._scroll_down()
            self._click_button("You made a false detection")
        self._automate_attack("XSS (Reflected)", "name", "<script>document.write(document.cookie)</script>")
        if self._with_waf_waf:
            self._scroll_down()
            self._click_link("Return to the site")
        try:
            self._automate_attack("Command Injection", "ip", "; pwd")
        except WebDriverException:
            pass
        self._driver.close()

    def _click_button(self, input_value):
        button = self._driver.find_elements_by_xpath(f"//input[@value='{input_value}']")[0]
        button.click()

    def _click_link(self, link_text):
        self._driver.find_element_by_link_text(link_text).click()

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

    def _scroll_down(self):
        sleep(8)
        self._driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        sleep(5)


def main():
    automation = Automation(eval(argv[1]))
    automation.run()


if __name__ == "__main__":
    main()
