import os
import toml


class CaptchaImplementer:
    CAPTCHA_FILE_PATH = "detective/toolbox/brute_force/captcha.txt"
    CONFIGURATION_FILE_PATH = "brute_force_configuration.toml"

    _users_login_permission = dict()
    _captcha = None

    def get_login_url(self, request):
        if os.path.exists(self.CONFIGURATION_FILE_PATH):
            login_url = toml.load(self.CONFIGURATION_FILE_PATH).get("login_url", None)
            if login_url is not None and login_url in request.url:
                return login_url
        return None

    def implement(self, user_ip_address, login_url):
        if self._load_captcha(self.CAPTCHA_FILE_PATH, login_url):
            self._users_login_permission[user_ip_address] = True
            return self._captcha
        return None

    def remove_login_permission(self, user_ip_address):
        self._users_login_permission[user_ip_address] = False

    def has_login_permission(self, user_ip_address):
        if user_ip_address in self._users_login_permission.keys():
            return self._users_login_permission[user_ip_address]
        return False

    def _load_captcha(self, captcha_file_path, login_url):
        if self._captcha is not None:
            return True
        if os.path.exists(captcha_file_path):
            with open(captcha_file_path, 'r') as captcha_file:
                self._captcha = captcha_file.read()
                self._captcha = self._captcha.replace("{login_url}", login_url)
                captcha_file.close()
            return True
        return False
