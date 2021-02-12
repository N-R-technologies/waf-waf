import os


class CaptchaImplementer:
    CAPTCHA_FILE_PATH = "detective/toolbox/lenses/brute_force/captcha.txt"
    LOGIN_URL_PATTERN = "<LOGIN_URL>"

    _users_login_permission = dict()
    _captcha = None

    def implement(self, user_ip_address, login_url):
        """
        This function will replace the response packet content
        with captcha in order to prevent login brute force
        :param user_ip_address: the ip of the response receiving user
        :param login_url: the URL of the login page
        :type user_ip_address: str
        :type login_url: str
        :return: the captcha html page if loaded successfully, otherwise, None
        :rtype: str or None
        """
        if self._load_captcha(self.CAPTCHA_FILE_PATH, login_url):
            self._users_login_permission[user_ip_address] = True
            return self._captcha
        return None

    def remove_login_permission(self, user_ip_address):
        """
        This function will remove the user's permission to login to
        the site, means he will have to implement the captcha again
        :param user_ip_address: the ip of the response receiving user
        :type user_ip_address: str
        """
        self._users_login_permission[user_ip_address] = False

    def has_login_permission(self, user_ip_address):
        """
        This function will check if the given user has
        permission to access the login URL of the site
        :param user_ip_address: the ip of the response receiving user
        :type user_ip_address: str
        :return: True, if he can, otherwise, False
        :rtype: bool
        """
        if user_ip_address in self._users_login_permission.keys():
            return self._users_login_permission[user_ip_address]
        return False

    def _load_captcha(self, captcha_file_path, login_url):
        """
        This function will load the captcha file and then
        will set captcha redirection to the login URL
        :param captcha_file_path: the ip of the response receiving user
        :param login_url: the URL of the login page
        :type captcha_file_path: str
        :type login_url: str
        :return: True, if loaded successfully, otherwise, False
        :rtype: bool
        """
        if self._captcha is not None:
            return True
        if os.path.exists(captcha_file_path):
            with open(captcha_file_path, 'r') as captcha_file:
                self._captcha = captcha_file.read()
                self._captcha = self._captcha.replace(self.LOGIN_URL_PATTERN, login_url)
                captcha_file.close()
            return True
        return False
