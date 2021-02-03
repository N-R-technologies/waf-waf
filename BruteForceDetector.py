import time
import sched
import threading


class BruteForceDetection:
    MAX_REQUEST_IN_TIME = 20
    HOUR_SLEEP = 3600
    TIME_SECONDS = 30
    DELAY_TIME_SECONDS = 3
    MAX_LOGIN_ATTEMPTS_PER_MINUTE = 15

    def __init__(self, login_url=""):
        self._log = dict()
        self._delay_ip = dict()
        self._log_lock = threading.Lock()
        self._delay_ip_lock = threading.Lock()
        self._login_url = login_url
        self._common_login_fields_name = {"uname", "username", "pass", "password", "email", "mail", "user", "access", "identity", "credential", "user account", "access code", "login name", "name"}
        self._common_login_urls = ("login", "signin")
        self._common_username_fields = ("uname", "username", "user", "access", "identity", "credential", "user account", "access code", "login name", "name")
        self._user_logins_log = dict()
        self._block_users = list()

    def _is_login_request(self, url):
        """
        function checks if the request is a login request, by the url
        :param url: the url of the request
        :type url: str
        :return: True if it is a login request, otherwise False
        :rtype: bool
        """
        return url in self._login_url

    def _get_username(self, login_request):
        """
        function returns the username of the login request
        :param login_request: the login request
        :type login_request: multidict
        :return: the username which tries to login, if not found None
        :rtype: str
        """
        for username_field in self._common_username_fields:
            if username_field in login_request.keys():
                return login_request[username_field]
        return None

    def detect_login_brute_force(self, request):
        """
        function detect login brute force
        :param request: the request
        :type request: mitm proxy request
        """
        if self._is_login_request(request.url):
            username = self._get_username(request.urlencoded_form)
            if username is not None:
                self._add_user_login_attempt(username)

    def _add_user_login_attempt(self, username):
        """
        function add login attempt to the logins log with the key of the username
        :param username: the username try to login
        :type username: str
        """
        if username in self._user_logins_log.keys():
            self._user_logins_log[username] += 1
        else:
            self._user_logins_log[username] = 1

    def check_brute_force_login(self):
        """
        function checks if some user try to login too much times per minute,
        if so, it will block its login attempts for permanent time
        """
        for username, attempts_num in self._user_logins_log.items():
            if attempts_num >= self.MAX_LOGIN_ATTEMPTS_PER_MINUTE:
                self._block_users.append(username)

    def is_username_blocked(self, username):
        """
        function checks if the username is in the block username list
        :param username: the username
        :type username: str
        :return: True if the username is in the block list, otherwise False
        :rtype: bool
        """
        return username in self._block_users

    def reset_block_users(self):
        """
        function reset the block users list
        """
        self._block_users.clear()

    def _scheduling_brute_force(self):
        """
        function start the scheduling for the brute force thread that
        supposed to run every amount of time
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.TIME_SECONDS, 1, self._check_brute_force)
            scheduler.run()

    def _scheduling_reset_delay(self):
        """
        function start the scheduling for the reset delay ip thread that
        supposed to run every amount of time
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.HOUR_SLEEP, 1, self._reset_delay_ip)
            scheduler.run()

    def start_brute_force_scheduler_threads(self):
        """
        function start the brute force scheduler thread
        """
        brute_force_scheduler_thread = threading.Thread(target=self._scheduling_brute_force)
        reset_delay_ip_thread = threading.Thread(target=self._scheduling_reset_delay)
        brute_force_scheduler_thread.start()
        reset_delay_ip_thread.start()

    def add_to_log(self, request_ip, request_url):
        """
        function add the request to the log
        :param request_ip: the ip of the request
        :param request_url: the url of the request
        :type request_ip: str
        :type request_url: str
        """
        if self._login_url in request_url:
            with self._log_lock:
                self._log[request_ip] += 1

    def _check_brute_force(self):
        """
        function check if there is brute force attack, according to the log
        requests dictionary
        """
        with self._log_lock, self._delay_ip_lock:
            for ip, ip_request_amount in self._log.items():
                if ip_request_amount >= self.MAX_REQUEST_IN_TIME:
                    self._delay_ip[ip] = True
            self._log.clear()

    def add_delay(self, ip, response):
        """
        function add delay to the packet , with the header Retry-After
        if the packet ip is in the delay_ip dict
        do it alternately
        :param ip: the ip of the packet
        :param response: the response packet
        :type ip: str
        :type response: mitm proxy response
        """
        with self._delay_ip_lock:
            if ip in self._delay_ip:
                if self._delay_ip[ip]:
                    response.headers["Retry-After"] = self.DELAY_TIME_SECONDS
                    self._delay_ip[ip] = False
                else:
                    self._delay_ip[ip] = True

    def _reset_delay_ip(self):
        """
        function reset the delay ip dictionary of the class
        """
        with self._delay_ip_lock:
            self._delay_ip.clear()

    def check_login_url(self, request):
        """
        function checks if the request is a login request
        if so, returns the url of the request
        :param request: the request
        :type request: mitm proxy request
        :return the login url, None if not found
        :rtype: bool
        """
        if request.method == "POST":
            keys_set = set(request.urlencoded_form.keys())
            if self._common_login_fields_name & keys_set and any(map(request.url.__contains__, self._common_login_fields_name)):
                return request.url
        return None

