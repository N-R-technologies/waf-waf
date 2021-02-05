import os
import time
import sched
import threading
import toml


class BruteForceDetection:
    MAX_REQUEST_IN_HALF_MINUTE = 20
    TIME_SECONDS_CHECK_BRUTE_FORCE = 30
    TIME_SECONDS_CHECK_LOGIN_BRUTE_FORCE = 60
    DELAY_TIME_SECONDS = 3
    MAX_LOGIN_ATTEMPTS_PER_MINUTE = 15
    TIME_RESET_BLOCKED_USERS = 7200
    TIME_RESET_DELAY_IP = 3600

    def __init__(self):
        self._requests_log = dict()
        self._delay_ip = dict()
        self._request_log_lock = threading.Lock()
        self._delay_ip_lock = threading.Lock()
        self._common_login_fields_name = {"uname", "username", "pass", "password",
                                          "email", "mail", "user", "access", "identity",
                                          "credential", "user account", "access code",
                                          "login name", "name"}
        self._common_login_urls = ("login", "signin")
        self._common_username_fields = ("uname", "username", "user", "access",
                                        "identity", "credential", "user account",
                                        "access code", "login name", "name")
        self._user_logins_log = dict()
        self._block_users = list()
        self._logins_log_lock = threading.Lock()
        self._block_users_lock = threading.Lock()

    def detect(self, request, client_ip):
        """
        function is responsible to add the request to the
        relevant logs, and to add delay header to the request if it
        is brute force one
        """
        self._add_login_attempt(request)
        self._add_user_request(client_ip)

    def is_request_block(self, request):
        """
        function checked if the username that try to login
        is blocked
        :param request: the request
        :type request: mimtproxy request
        :return: True if the request supposed to be blocked, otherwise False
        :rtype: bool
        """
        if self._is_login_request(request):
            username = self._get_username(request)
            return self._is_username_blocked(username)
        return False

    def edit_response(self, response, client_ip):
        """
        function add retry after header to the response,
        if the response is for ip that brute force the server recently
        :param response: the response to be changed
        :param client_ip: the ip of the client
        :type response: mitm proxy response
        :type client_ip: str
        :return: None
        """
        self._add_delay(client_ip, response)

    def _is_login_request(self, request):
        """
        function checks if the request is a login request, by the url
        :param request: the request
        :type request mimt proxy request
        :return: True if it is a login request, otherwise False
        :rtype: bool
        """
        return request.url in self._load_login_url() or self._check_login_url(request)

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

    def _add_login_attempt(self, request):
        """
        function detect login brute force
        :param request: the request
        :type request: mitm proxy request
        """
        if self._is_login_request(request):
            username = self._get_username(request.urlencoded_form)
            if username is not None:
                self._add_user_login_attempt(username)

    def _add_user_login_attempt(self, username):
        """
        function add login attempt to the logins log with the key of the username
        :param username: the username try to login
        :type username: str
        """
        with self._logins_log_lock:
            if username in self._user_logins_log.keys():
                self._user_logins_log[username] += 1
            else:
                self._user_logins_log[username] = 1

    def _check_brute_force_login(self):
        """
        function checks if some user try to login too much times per minute,
        if so, it will block its login attempts for permanent time
        """
        with self._logins_log_lock, self._block_users_lock:
            for username, attempts_num in self._user_logins_log.items():
                if attempts_num >= self.MAX_LOGIN_ATTEMPTS_PER_MINUTE:
                    self._block_users.append(username)
            self._user_logins_log.clear()

    def _check_login_url(self, request):
        """
        function checks if the request is a login request
        if so, returns true
        :param request: the request
        :type request: mitm proxy request
        :return the login url, None if not found
        :rtype: bool
        """
        if request.method == "POST":
            keys_set = set(request.urlencoded_form.keys())
            return self._common_login_fields_name & keys_set and any(map(request.url.__contains__, self._common_login_fields_name))
        return False

    def _load_login_url(self):
        """
        function load the login url from the .toml file
        if its not exist return None
        :return: the login url if found otherwise None
        :rtype: str
        """
        if os.path.exists("url_login.toml"):
            return toml.load("url_login.toml").get("url", None)
        return None

    def _is_username_blocked(self, username):
        """
        function checks if the username is in the block username list
        :param username: the username
        :type username: str
        :return: True if the username is in the block list, otherwise False
        :rtype: bool
        """
        return username in self._block_users

    def _reset_block_users(self):
        """
        function reset the block users list
        """
        with self._logins_log_lock:
            self._block_users.clear()

    def _scheduling_login_brute_force(self):
        """
        function scheduling the login brute force detection function
        to be execute every minute
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.TIME_SECONDS_CHECK_LOGIN_BRUTE_FORCE, 1, self._check_brute_force_login)
            scheduler.run()

    def _scheduling_reset_blocked_users(self):
        """
        function scheduling the reset block function to
        be executed every half of an hour
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.TIME_RESET_BLOCKED_USERS, 1, self._reset_block_users)
            scheduler.run()

    def _scheduling_brute_force(self):
        """
        function start the scheduling for the brute force thread that
        supposed to run every amount of time
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.TIME_SECONDS_CHECK_BRUTE_FORCE, 1, self._check_brute_force)
            scheduler.run()

    def _scheduling_reset_delay(self):
        """
        function start the scheduling for the reset delay ip thread that
        supposed to run every amount of time
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.TIME_RESET_DELAY_IP, 1, self._reset_delay_ip)
            scheduler.run()

    def start_brute_force_scheduler_threads(self):
        """
        function start the brute force scheduler thread
        """
        login_brute_force_scheduler_thread = threading.Thread(target=self._scheduling_login_brute_force)
        reset_blocked_users = threading.Thread(target=self._scheduling_reset_blocked_users)
        brute_force_scheduler_thread = threading.Thread(target=self._scheduling_brute_force)
        reset_delay_ip_thread = threading.Thread(target=self._scheduling_reset_delay)
        login_brute_force_scheduler_thread.start()
        reset_blocked_users.start()
        brute_force_scheduler_thread.start()
        reset_delay_ip_thread.start()

    def _add_user_request(self, request_ip):
        """
        function add the request to the log
        :param request_ip: the ip of the request
        :type request_ip: str
        """
        with self._request_log_lock:
            if request_ip in self._requests_log.keys():
                self._requests_log[request_ip] += 1
            else:
                self._requests_log[request_ip] = 1

    def _check_brute_force(self):
        """
        function check if there is brute force attack, according to the log
        requests dictionary
        """
        with self._request_log_lock, self._delay_ip_lock:
            for ip, ip_request_amount in self._requests_log.items():
                if ip_request_amount >= self.MAX_REQUEST_IN_HALF_MINUTE:
                    self._delay_ip[ip] = True
            self._requests_log.clear()

    def _add_delay(self, ip, response):
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
            if ip in self._delay_ip.keys():
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
