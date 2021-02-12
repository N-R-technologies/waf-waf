import os
import time
import threading
import sched
import toml


class BruteForceDetector:
    LOGIN_URL_FILE_PATH = "login_url.toml"
    DELAY_TIME = 3
    MAX_LOGINS_PER_MINUTE = 15
    MAX_REQUESTS_PER_HALF_MINUTE = 20
    CHECK_BRUTE_FORCE_TIMER = 30
    CHECK_LOGIN_BRUTE_FORCE_TIMER = 60
    RESET_BLOCKED_USERS_TIMER = 7200
    RESET_DELAY_IP_TIMER = 3600

    COMMON_LOGIN_URL = ("login", "signin")
    COMMON_LOGIN_FIELDS = {"uname", "username", "pass", "password",
                           "email", "mail", "user", "access", "identity",
                           "credential", "user account", "access code",
                           "login name", "name"}
    COMMON_USERNAME_FIELDS = ("uname", "username", "user", "access",
                              "identity", "credential", "user account",
                              "access code", "login name", "name")

    _login_url = ""
    _blocked_users = list()
    _users_logins_attempts = dict()
    _users_requests_counter = dict()
    _users_delay = dict()
    _blocked_users_lock = threading.Lock()
    _logins_counter_lock = threading.Lock()
    _requests_counter_lock = threading.Lock()
    _users_delay_lock = threading.Lock()

    def __init__(self):
        self._load_login_url_configuration(self.LOGIN_URL_FILE_PATH)
        self._schedule_threads()

    def _load_login_url_configuration(self, login_url_file_path):
        if os.path.exists(login_url_file_path):
            self._login_url = toml.load(login_url_file_path).get("url", None)

    def _schedule_threads(self):
        """
        This function will start all the brute force scheduler threads
        """
        login_brute_force_scheduler = threading.Thread(target=self._login_brute_force_scheduler)
        brute_force_scheduler = threading.Thread(target=self._brute_force_scheduler)
        reset_blocked_users_scheduler = threading.Thread(target=self._reset_blocked_users_scheduler)
        reset_users_delay_scheduler = threading.Thread(target=self._reset_users_delay_scheduler)
        login_brute_force_scheduler.start()
        brute_force_scheduler.start()
        reset_blocked_users_scheduler.start()
        reset_users_delay_scheduler.start()

    def is_request_blocked(self, request):
        """
        This function will check if the user that tries to login is blocked
        :param request: the request
        :type request: mitmproxy.http.HTTPFlow.request
        :return: True, if he is blocked, otherwise, False
        :rtype: bool
        """
        if self._is_login_request(request):
            username = self._get_username(request)
            return username in self._blocked_users
        return False

    def count_user_requests(self, request, user_ip_address):
        """
        This function will count the requests each user sends
        :param request: the user's request
        :param user_ip_address: the user's ip address
        :type request: mitmproxy.http.HTTPFlow.request
        :type user_ip_address: str
        """
        self._count_login_attempt(request)
        self._count_request(user_ip_address)

    def add_delay(self, response, user_ip_address):
        """
        This function will add the Retry-After header to the response,
        if the response is from an ip that brute forced the server recently
        :param response: the response packet
        :param user_ip_address: the ip of the response receiving user
        :type response: mitmproxy.http.HTTPFlow.response
        :type user_ip_address: str
        """
        with self._users_delay_lock:
            if user_ip_address in self._users_delay.keys():
                if self._users_delay[user_ip_address]:
                    response.headers["Retry-After"] = self.DELAY_TIME
                    self._users_delay[user_ip_address] = False
                else:
                    self._users_delay[user_ip_address] = True

    def _count_login_attempt(self, request):
        """
        This function will count a login attempt to the user who sent it
        :param request: the request a user sent
        :type request: mitmproxy.http.HTTPFlow.request
        """
        if self._is_login_request(request):
            username = self._get_username(request.urlencoded_form)
            if username is not None:
                with self._logins_counter_lock:
                    if username in self._users_logins_attempts.keys():
                        self._users_logins_attempts[username] += 1
                    else:
                        self._users_logins_attempts[username] = 1

    def _count_request(self, user_ip_address):
        """
        This function will count a request to the user who sent it
        :param user_ip_address: the ip of the request's sender
        :type user_ip_address: str
        """
        with self._requests_counter_lock:
            if user_ip_address in self._users_requests_counter.keys():
                self._users_requests_counter[user_ip_address] += 1
            else:
                self._users_requests_counter[user_ip_address] = 1

    def _is_login_request(self, request):
        """
        This function will check if the given request is a login request,
        by its URL, or fields, if its a POST request
        :param request: the request
        :type request mitmproxy.http.HTTPFlow.request
        :return: True, if it is a login request, otherwise, False
        :rtype: bool
        """
        login_fields_found = False
        if request.method == "POST":
            keys_set = set(request.urlencoded_form.keys())
            login_fields_found = self.COMMON_LOGIN_FIELDS & keys_set and any(map(request.url.__contains__, self.COMMON_LOGIN_FIELDS))
        return self._login_url in request.url or login_fields_found

    def _get_username(self, login_request):
        """
        This function will return the username
        of the user who sent a login request
        :param login_request: the login request
        :type login_request: MultiDict
        :return: the username of the user that tries to login, if not found then None
        :rtype: str
        """
        request_fields = login_request.keys()
        for username_field in self.COMMON_USERNAME_FIELDS:
            if username_field in request_fields:
                return login_request[username_field]
        return None

    def _login_brute_force_scheduler(self):
        """
        This function will schedule the login brute force
        detection function to be executed every minute
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.CHECK_LOGIN_BRUTE_FORCE_TIMER, 1, self._check_brute_force_login)
            scheduler.run()

    def _brute_force_scheduler(self):
        """
        This function will schedule the brute force
        detection function to be executed every 30 seconds
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.CHECK_BRUTE_FORCE_TIMER, 1, self._check_brute_force)
            scheduler.run()

    def _reset_blocked_users_scheduler(self):
        """
        This function will schedule the reset blocked users
        function to be executed every 2 hours
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.RESET_BLOCKED_USERS_TIMER, 1, self._reset_block_users)
            scheduler.run()

    def _reset_users_delay_scheduler(self):
        """
        This function will schedule the reset users delay
        function to be executed every hour
        """
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.RESET_DELAY_IP_TIMER, 1, self._reset_users_delay)
            scheduler.run()

    def _check_brute_force_login(self):
        """
        This function will check if a user tried to login too many times
        per minute. if so, it will block his login attempts for a permanent time
        """
        with self._logins_counter_lock, self._blocked_users_lock:
            for username, logins_amount in self._users_logins_attempts.items():
                if logins_amount >= self.MAX_LOGINS_PER_MINUTE:
                    self._blocked_users.append(username)
            self._users_logins_attempts.clear()

    def _check_brute_force(self):
        """
        This function will check if a user tried to send requests too many times
        per half a minute. if so, it will delay his next requests for a permanent time
        """
        with self._requests_counter_lock, self._users_delay_lock:
            for user_ip_address, requests_amount in self._users_requests_counter.items():
                if requests_amount >= self.MAX_REQUESTS_PER_HALF_MINUTE:
                    self._users_delay[user_ip_address] = True
            self._users_requests_counter.clear()

    def _reset_block_users(self):
        """
        This function will reset the blocked users list
        """
        with self._blocked_users_lock:
            self._blocked_users.clear()

    def _reset_users_delay(self):
        """
        This function will reset the users delay dictionary
        """
        with self._users_delay_lock:
            self._users_delay.clear()
