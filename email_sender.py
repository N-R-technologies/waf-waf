import toml
import os
from datetime import date
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

BOT_ADDRESS_FILE_PATH = "bot_address.toml"
USER_ADDRESSES_FILE_PATH = "user_addresses.toml"
LOG_SUBJECT = "Daily log - "
LOG_DESCRIPTION = "Hello there, this is your daily log from the WAF.\nIf you have any problems you can " \
                  "contact us anytime.\nIn addition, if you recognize that you have been attacked and we " \
                  "were unable to identify it, we would like you to send a full report of the case.\n\n" \
                  "Please do not reply to this address! You will not receive any response.\n" \
                  "Instead, contact noammiz918@gmail.com or ronkonis1@gmail.com.\nHave a good one!"


class EmailSender:
    _bot_address = ""
    _bot_pass = ""

    def __init__(self):
        self._load_bot_address_configuration(BOT_ADDRESS_FILE_PATH)

    def send_log(self, daily_log):
        """
        This function will send the daily log to the users email addresses
        :param daily_log: the daily log's file path
        :type daily_log: string
        :return: if the function succeeded sending the emails
        :rtype: boolean
        """
        user_addresses = self._load_user_addresses_configuration(USER_ADDRESSES_FILE_PATH)
        if len(user_addresses) > 0:
            daily_log_mail = MIMEMultipart()
            daily_log_mail["From"] = self._bot_address
            daily_log_mail["To"] = ", ".join(user_addresses)
            daily_log_mail["Date"] = formatdate(localtime=True)
            daily_log_mail["Subject"] = LOG_SUBJECT + date.today().strftime("%d/%m/%Y")
            daily_log_description = LOG_DESCRIPTION

            daily_log_mail.attach(MIMEText(daily_log_description))
            with open(daily_log, "rb") as log_to_send:
                part = MIMEApplication(log_to_send.read(), Name=os.path.basename(daily_log))
            part["Content-Disposition"] = 'attachment; filename="%s"' % os.path.basename(daily_log)
            daily_log_mail.attach(part)

            try:
                server_ssl = smtplib.SMTP_SSL("smtp.gmail.com", 465)
                server_ssl.ehlo()
                server_ssl.login(self._bot_address, self._bot_pass)
                server_ssl.sendmail(daily_log_mail["From"], daily_log_mail["To"], daily_log_mail.as_string())
                server_ssl.close()
                return True
            except Exception:
                return False
        return True

    def _load_bot_address_configuration(self, bot_address_file_path):
        if os.path.exists(bot_address_file_path):
            bot_address = toml.load(bot_address_file_path)
            self._bot_address = bot_address["address"]
            self._bot_pass = bot_address["pass"]
        else:
            raise FileNotFoundError

    def _load_user_addresses_configuration(self, user_addresses_file_path):
        user_addresses = dict()
        if os.path.exists(user_addresses_file_path):
            user_addresses = toml.load(user_addresses_file_path).get("addresses", {})
        else:
            open(user_addresses_file_path, 'w').close()

        addresses = set()
        for address in user_addresses.values():
            addresses.add(address)
        return addresses
