import toml
import os
from datetime import date
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate


class EmailSender:
    LOG_FILE_PATH = "logger/data/logs/daily_log_"
    BOT_EMAIL_FILE_PATH = "logger/data/bot_email.toml"
    USER_EMAILS_FILE_PATH = "logger/data/user_emails.toml"
    LOG_SUBJECT = "Daily Log - "
    LOG_DESCRIPTION = "Hello there, this is your daily log from the WAF.\nIf you have any problems you can " \
                      "contact us anytime.\nIn addition, if you recognize that you have been attacked and we " \
                      "were unable to identify it, we would like you to send a full report of the case.\n\n" \
                      "Please do not reply to this address! You will not receive any response.\n" \
                      "Instead, contact noammiz918@gmail.com or ronkonis1@gmail.com.\nHave a good one!"

    _bot_address = ""
    _bot_pass = ""

    def __init__(self):
        self._load_bot_email_configuration(self.BOT_EMAIL_FILE_PATH)

    def send_log(self):
        """
        This function will send the daily log to the users email addresses
        """
        user_addresses = self._load_user_addresses_configuration(self.USER_EMAILS_FILE_PATH)
        if len(user_addresses) > 0:
            daily_log_mail = MIMEMultipart()
            daily_log_mail["From"] = self._bot_address
            daily_log_mail["To"] = ", ".join(user_addresses)
            daily_log_mail["Date"] = formatdate(localtime=True)
            daily_log_mail["Subject"] = self.LOG_SUBJECT + date.today().strftime("%d/%m/%Y")
            daily_log_description = self.LOG_DESCRIPTION
            daily_log_mail.attach(MIMEText(daily_log_description))

            daily_log_path = self.LOG_FILE_PATH + date.today().strftime("%d_%m_%Y") + ".pdf"
            with open(daily_log_path, "rb") as daily_log:
                part = MIMEApplication(daily_log.read(), Name=os.path.basename(daily_log_path))
            part["Content-Disposition"] = 'attachment; filename="%s"' % os.path.basename(daily_log_path)
            daily_log_mail.attach(part)

            try:
                server_ssl = smtplib.SMTP_SSL("smtp.gmail.com", 465)
                server_ssl.ehlo()
                server_ssl.login(self._bot_address, self._bot_pass)
                server_ssl.sendmail(daily_log_mail["From"], daily_log_mail["To"], daily_log_mail.as_string())
                server_ssl.close()
            except Exception:
                pass

    def _load_bot_email_configuration(self, bot_email_file_path):
        if os.path.exists(bot_email_file_path):
            bot_email = toml.load(bot_email_file_path)
            self._bot_address = bot_email["address"]
            self._bot_pass = bot_email["pass"]
        else:
            raise FileNotFoundError

    def _load_user_addresses_configuration(self, user_emails_file_path):
        user_emails = dict()
        if os.path.exists(user_emails_file_path):
            user_emails = toml.load(user_emails_file_path).get("emails", {})

        user_addresses = set()
        for address in user_emails.values():
            user_addresses.add(address)
        return user_addresses
