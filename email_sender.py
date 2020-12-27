import toml
import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

EMAILS_FILE_PATH = "email_addresses.toml"
WAF_BOT_ADDRESS = "WAFDetectiveBot@gmail.com"
WAF_BOT_PASS = "wafbot2003"
LOG_SUBJECT = "Daily log"
LOG_DESCRIPTION = "Hello there, this is your daily log from the WAF.\nIf you have any problems you can " \
                  "contact us anytime.\nIn addition, if you recognize that you have been attacked and we " \
                  "were unable to identify it, we would like you to send a full report of the case.\n\n" \
                  "Please do not reply to this address! You will not receive any response.\n" \
                  "Instead, contact noammiz918@gmail.com or ronkonis1@gmail.com.\nHave a good one!"


class EmailSender:
    @staticmethod
    def send_log(daily_log):
        """
        This function will send the daily log to the users email addresses
        :param daily_log: the daily log's file path
        :type daily_log: string
        :return: if the function succeeded sending the emails
        :rtype: boolean
        """
        email_addresses = EmailSender.load_emails_configuration(EMAILS_FILE_PATH)
        if len(email_addresses) > 0:
            daily_log_mail = MIMEMultipart()
            daily_log_mail['From'] = WAF_BOT_ADDRESS
            daily_log_mail['To'] = ", ".join(email_addresses)
            daily_log_mail['Date'] = formatdate(localtime=True)
            daily_log_mail['Subject'] = LOG_SUBJECT
            daily_log_description = LOG_DESCRIPTION

            daily_log_mail.attach(MIMEText(daily_log_description))
            with open(daily_log, "rb") as log_to_send:
                part = MIMEApplication(log_to_send.read(), Name=os.path.basename(daily_log))
            part['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(daily_log)
            daily_log_mail.attach(part)

            try:
                server_ssl = smtplib.SMTP_SSL("smtp.gmail.com", 465)
                server_ssl.ehlo()
                server_ssl.login(WAF_BOT_ADDRESS, WAF_BOT_PASS)
                server_ssl.sendmail(daily_log_mail['From'], daily_log_mail['To'], daily_log_mail.as_string())
                server_ssl.close()
                return True
            except Exception:
                return False
        return True

    @staticmethod
    def load_emails_configuration(emails_file_path):
        emails = dict()
        if os.path.exists(emails_file_path):
            emails = toml.load(emails_file_path).get("emails", {})
        else:
            open(emails_file_path, 'w').close()

        email_addresses = set()
        for email_address in emails.values():
            email_addresses.add(email_address)
        return email_addresses
