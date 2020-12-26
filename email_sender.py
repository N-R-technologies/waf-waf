import smtplib
import toml
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate


class EmailSender:
    @staticmethod
    def get_email_addresses():
        """ This function will read the users email addresses from the toml configuration file """
        with open("email_addresses.toml", 'r') as email_file:  # open the file for reading
            print("Reading content from file...")
            email_addresses = toml.loads(email_file.read())
            email_file.close()
            emails_lst = []
            for name in email_addresses["emails"]:
                emails_lst.append(email_addresses["emails"][name])
        return emails_lst

    @staticmethod
    def send_emails(daily_log):
        """
        This function will send the daily log to the users email addresses
        :param daily_log: the daily log file to send
        :type daily_log: pdf file
        :return: if it succeed to send the emails
        :rtype: boolean
        """
        daily_log_mail = MIMEMultipart()
        daily_log_mail['From'] = "WAFDetectiveBot@gmail.com"
        daily_log_mail['To'] = ", ".join(EmailSender.get_email_addresses())
        daily_log_mail['Date'] = formatdate(localtime=True)
        daily_log_mail['Subject'] = "Daily log"
        daily_log_description = "Hello there, this is your daily log from the WAF\n" \
               "If you have any problems dont answer this email. send your question to: noammiz918@gmail.com\n" \
               "have a good one!"

        daily_log_mail.attach(MIMEText(daily_log_description))
        with open(daily_log, "rb") as log_to_send:
            part = MIMEApplication(
                log_to_send.read(),
                Name=basename(daily_log)
            )
        part['Content-Disposition'] = 'attachment; filename="%s"' % basename(daily_log)
        daily_log_mail.attach(part)
        try:
            server_ssl = smtplib.SMTP_SSL("smtp.gmail.com", 465)
            server_ssl.ehlo()
            server_ssl.login("wafdetectivebot@gmail.com", "wafbot2003")
            server_ssl.sendmail(daily_log_mail['From'], daily_log_mail['To'], daily_log_mail.as_string())
            server_ssl.close()
            return True
        except Exception:
            return False
