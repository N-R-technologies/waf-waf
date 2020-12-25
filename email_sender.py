import yagmail
import smtplib


class EmailSender:
    @staticmethod
    def get_email_addresses():
        """ This function will read the users email addresses from the toml configuration file """
        email_addresses = dict()
        # reading data from emails.toml here
        # see "toml_use_example" to check how to read data from toml files
        return email_addresses

    @staticmethod
    def send_emails(daily_log):
        """ This function will send the daily log to the users email addresses
        :param email_addresses: the email addresses of the users
        :param daily_log: the daily log file to send
        :type email_addresses: list
        :type daily_log: pdf file
        :return: if it succeed to send the emails
        :rtype: boolean"""
        email_addresses = EmailSender.get_email_addresses()
        email_addresses.append("bot email address")  # remove this line later. it is used to send an email to ourselves
        email_addresses['bot name'] = "bot email address"
        FROM = "bot email address"
        TO = email_addresses
        SUBJECT = "Daily log"
        TEXT = daily_log
        # Prepare actual message
        message = """From: %s\nTo: %s\nSubject: %s\n\n%s
        
        """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
        try:
            server_ssl = smtplib.SMTP_SSL("smtp.gmail.com", 465)
            server_ssl.ehlo()
            server_ssl.login("bot email address", "bot email password")
            server_ssl.sendmail(FROM, TO, message)
            server_ssl.close()
            return True
        except Exception:
            return False
