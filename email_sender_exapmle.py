import yagmail
import smtplib
import sqlite3
import time

def read_daily_log():
    with open("daily_log.txt", 'r') as f:
        return f.read()

def get_email_addresses():
    email_addresses = list()
    try:
        conn = sqlite3.connect("email_addresses_database.sqlite")
        cur = conn.cursor()
        cur.execute("SELECT * FROM EMAIL_ADDRESSES")
        email_addresses = cur.fetchall()
    except Exception as e:
        print(e)

    return email_addresses

def send_emails(email_addresses, daily_log):
    """
    email_addresses.append("bot email address") # remove this line later. it is used to send an email to ourselves
    print("Sending emails...")
    try:
        sender_email = "bot email address"
        subject = "Daily log"
        sender_password = input(f'Please, enter the password for {sender_email}:\n')
        yag = yagmail.SMTP(user=sender_email, password=sender_password)
        contents = [
            "This is the first paragraph in our email",
            "As you can see, we can send a list of strings,",
            "being this our third one",
        ]
        yag.send(email_addresses, subject, contents)
    except Exception as e:
        print(e)
"""
    email_addresses.append("bot email address")
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
        print('successfully sent the email')
    except Exception as e:
        print("failed to send email\n", e)

def main():
    start_time = time.time()
    daily_log = read_daily_log()
    email_addresses = get_email_addresses()
    send_emails(email_addresses, daily_log)
    print("--- %s seconds ---" % (time.time() - start_time))

if __name__ == '__main__':
    main()