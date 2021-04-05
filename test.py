import notify2
import os


def _notify_user(title, content, icon_name):
    notify2.init("WAF WAF")
    ICONS_FILE_PATH = os.getcwd() + "/misc/icons/"
    icon_path = ICONS_FILE_PATH + icon_name
    notifier = notify2.Notification(title, content, icon_path)
    notifier.set_timeout(5000)
    notifier.show()
_notify_user("Successful Email!", "Successfully sent the daily log", "mail.png")
input("continue")
_notify_user("Refuse Error!", "The following recipients have refused to receive the daily log:"
                              f"\n{str(['noam', 'ron', 'lidor'])}", "refuse.png")
input("continue")
_notify_user("Authentication Error!", "WAF WAF account failed to authenticate\n"
                                      "Please contact the manufacturers", "lock.png")
input("continue")
_notify_user("Refuse Error!", "All recipients have refused to receive the daily log", "refuse.png")
input("continue")
_notify_user("Unexpected Error!", "An error has occurred while sending the daily log", "error.png")