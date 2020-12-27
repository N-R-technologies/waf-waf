from fpdf import FPDF
from email_sender import EmailSender


class LogHandler:
    _daily_log = ""

    def __init__(self):
        """
        This function will initialize the pdf log document and will set the title
        """
        self._daily_log = FPDF()
        self._daily_log.add_page()
        self._daily_log.set_font("Times", 'BU', size=30)
        self._daily_log.cell(200, 10, txt="Daily Log WAF", ln=1, align='C')
        self._daily_log.set_font("Arial", size=10)

    def write_to_log(self, attack_info):
        """
        This function will write the attack information into the daily log file
        :param attack_info: the attack information
        :type attack_info: string
        :return: None
        """
        attack_list = attack_info.split('\n')
        for row in attack_lsit:
            self._daily_log.cell(200, 10, txt=row, ln=2, align='L')
        self._daily_log.image("icon.jpeg", x=80, w=70, h=80)

    def save_send(self):
        """
        This function will save the daily log document and will send it to the users
        :return: if the email send action succeeded
        :rtype: boolean
        """
        self._daily_log.output("daily_log.pdf")
        return EmailSender.send_log("daily_log.pdf")
