from fpdf import FPDF

LOG_FILE_PATH = "daily_log.pdf"


class LogWriter:
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
        """
        attack_list = attack_info.split('\n')
        for row in attack_list:
            self._daily_log.cell(200, 10, txt=row, ln=2, align='L')
        self._daily_log.image("icon.jpeg", x=80, w=70, h=80)

    def save_log(self):
        """
        This function will save the daily log document
        """
        self._daily_log.output(LOG_FILE_PATH)
