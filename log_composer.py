import os
from datetime import date
from fpdf import FPDF

LOG_FILE_PATH = "log_related/logs/daily_log_"
BACKGROUND_FILE_PATH = "log_related/images/background.jpg"
CALIBRI_BOLD_FILE_PATH = "log_related/fonts/calibri_bold.ttf"
CALIBRI_LIGHT_FILE_PATH = "log_related/fonts/calibri_light.ttf"
LOG_TITLE = "WAF Daily Log"


class LogComposer:
    _daily_log = None

    def __init__(self):
        """
        This function will initialize the pdf log document and will set the title
        """
        self._daily_log = FPDF()
        self._daily_log.add_page()
        self._load_calibri_font(CALIBRI_BOLD_FILE_PATH, CALIBRI_LIGHT_FILE_PATH)
        self._set_main_page_header(LOG_TITLE)

    def _load_calibri_font(self, calibri_bold_file_path, calibri_light_file_path):
        self._remove_calibri_font_configuration(calibri_bold_file_path, calibri_light_file_path)
        if os.path.exists(calibri_bold_file_path) and os.path.exists(calibri_light_file_path):
            self._daily_log.add_font("Calibri", 'B', calibri_bold_file_path, uni=True)
            self._daily_log.add_font("Calibri Light", "", calibri_light_file_path, uni=True)
        else:
            raise FileNotFoundError

    def _remove_calibri_font_configuration(self, calibri_bold_file_path, calibri_light_file_path):
        calibri_bold_file_path = calibri_bold_file_path.replace(".ttf", ".pkl")
        calibri_light_file_path = calibri_light_file_path.replace(".ttf", ".pkl")
        if os.path.exists(calibri_bold_file_path):
            os.remove(calibri_bold_file_path)
        if os.path.exists(calibri_light_file_path):
            os.remove(calibri_light_file_path)

    def _set_main_page_header(self, log_title):
        """
        This function will write the log's main page date, title and background
        :param log_title: the title of the main page
        :type log_title: string
        """
        self._daily_log.image(BACKGROUND_FILE_PATH, x=0, y=0, w=200, h=300)
        self._daily_log.set_font("Calibri Light", size=12)
        self._daily_log.cell(w=190, h=5, txt=date.today().strftime("%d/%m/%Y"), ln=1, align='R')
        self._daily_log.set_font("Calibri", 'B', size=72)
        self._daily_log.cell(w=200, h=250, txt=log_title, ln=1, align='C')

    def _set_attack_page_header(self, title):
        """
        This function will write the the log's attacks page date, title and background
        :param title: the title of the page
        :type title: string
        """
        self._daily_log.image(BACKGROUND_FILE_PATH, x=0, y=0, w=200, h=300)
        self._daily_log.set_font("Calibri Light", size=12)
        self._daily_log.cell(w=190, h=5, txt=date.today().strftime("%d/%m/%Y"), ln=1, align='R')
        self._daily_log.set_font("Calibri", "BU", size=32)
        self._daily_log.cell(w=200, h=20, txt=title, ln=1, align='C')

    def write_to_log(self, info):
        """
        This function will write all the attacks information
        into the daily log file and will save it
        :param info: all the attacks information
        :type info: dict
        """
        for attack_name, attack_info in info.items():
            self._daily_log.add_page()
            self._set_attack_page_header(attack_name)
            self._daily_log.set_font("Calibri Light", size=14)
            self._write_info(attack_info["general"])
            self._daily_log.cell(w=200, h=5, txt="", ln=2)
            self._daily_log.cell(w=200, h=10, txt="Detected risks:", ln=2, align='L')
            for detected_risk_info in attack_info["attacks"]:
                self._write_info(detected_risk_info)
            self._daily_log.cell(w=200, h=5, txt="", ln=2)
            self._write_info(attack_info["links"])
        self._daily_log.output(LOG_FILE_PATH + date.today().strftime("%d/%m/%Y").replace('/', '_') + ".pdf")

    def _write_info(self, info):
        """
        This function will write the given information into the daily log file
        :param info: the information to write
        :type info: string
        """
        for info_line in info.split('\n'):
            self._daily_log.cell(w=200, h=12, txt=info_line, ln=2, align='L')
