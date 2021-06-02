import os
from datetime import date
from fpdf import FPDF


class LogComposer:
    LOG_FILE_PATH = "logger/data/logs/daily_log_"
    GRAPH_FILE_PATH = "logger/data/graphs/risks_graph_"
    BACKGROUND_FILE_PATH = "logger/data/images/background.jpg"
    CALIBRI_BOLD_FILE_PATH = "logger/data/fonts/calibri_bold.ttf"
    CALIBRI_LIGHT_FILE_PATH = "logger/data/fonts/calibri_light.ttf"
    LOG_TITLE = "WAF Daily Log"
    GRAPH_TITLE = "Risks Found In The Last Day"

    _daily_log = FPDF()

    def __init__(self):
        self._daily_log.add_page()
        self._load_calibri_font(self.CALIBRI_BOLD_FILE_PATH, self.CALIBRI_LIGHT_FILE_PATH)
        self._set_main_page(self.LOG_TITLE)

    def _load_calibri_font(self, calibri_bold_file_path, calibri_light_file_path):
        if os.path.exists(calibri_bold_file_path) and os.path.exists(calibri_light_file_path):
            self._daily_log.add_font("Calibri", 'B', calibri_bold_file_path, uni=True)
            self._daily_log.add_font("Calibri Light", "", calibri_light_file_path, uni=True)
        else:
            raise FileNotFoundError
        self._remove_calibri_font_configuration(calibri_bold_file_path, calibri_light_file_path)

    def _remove_calibri_font_configuration(self, calibri_bold_file_path, calibri_light_file_path):
        calibri_bold_configuration = calibri_bold_file_path.replace(".ttf", ".pkl")
        calibri_light_configuration = calibri_light_file_path.replace(".ttf", ".pkl")
        os.remove(calibri_bold_configuration)
        os.remove(calibri_light_configuration)

    def _set_main_page(self, log_title):
        self._daily_log.image(self.BACKGROUND_FILE_PATH, x=0, y=0, w=200, h=300)
        self._daily_log.set_font("Calibri Light", size=12)
        self._daily_log.cell(w=190, h=5, txt=date.today().strftime("%d/%m/%Y"), ln=1, align='R')
        self._daily_log.set_font("Calibri", 'B', size=72)
        self._daily_log.cell(w=200, h=250, txt=log_title, ln=1, align='C')

    def write_log(self, info):
        for attack_name, attack_info in info.items():
            self._daily_log.add_page()
            self._set_page_header(attack_name)
            self._daily_log.set_font("Calibri Light", size=14)
            for detail in attack_info.split('\n'):
                self._daily_log.cell(w=200, h=12, txt=detail, ln=2, align='L')
        self._add_graph(self.GRAPH_TITLE, self.GRAPH_FILE_PATH + date.today().strftime("%d_%m_%Y") + ".png")
        self._daily_log.output(self.LOG_FILE_PATH + date.today().strftime("%d_%m_%Y") + ".pdf")

    def _set_page_header(self, title):
        self._daily_log.image(self.BACKGROUND_FILE_PATH, x=0, y=0, w=200, h=300)
        self._daily_log.set_font("Calibri Light", size=12)
        self._daily_log.cell(w=190, h=5, txt=date.today().strftime("%d/%m/%Y"), ln=1, align='R')
        self._daily_log.set_font("Calibri", "BU", size=32)
        self._daily_log.cell(w=200, h=20, txt=title, ln=1, align='C')

    def _add_graph(self, graph_title, graph_file_path):
        self._daily_log.add_page()
        self._set_page_header(graph_title)
        self._daily_log.image(graph_file_path, x=-10, y=35, w=240, h=230)
