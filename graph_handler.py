from datetime import date
import numpy as np
import matplotlib.pyplot as plt
from risk_level import RiskLevel


class GraphHandler:

    def __init__(self):
        plt.rcdefaults()

    def create_graph(self, risks_found_day):
        """
        This function will create an image graph based on the detectors findings
        """
        objects = tuple([risk_level for risk_level in RiskLevel])
        y_pos = np.arange(len(objects))
        plt.bar(y_pos, risks_found_day, align='center', alpha=0.5)
        plt.xticks(y_pos, objects)
        plt.locator_params(axis="y", nbins=max(objects) * 2)
        plt.ylabel('Risks Found')
        plt.xlabel('Risks Levels')
        plt.title('Risks Found In The Last Day')
        graph_name = "risks_graph-" + date.today().strftime("%d/%m/%Y").replace('/', '_')
        plt.savefig(graph_name + '.png')

