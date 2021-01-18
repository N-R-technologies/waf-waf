from datetime import date
import numpy as np
import matplotlib.pyplot as plt
from detective.toolbox.risk_levels import RiskLevels


class GraphHandler:
    GRAPH_FILE_PATH = "log_related/data/graphs/risks_graph_"
    GRAPH_Y_TITLE = "Risks Found"
    GRAPH_X_TITLE = "Risk Levels"
    NEGLIGIBLE = 1/5
    SLIGHT = 1/2
    MODERATE = 1/3
    CRITICAL = 1
    CATASTROPHIC = 1
    GREEN_IMPACT = 0.2
    YELLOW_IMPACT = 0.4
    ORANGE_IMPACT = 0.6
    RED_IMPACT = 0.8
    GREEN = "#00FF00"
    YELLOW = "#FFFF00"
    ORANGE = "#FF6400"
    RED = "#FF0000"
    BLANK = "#FFFFFF"

    _multiplying_factors = []

    def __init__(self):
        self._multiplying_factors = [self.NEGLIGIBLE, self.SLIGHT, self.MODERATE, self.CRITICAL, self.CATASTROPHIC]
        plt.rcdefaults()

    def create_graph(self, risks_found_today):
        """
        This function will create an image graph based on the lenses findings
        :param risks_found_today: all the risk levels which were found today
        :type risks_found_today: list
        """
        objects = tuple([risk_level for risk_level in vars(RiskLevels)["_member_names_"]])
        y_pos = np.arange(len(objects))
        graph_colors = self._calculate_risk_colors(risks_found_today)
        y_limit = 5
        if y_limit < max(risks_found_today[RiskLevels.NEGLIGIBLE:]) < 10:
            y_limit = 10
        elif max(risks_found_today[RiskLevels.NEGLIGIBLE:]) > 10:
            y_limit = max(risks_found_today[RiskLevels.NEGLIGIBLE:])
        plt.ylim([0, y_limit])
        plt.locator_params(axis='y', nbins=y_limit)
        plt.xticks(y_pos, objects, fontsize=8)
        plt.ylabel(self.GRAPH_Y_TITLE)
        plt.xlabel(self.GRAPH_X_TITLE)
        plt.bar(y_pos, risks_found_today, align="center", alpha=1, color=graph_colors)
        plt.savefig(self.GRAPH_FILE_PATH + date.today().strftime("%d_%m_%Y") + ".png")

    def _calculate_risk_colors(self, risks_found_today):
        """
        This function will calculate the color the graph
        will show for each risk level according to its impact
        :param risks_found_today: all the risk levels which were found today
        :type risks_found_today: list
        :return: each of risk levels colors
        :rtype: list
        """
        graph_colors = [self.BLANK]
        for risk_occurrences, multiplying_factor in zip(risks_found_today[RiskLevels.NEGLIGIBLE:], self._multiplying_factors):
            current_impact_level = risk_occurrences * multiplying_factor
            if self.GREEN_IMPACT <= current_impact_level < self.YELLOW_IMPACT:
                graph_colors.append(self.GREEN)
            elif self.YELLOW_IMPACT <= current_impact_level <= self.ORANGE_IMPACT:
                graph_colors.append(self.YELLOW)
            elif self.ORANGE_IMPACT < current_impact_level <= self.RED_IMPACT:
                graph_colors.append(self.ORANGE)
            elif self.RED_IMPACT < current_impact_level:
                graph_colors.append(self.RED)
            else:
                graph_colors.append(self.BLANK)
        return graph_colors
