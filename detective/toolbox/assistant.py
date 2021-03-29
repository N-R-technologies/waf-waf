from importlib import import_module
from detective.toolbox import lenses
from detective.toolbox import RiskLevels


class Assistant:
    _risks_findings = [0] * len(RiskLevels)
    _info = {}
    _general_info = {}
    _links = {}

    def __init__(self):
        for lens in lenses.__all__:
            lens_info = import_module(f"detective.toolbox.lenses.{lens}.info")
            self._general_info[lens_info.category] = lens_info.general_info
            self._links[lens_info.category] = lens_info.links_for_info

    def set_findings(self, attack_risks_findings):
        self._risks_findings = list(map(lambda new_finding, existing_finding: new_finding + existing_finding, attack_risks_findings, self._risks_findings))

    def set_info(self, category, attack_info):
        if category not in self._info:
            self._info[category] = {
                "general": self._general_info[category],
                "attacks": set(attack_info),
                "links": self._links[category]
            }
        else:
            for attack_detected in attack_info:
                self._info[category]["attacks"].add(attack_detected)

    def _get_info(self):
        summarized_info = {}
        for attack_name, attack_info in self._info.items():
            detected_risks = "Detected risks:\n" + "".join(attack_info["attacks"])
            summarized_info[attack_name] = f'{attack_info["general"]}\n{detected_risks}\n{attack_info["links"]}'
        return summarized_info
