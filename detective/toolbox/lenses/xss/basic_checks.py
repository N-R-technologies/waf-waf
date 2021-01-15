import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:
    @staticmethod
    def cookie_steal(request):
        """
        This function will check if the user tries to
        inject users cookies stealing
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CATASTROPHIC if re.search(r"""\bdocument\.cookie\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def alert(request):
        """
        This function will check if the user tries to inject an alert function
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""\balert\b\s*(?:>\s*)?\([^\)]+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def eval(request):
        """
        This function will check if the user tries to inject an eval function
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""\beval\b\s*\([^\)]+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def utf7(request):
        """
        This function will check if the user tries to
        inject a script encoded with UTF-7
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""\bcharset\b\s*=\s*utf-7""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def script(request):
        """
        This function will check if the user tries to
        inject any kind of script as input
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CATASTROPHIC if re.search(r"""<\s*script(?:/|\s|\()(?:.+?>|>.+?)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def script_access(request):
        """
        This function will check if the user tries to allow himself
        script access via the embed tag's allowscriptaccess attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL \
            if re.search(r"""<\s*embed(?:/|\s).*?allowscriptaccess\s*=(?:(?:\"|'|`)\s*)?always""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def tag_attributes(request):
        """
        This function will check if the user tries to
        use any attributes of different tags
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"""<\s*(?:img|body|i?frame|a|svg|isindex)(?:/|\s).+?=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def img_src(request):
        """
        This function will check if the user tries to
        inject a script via the img or input tag's src attributes
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*img(?:/|\s).*?(?:src|dnysrc|lowsrc)\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def old_img_src(request):
        """
        This function will check if the user tries to
        inject a script via the old img tag's src attributes
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*img(?:/|\s).*?(?:src|dnysrc|lowsrc)\s*=\s*(?:(?:\"|'|`)\s*)?(?:vbscript\s*:\s*msgbox|livescript\s*:\s*\[)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def tags_src(request):
        """
        This function will check if the user tries to
        inject a script via different tags src attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*(?:input|bgsound|xml)(?:/|\s).*?src\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def div_background(request):
        """
        This function will check if the user tries to
        inject a script via div tag's background attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*div(?:/|\s).*?style\s*=\s*(?:(?:\"|'|`)\s*)?(?:background-image|width)\s*:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def style_background(request):
        """
        This function will check if the user tries to
        inject a script via style tag's background attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*style(?:/|\s)*>.*?{\s*(?:(?:\"|'|`)\s*)?background-image\s*:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def tags_background(request):
        """
        This function will check if the user tries to
        inject a script via different tags background attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*(?:table|td)(?:/|\s).*?background\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def link_base_href(request):
        """
        This function will check if the user tries to
        inject a script via the link or base tags href attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*(?:link|base)(?:/|\s).*?href\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def br_size(request):
        """
        This function will check if the user tries to
        inject a script via the br tag's size attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*br(?:/|\s).*?size\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def meta_content(request):
        """
        This function will check if the user tries to
        inject a script via the meta tag's content attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*meta(?:/|\s).*?(?:content|url)\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def html_body_xml(request):
        """
        This function will check if the user tries to inject a
        script through xml via the html and body tags to attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*html(?:/|\s)*>\s*<\s*body(?:/|\s)*>.*?to\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def object_type(request):
        """
        This function will check if the user tries to
        inject a script via the object tag's type attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*object(?:/|\s).*?type\s*=(?:(?:\"|'|`)\s*)?text\s*/\s*x-scriptlet""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def style_type(request):
        """
        This function will check if the user tries to
        inject a script via the style tag's type attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*style(?:/|\s).*?type\s*=(?:(?:\"|'|`)\s*)?text\s*/\s*(?:javascript|css)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def list_style_image(request):
        """
        This function will check if the user tries to
        inject a script via the style tag's list-style-image attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*style(?:/|\s).*?{\s*list-style-image\s*:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_style_comments(request):
        """
        This function will check if the user's request contains html comment
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"""style\s*=\s*.*?(/\*.*?\*/)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_html_comments(request):
        """
        This function will check if the user's request contains html comment
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.NEGLIGIBLE if re.search(r"""<!--.*-->""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def fscommand(request):
        """
        this function check if the user try to
        execute the function fscommand
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """

        return RiskLevels.SLIGHT if re.search(r"fscommand", request) else RiskLevels.NO_RISK

    @staticmethod
    def onabort(request):
        """
        this function check if the user try to
        execute the function onabort
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onabort", request) else RiskLevels.NO_RISK

    @staticmethod
    def onactivate(request):
        """
        this function check if the user try to
        execute the function onactivate
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onactivate", request) else RiskLevels.NO_RISK


    @staticmethod
    def onafterprint(request):
        """
        this function check if the user try to
        execute the function onafterprint
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onafterprint", request) else RiskLevels.NO_RISK

    @staticmethod
    def onafterupdate(request):
        """
        this function check if the user try to
        execute the function onafterupdate
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onafterupdate", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeactivate(request):
        """
        this function check if the user try to
        execute the function onbeforeactivate
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbeforeactivate", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforecopy(request):
        """
        this function check if the user try to
        execute the function onbeforecopy
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbeforecopy", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforecut(request):
        """
        this function check if the user try to
        execute the function onbeforecut
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbeforecut", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforedeactivate(request):
        """
        this function check if the user try to
        execute the function onbeforedeactivate
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbeforedeactivate", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeeditfocus(request):
        """
        this function check if the user try to
        execute the function onbeforeeditfocus
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbeforeeditfocus", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforepaste(request):
        """
        this function check if the user try to
        execute the function onbeforepaste
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbeforepaste", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeprint(request):
        """
        this function check if the user try to
        execute the function onbeforeprint
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbeforeprint", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeunload(request):
        """
        this function check if the user try to
        execute the function onbeforeunload
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbeforeunload", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeupdate(request):
        """
        this function check if the user try to
        execute the function onbeforeupdate
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbeforeupdate", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbegin(request):
        """
        this function check if the user try to
        execute the function onbegin
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbegin", request) else RiskLevels.NO_RISK

    @staticmethod
    def onblur(request):
        """
        this function check if the user try to
        execute the function onblur
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onblur", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbounce(request):
        """
        this function check if the user try to
        execute the function onbounce
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onbounce", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncellchange(request):
        """
        this function check if the user try to
        execute the function oncellchange
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"oncellchange", request) else RiskLevels.NO_RISK

    @staticmethod
    def onchange(request):
        """
        this function check if the user try to
        execute the function onchange
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onchange", request) else RiskLevels.NO_RISK

    @staticmethod
    def onclick(request):
        """
        this function check if the user try to
        execute the function onclick
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onclick", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncontextmenu(request):
        """
        this function check if the user try to
        execute the function oncontextmenu
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"oncontextmenu", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncontrolselect(request):
        """
        this function check if the user try to
        execute the function oncontrolselect
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"oncontrolselect", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncopy(request):
        """
        this function check if the user try to
        execute the function oncopy
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"oncopy", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncut(request):
        """
        this function check if the user try to
        execute the function oncut
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"oncut", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondataavailable(request):
        """
        this function check if the user try to
        execute the function ondataavailable
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondataavailable", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondatasetchanged(request):
        """
        this function check if the user try to
        execute the function ondatasetchanged
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondatasetchanged", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondatasetcomplete(request):
        """
        this function check if the user try to
        execute the function ondatasetcomplete
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondatasetcomplete", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondblclick(request):
        """
        this function check if the user try to
        execute the function ondblclick
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondblclick", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondeactivate(request):
        """
        this function check if the user try to
        execute the function ondeactivate
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondeactivate", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondrag(request):
        """
        this function check if the user try to
        execute the function ondrag
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondrag", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragend(request):
        """
        this function check if the user try to
        execute the function ondragend
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondragend", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragleave(request):
        """
        this function check if the user try to
        execute the function ondragleave
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondragleave", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragenter(request):
        """
        this function check if the user try to
        execute the function ondragenter
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondragenter", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragover(request):
        """
        this function check if the user try to
        execute the function ondragover
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondragover", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragdrop(request):
        """
        this function check if the user try to
        execute the function ondragdrop
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondragdrop", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragstart(request):
        """
        this function check if the user try to
        execute the function ondragstart
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondragstart", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondrop(request):
        """
        this function check if the user try to
        execute the function ondrop
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ondrop", request) else RiskLevels.NO_RISK

    @staticmethod
    def onend(request):
        """
        this function check if the user try to
        execute the function onend
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onend", request) else RiskLevels.NO_RISK

    @staticmethod
    def onerror(request):
        """
        this function check if the user try to
        execute the function onerror
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onerror", request) else RiskLevels.NO_RISK

    @staticmethod
    def onerrorupdate(request):
        """
        this function check if the user try to
        execute the function onerrorupdate
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onerrorupdate", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfilterchange(request):
        """
        this function check if the user try to
        execute the function onfilterchange
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onfilterchange", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfinish(request):
        """
        this function check if the user try to
        execute the function onfinish
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onfinish", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfocus(request):
        """
        this function check if the user try to
        execute the function onfocus
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onfocus", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfocusin(request):
        """
        this function check if the user try to
        execute the function onfocusin
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onfocusin", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfocusout(request):
        """
        this function check if the user try to
        execute the function onfocusout
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onfocusout", request) else RiskLevels.NO_RISK

    @staticmethod
    def onhashchange(request):
        """
        this function check if the user try to
        execute the function onhashchange
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onhashchange", request) else RiskLevels.NO_RISK

    @staticmethod
    def onhelp(request):
        """
        this function check if the user try to
        execute the function onhelp
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onhelp", request) else RiskLevels.NO_RISK

    @staticmethod
    def oninput(request):
        """
        this function check if the user try to
        execute the function oninput
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"oninput", request) else RiskLevels.NO_RISK

    @staticmethod
    def onkeydown(request):
        """
        this function check if the user try to
        execute the function onkeydown
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onkeydown", request) else RiskLevels.NO_RISK

    @staticmethod
    def onkeypress(request):
        """
        this function check if the user try to
        execute the function onkeypress
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onkeypress", request) else RiskLevels.NO_RISK

    @staticmethod
    def onkeyup(request):
        """
        this function check if the user try to
        execute the function onkeyup
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onkeyup", request) else RiskLevels.NO_RISK

    @staticmethod
    def onlayoutcomplete(request):
        """
        this function check if the user try to
        execute the function onlayoutcomplete
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onlayoutcomplete", request) else RiskLevels.NO_RISK

    @staticmethod
    def onload(request):
        """
        this function check if the user try to
        execute the function onload
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onload", request) else RiskLevels.NO_RISK

    @staticmethod
    def onlosecapture(request):
        """
        this function check if the user try to
        execute the function onlosecapture
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onlosecapture", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmediacomplete(request):
        """
        this function check if the user try to
        execute the function onmediacomplete
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmediacomplete", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmediaerror(request):
        """
        this function check if the user try to
        execute the function onmediaerror
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmediaerror", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmessage(request):
        """
        this function check if the user try to
        execute the function onmessage
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmessage", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmousedown(request):
        """
        this function check if the user try to
        execute the function onmousedown
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmousedown", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseenter(request):
        """
        this function check if the user try to
        execute the function onmouseenter
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmouseenter", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseleave(request):
        """
        this function check if the user try to
        execute the function onmouseleave
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmouseleave", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmousemove(request):
        """
        this function check if the user try to
        execute the function onmousemove
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmousemove", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseout(request):
        """
        this function check if the user try to
        execute the function onmouseout
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmouseout", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseover(request):
        """
        this function check if the user try to
        execute the function onmouseover
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmouseover", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseup(request):
        """
        this function check if the user try to
        execute the function onmouseup
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmouseup", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmousewheel(request):
        """
        this function check if the user try to
        execute the function onmousewheel
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmousewheel", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmove(request):
        """
        this function check if the user try to
        execute the function onmove
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmove", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmoveend(request):
        """
        this function check if the user try to
        execute the function onmoveend
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmoveend", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmovestart(request):
        """
        this function check if the user try to
        execute the function onmovestart
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onmovestart", request) else RiskLevels.NO_RISK

    @staticmethod
    def onoffline(request):
        """
        this function check if the user try to
        execute the function onoffline
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onoffline", request) else RiskLevels.NO_RISK

    @staticmethod
    def ononline(request):
        """
        this function check if the user try to
        execute the function ononline
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ononline", request) else RiskLevels.NO_RISK

    @staticmethod
    def onoutofsync(request):
        """
        this function check if the user try to
        execute the function onoutofsync
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onoutofsync", request) else RiskLevels.NO_RISK

    @staticmethod
    def onpaste(request):
        """
        this function check if the user try to
        execute the function onpaste
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onpaste", request) else RiskLevels.NO_RISK

    @staticmethod
    def onpause(request):
        """
        this function check if the user try to
        execute the function onpause
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onpause", request) else RiskLevels.NO_RISK

    @staticmethod
    def onpopstate(request):
        """
        this function check if the user try to
        execute the function onpopstate
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onpopstate", request) else RiskLevels.NO_RISK

    @staticmethod
    def onprogress(request):
        """
        this function check if the user try to
        execute the function onprogress
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onprogress", request) else RiskLevels.NO_RISK

    @staticmethod
    def onpropertychange(request):
        """
        this function check if the user try to
        execute the function onpropertychange
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onpropertychange", request) else RiskLevels.NO_RISK

    @staticmethod
    def onreadystatechange(request):
        """
        this function check if the user try to
        execute the function onreadystatechange
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onreadystatechange", request) else RiskLevels.NO_RISK

    @staticmethod
    def onredo(request):
        """
        this function check if the user try to
        execute the function onredo
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onredo", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrepeat(request):
        """
        this function check if the user try to
        execute the function onrepeat
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onrepeat", request) else RiskLevels.NO_RISK

    @staticmethod
    def onreset(request):
        """
        this function check if the user try to
        execute the function onreset
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onreset", request) else RiskLevels.NO_RISK

    @staticmethod
    def onresize(request):
        """
        this function check if the user try to
        execute the function onresize
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onresize", request) else RiskLevels.NO_RISK

    @staticmethod
    def onresizeend(request):
        """
        this function check if the user try to
        execute the function onresizeend
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onresizeend", request) else RiskLevels.NO_RISK

    @staticmethod
    def onresizestart(request):
        """
        this function check if the user try to
        execute the function onresizestart
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onresizestart", request) else RiskLevels.NO_RISK

    @staticmethod
    def onresume(request):
        """
        this function check if the user try to
        execute the function onresume
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onresume", request) else RiskLevels.NO_RISK

    @staticmethod
    def onreverse(request):
        """
        this function check if the user try to
        execute the function onreverse
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onreverse", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrowsenter(request):
        """
        this function check if the user try to
        execute the function onrowsenter
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onrowsenter", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrowexit(request):
        """
        this function check if the user try to
        execute the function onrowexit
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onrowexit", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrowdelete(request):
        """
        this function check if the user try to
        execute the function onrowdelete
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onrowdelete", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrowinserted(request):
        """
        this function check if the user try to
        execute the function onrowinserted
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onrowinserted", request) else RiskLevels.NO_RISK

    @staticmethod
    def onscroll(request):
        """
        this function check if the user try to
        execute the function onscroll
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onscroll", request) else RiskLevels.NO_RISK

    @staticmethod
    def onseek(request):
        """
        this function check if the user try to
        execute the function onseek
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onseek", request) else RiskLevels.NO_RISK

    @staticmethod
    def onselect(request):
        """
        this function check if the user try to
        execute the function onselect
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onselect", request) else RiskLevels.NO_RISK

    @staticmethod
    def onselectionchange(request):
        """
        this function check if the user try to
        execute the function onselectionchange
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onselectionchange", request) else RiskLevels.NO_RISK

    @staticmethod
    def onselectstart(request):
        """
        this function check if the user try to
        execute the function onselectstart
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onselectstart", request) else RiskLevels.NO_RISK

    @staticmethod
    def onstart(request):
        """
        this function check if the user try to
        execute the function onstart
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onstart", request) else RiskLevels.NO_RISK

    @staticmethod
    def onstop(request):
        """
        this function check if the user try to
        execute the function onstop
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onstop", request) else RiskLevels.NO_RISK

    @staticmethod
    def onstorage(request):
        """
        this function check if the user try to
        execute the function onstorage
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onstorage", request) else RiskLevels.NO_RISK

    @staticmethod
    def onsyncrestored(request):
        """
        this function check if the user try to
        execute the function onsyncrestored
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onsyncrestored", request) else RiskLevels.NO_RISK

    @staticmethod
    def onsubmit(request):
        """
        this function check if the user try to
        execute the function onsubmit
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onsubmit", request) else RiskLevels.NO_RISK

    @staticmethod
    def ontimeerror(request):
        """
        this function check if the user try to
        execute the function ontimeerror
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ontimeerror", request) else RiskLevels.NO_RISK

    @staticmethod
    def ontrackchange(request):
        """
        this function check if the user try to
        execute the function ontrackchange
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"ontrackchange", request) else RiskLevels.NO_RISK

    @staticmethod
    def onundo(request):
        """
        this function check if the user try to
        execute the function onundo
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onundo", request) else RiskLevels.NO_RISK

    @staticmethod
    def onunload(request):
        """
        this function check if the user try to
        execute the function onunload
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onunload", request) else RiskLevels.NO_RISK

    @staticmethod
    def onurlflip(request):
        """
        this function check if the user try to
        execute the function onurlflip
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"onurlflip", request) else RiskLevels.NO_RISK

    @staticmethod
    def seeksegmenttime(request):
        """
        this function check if the user try to
        execute the function seeksegmenttime
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"seeksegmenttime", request) else RiskLevels.NO_RISK

    @staticmethod
    def html_break(request):
        """
        this function check if the user try to
        use html breaks
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"([\"'].*?>)|(#.+?\)[\"\s]*>)|(['\"][,;\s]+\w*[\[(])|(>.*?<\s*\/?[\w\s]+>)|()", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def hash_location(request):
        """
        this function check if the user try to
        get to location.hash
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL if re.search(r"\blocation\b.*?\..*?\bhash\b", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def self_contained_payload(request):
        """
        this function check if the user try to
        attack the server with contained payload xss attack
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL if re.search(r"\bwith\b\s*\(.+?\)[\s\w]+\(", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def c_style_loops(request):
        """
        this function check if the user try to
        use c style loops
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"(\b(do|while|for)\b.*?\([^)]*\).*?\{)|(\}.*?\b(do|while|for)\b.*?\([^)]*\))", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def c_style_short_condition(request):
        """
        this function check if the user try to
        use c style shor if condition
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"[=<>].+?\?.+?:", request)\
            else RiskLevels.NO_RISK

    @staticmethod
    def jquery_selector(request):
        """
        this function check if the user try to
        use jquery selector
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.NEGLIGIBLE if re.search(r"\$\(.+?\)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def conditional_tokens(request):
        """
        this function check if the user try to
        use condition tokens
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r" @(cc_on|set)\b", request)\
            else RiskLevels.NO_RISK

    @staticmethod
    def fire_fox_url_handler(request):
        """
        this function check if the user try to
        use url handler
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.NEGLIGIBLE if re.search(r"(\bfirefoxurl\s*:)|(\bwyciwyg\s*:)", request) \
            else RiskLevels.NO_RISK
