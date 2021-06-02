import re
from detective.toolbox import RiskLevels


class BasicChecks:
    @staticmethod
    def cookie_steal(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search(r"""\bdocument\.cookie\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def alert(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""\balert\b\s*(?:(?:>|%3e)\s*)?\([^\)]+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def eval(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""\beval\b\s*\([^\)]+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def utf7(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""\bcharset\b\s*=\s*utf-7""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def script(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search(r"""(?:<|%3c)\s*script(?:.+?(?:>|%3e)|(?:>|%3e).+?)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def script_access(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(?:<|%3c)\s*embed(?:/|\s).*?allowscriptaccess\s*=(?:(?:\"|'|`)\s*)?always""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def tag_attributes(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:<|%3c)\s*(?:img|body|i?frame|a|svg|isindex)(?:/|\s).+?=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def img_src(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:<|%3c)\s*img(?:/|\s).*?(?:src|dnysrc|lowsrc)\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def tags_src(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:<|%3c)\s*(?:input|bgsound|xml)(?:/|\s).*?src\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def div_background(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:<|%3c)\s*div(?:/|\s).*?style\s*=\s*(?:(?:\"|'|`)\s*)?(?:background-image|width)\s*:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def style_background(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:<|%3c)\s*style(?:/|\s)*.*?{\s*(?:(?:\"|'|`)\s*)?background(?:-image)?\s*:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def tags_background(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:<|%3c)\s*(?:table|td)(?:/|\s).*?background\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def link_base_href(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:<|%3c)\s*(?:link|base)(?:/|\s).*?href\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def br_size(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:<|%3c)\s*br(?:/|\s).*?size\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def meta_content(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:<|%3c)\s*meta(?:/|\s).*?(?:content|url)\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def html_body_xml(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:<|%3c)\s*html(?:/|\s)*(?:>|%3e)\s*(?:<|%3c)\s*body(?:/|\s)*(?:>|%3e).*?to\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def object_type(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:<|%3c)\s*object(?:/|\s).*?type\s*=(?:(?:\"|'|`)\s*)?text\s*/\s*x-scriptlet""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def style_type(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:<|%3c)\s*style(?:/|\s).*?type\s*=(?:(?:\"|'|`)\s*)?text\s*/\s*(?:javascript|css)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def list_style_image(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:<|%3c)\s*style(?:/|\s)*.*?{\s*list-style-image\s*:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_style_comment(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""style\s*=\s*.*?(?:/\*.*?\*/)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_html_comment(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""(?:<|%3c)!--.*--(?:>|%3e)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def fscommand(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""fscommand""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onabort(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onabort""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onactivate(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onactivate""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onafterprint(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onafterprint""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onafterupdate(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onafterupdate""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeactivate(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbeforeactivate""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforecopy(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbeforecopy""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforecut(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbeforecut""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforedeactivate(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbeforedeactivate""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeeditfocus(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbeforeeditfocus""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforepaste(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbeforepaste""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeprint(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbeforeprint""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeunload(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbeforeunload""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbeforeupdate(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbeforeupdate""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbegin(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbegin""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onblur(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onblur""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onbounce(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onbounce""", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncellchange(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""oncellchange""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onchange(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onchange""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onclick(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onclick""", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncontextmenu(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""oncontextmenu""", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncontrolselect(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""oncontrolselect""", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncopy(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""oncopy""", request) else RiskLevels.NO_RISK

    @staticmethod
    def oncut(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""oncut""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondataavailable(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondataavailable""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondatasetchanged(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondatasetchanged""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondatasetcomplete(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondatasetcomplete""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondblclick(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondblclick""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondeactivate(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondeactivate""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondrag(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondrag""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragend(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondragend""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragleave(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondragleave""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragenter(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondragenter""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragover(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondragover""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragdrop(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondragdrop""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondragstart(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondragstart""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ondrop(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ondrop""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onend(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onend""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onerror(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onerror""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onerrorupdate(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onerrorupdate""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfilterchange(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onfilterchange""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfinish(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onfinish""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfocus(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onfocus""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfocusin(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onfocusin""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onfocusout(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onfocusout""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onhashchange(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onhashchange""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onhelp(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onhelp""", request) else RiskLevels.NO_RISK

    @staticmethod
    def oninput(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""oninput""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onkeydown(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onkeydown""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onkeypress(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onkeypress""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onkeyup(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onkeyup""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onlayoutcomplete(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onlayoutcomplete""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onload(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onload""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onlosecapture(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onlosecapture""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmediacomplete(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmediacomplete""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmediaerror(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmediaerror""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmessage(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmessage""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmousedown(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmousedown""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseenter(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmouseenter""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseleave(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmouseleave""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmousemove(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmousemove""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseout(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmouseout""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseover(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmouseover""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmouseup(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmouseup""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmousewheel(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmousewheel""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmove(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmove""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmoveend(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmoveend""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onmovestart(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onmovestart""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onoffline(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onoffline""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ononline(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ononline""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onoutofsync(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onoutofsync""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onpaste(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onpaste""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onpause(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onpause""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onpopstate(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onpopstate""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onprogress(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onprogress""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onpropertychange(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onpropertychange""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onreadystatechange(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onreadystatechange""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onredo(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onredo""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrepeat(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onrepeat""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onreset(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onreset""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onresize(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onresize""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onresizeend(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onresizeend""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onresizestart(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onresizestart""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onresume(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onresume""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onreverse(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onreverse""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrowsenter(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onrowsenter""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrowexit(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onrowexit""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrowdelete(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onrowdelete""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onrowinserted(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onrowinserted""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onscroll(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onscroll""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onseek(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onseek""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onselect(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onselect""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onselectionchange(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onselectionchange""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onselectstart(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onselectstart""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onstart(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onstart""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onstop(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onstop""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onstorage(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onstorage""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onsyncrestored(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onsyncrestored""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onsubmit(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onsubmit""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ontimeerror(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ontimeerror""", request) else RiskLevels.NO_RISK

    @staticmethod
    def ontrackchange(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""ontrackchange""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onundo(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onundo""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onunload(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onunload""", request) else RiskLevels.NO_RISK

    @staticmethod
    def onurlflip(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""onurlflip""", request) else RiskLevels.NO_RISK

    @staticmethod
    def seeksegmenttime(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""seeksegmenttime""", request) else RiskLevels.NO_RISK

    @staticmethod
    def hash_location(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""\blocation\b.*?\..*?\bhash\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def self_contained_payload(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\bwith\b\s*\(.+?\)[\s\w]+\(""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def c_style_loops(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\b(?:do|while|for)\b.*?\([^)]*\).*?{)|(?:}.*?\b(?:do|while|for)\b.*?\([^)]*\))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def c_style_short_condition(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""[=><].+?\?.+?:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def jquery_selector(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\$\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def conditional_tokens(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""@(?:cc_on|set)\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def firefox_url_handler(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""(?:\bfirefoxurl\s*:)|(?:\bwyciwyg\s*:)""", request) \
            else RiskLevels.NO_RISK
