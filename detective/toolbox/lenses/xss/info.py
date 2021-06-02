category = "XSS"

general_info = "XSS (Cross-site scripting ) is a web security vulnerability that allows an\n" \
               "attacker to compromise the interactions that users have with a vulnerable\napplication. " \
               "It allows an attacker to circumvent the same origin policy,\nwhich is designed to segregate " \
               "different websites from each other.\nXSS vulnerabilities normally allow an attacker to " \
               "masquerade as a victim user,\nto carry out any actions that the user is able to " \
               "perform,\nand to access any of the user's data.\nIf the victim user has privileged access " \
               "within the application,\nthen the attacker might be able to gain full control over all of\n" \
               "the application's functionality and data.\n"

deep_info = {
    "cookie_steal": "* Cookie Steal: An attacker can inject and see sensitive data\n  "
                    "by printing or accessing the variable 'document.cookie'.\n",

    "alert": "* Alert: A common javascript function, which is being used by XSS attackers.\n "
             "The function simply pops up a notification window.\n",

    "eval": "* Eval: With the eval function attackers can execute external code on the\n  "
            "server side. This can be super dangerous because this code can harm the server.\n",

    "utf7": "* UTF-7: With the UTF-7 encoding, a potential attacker can hide his malicious\n  code and attack "
            "The server, with out the parser or input checker even know about that.\n",

    "script": "* Script: By using the script tag, an attacker can inject\n  and run malicious script on the server.\n  "
              "this kind of tag is very common and used a lot by XSS attackers.\n",

    "script_access": "* Script Access: If an attacker is able to change the allow_access_script\n  tag to True, he can "
                     "inject the server\n  with a script tag, and force him to execute it.\n",

    "tag_attributes": "* Tag Attributes: Attributes in different tage that provide an attacker\n  entry point to "
                      "inject and harm the server\n  by passing him malicious script hiding with png or svg format.\n",

    "img_src": "* img src: An attacker can use the image tag in order to include malicious code.\n",

    "tags_src": "* Tags src: An attacker can use tags like input or xml\n  to include malicious code that will be "
                "stored\n  on the server side, and user will run it.\n",

    "div_background": "* div background: An attacker can create a new div in the website frontend,\n  and set "
                      " its background to contain\n  malicious code which will run when the frontend load "
                      "on the client side.\n",

    "style_background": "* style background: An attacker can create a new style in the website frontend,\n  and set "
                        "its background to contain\n  malicious code which will run when the frontend load "
                        "on the client side.\n",

    "tags_background": "* Tags background: An attacker can create backgrounds in the website frontend,\n  "
                      "using different tags, to contain malicious\n  code which will run when the frontend load "
                      "on the client side.\n",

    "link_base_href": "* link/base href: An Attacker can include some links in his attack,\n  "
                      "to malicious files or websites.\n",

    "br_size": "* br size: The size element in the br tag can come before the function,\n  "
               "and disturb the parser.\n",

    "meta_content": "* meta content: An option that can be used by an attacker\n  to include malicious "
                    "content that will harm\n  users when they access the server.\n",

    "html_body_xml": "* html body xml: With editing the html body of the frontend as he wish\n  a potential attacker "
                     "can harm the server, and the users.\n",

    "object_type": "* object type: The object type attribute is a way which an attacker\n  can inject "
                   "malicious script with XSS into the server.\n",

    "style_type": "* style type: The style type attribute is a way which an attacker\n  can inject "
                  "malicious script with XSS into the server.\n",

    "list_style_image": "* list style image: list style image attribute is a way which an attacker\n  can inject "
                        "malicious script with XSS into the server.\n",

    "xss_style_comment": "* XSS Style Comments: Those are not dangerous for themselves,\n  but there is an "
                          "indicator of an attack that will harm the server.\n",

    "xss_html_comment": "* HTML Style Comments: Those are not dangerous for themselves,\n  but there is an "
                         "indicator of an attack that will harm the server.\n",

    "fscommand": "* fscommand: An attacker can use this when executed\n  from within an embedded flash object.\n",

    "onabort": "* onabort: When a user aborts the loading of an image.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onactivate": "* onactivate: Calls when object is set as the active element.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onafterprint": "* onafterprint: Activates after user prints or previews print job.\n  "
                    "An attacker can use this to execute a script when it is called.\n",

    "onafterupdate": "* onafterupdate: Activates on data object after updating data in the source object.\n  "
                    "An attacker can use this to execute a script when it is called.\n",

    "onbeforeactivate": "* onbeforeactivate: Fires before the object is set as the active element.\n  "
                        "An attacker can use this to execute a script when it is called.\n",

    "onbeforecopy": "* onbeforecopy: Executes right before a selection is copied to the clipboard.\n  "
                    "An attacker can use this to execute a script when it is called.\n",

    "onbeforecut": "* onbeforecut: Executes right before a selection is being cut.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "onbeforedeactivate": "* onbeforedeactivate: Fires right after the 'activeelement' is changed from "
                          "the current object.\n  An attacker can use this to execute a script when it is called.\n",

    "onbeforeeditfocus": "* onbeforeeditfocus: Fires before an object contained in an editable element enters\n  "
                      "a ui-activated state or when an editable container object is control selected.\n  "
                      "An attacker can use this to execute a script when it is called.\n",

    "onbeforepaste": "* onbeforepaste: A user needs to be tricked into pasting, or be forced\n  into it using "
                     "the execcommand('paste')\n function.\n  An attacker can use this to execute a script "
                     "when it is called.\n",

    "onbeforeprint": "* onbeforeprint: A user needs to be tricked into printing.\n  "
                     "An attacker can use the print(), or execcommand('print') function.\n  "
                     "An attacker can use this to execute a script when it is called.\n",

    "onbeforeunload": "* onbeforeunload: A user needs to be tricked into closing\n  the browser. "
                      "An attacker cannot unload windows,\n  unless it was spawned from the parent.\n  "
                      "An attacker can use this to execute a script when it is called.\n",

    "onbeforeupdate": "* onbeforeupdate: Activates on data object before updating data\n  in the source object. "
                    "An attacker can use this to execute a script when it is called.\n",

    "onbegin": "* onbegin: Fires immediately when the element’s timeline begins.\n  "
               "An attacker can use this to execute a script when it is called.\n",

    "onblur": "* onblur: When another popup is loaded and window looses focus.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onbounce": "* onbounce: When the behavior property of the marquee\n  "
                "object is set to “alternate” and the contents of the marquee\n  "
                "reach one side of the window.\n  An attacker can use this to execute "
                "a script when it is called.\n",

    "oncellchange": "* oncellchange: When data changes in the data provider.\n  "
                    "An attacker can use this to execute a script when it is called.\n",

    "onchange": "* onchange: Select text, or textarea field loses focus and its value has been modified.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onclick": "* onclick: When a user clicks on a form.\n  "
               "An attacker can use this to execute a script when it is called.\n",

    "oncontextmenu": "* oncontextmenu: When a user right clicks on something.\n  "
                     "An attacker can use this to execute a script when it is called.\n",

    "oncontrolselect": "* oncontrolselect: When the user is about to make a control selection "
                       "of an object.\n  An attacker can use this to execute a script when it is called.\n",

    "oncopy": "* oncopy: When a user copies something, or it can be\n  "
              "exploited using the execcommand('copy') command.\n  "
              "An attacker can use this to execute a script when it is called.\n",

    "oncut": "* oncut: When a user cuts something, or it can be\n  "
             "exploited using the execcommand('cut') command.\n  "
             "An attacker can use this to execute a script when it is called.\n",

    "ondataavailable": "* ondataavailable: When a user changes data in an element.\n  "
                       "An attacker can use this to execute a script when it is called.\n",

    "ondatasetchanged": "* ondatasetchanged: When the data set exposed by a data\n  "
                        "source object changes.\n  An attacker can use this to execute a script "
                        "when it is called.\n",

    "ondatasetcomplete": "* ondatasetcomplete: Fires to indicate that all data is available\n  "
                         "from the data source object.\n  An attacker can use this to execute "
                         "a script when it is called.\n",

    "ondblclick": "* ondblclick: Whan a user double-clicks a form element or a link.\n  "
                  "An attacker can use this to execute a script when it is called.\n",

    "ondeactivate": "* ondeactivate: When the active element is changed\n  "
                    "from the current object to another object in the parent document.\n  "
                    "An attacker can use this to execute a script when it is called.\n",

    "ondrag": "* ondrag: When a user drags an object.\n  "
              "An attacker can use this to execute a script when it is called.\n",

    "ondragend": "* ondragend: When a user finishes to drag an object.\n  "
                 "An attacker can use this to execute a script when it is called.\n",

    "ondragleave": "* ondragleave: When a user leaves the dragging\n  in an object's valid location.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "ondragenter": "* ondragenter: When a user enters the dragging\n  in an object's valid location.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "ondragover": "* ondragover: When a user drags over an object's valid location.\n  "
                  "An attacker can use this to execute a script when it is called.\n",

    "ondragdrop": "* ondragdrop: When a user drops an object (e.g. file) into the browser window.\n  "
                  "An attacker can use this to execute a script when it is called.\n",

    "ondragstart": "* ondragstart: When a user starts a dragging operation.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "ondrop": "* ondrop: When a user drops an object (e.g. file) into the browser window.\n  "
              "An attacker can use this to execute a script when it is called.\n",

    "onend": "* onend: When the timeline ends.\n  "
              "An attacker can use this to execute a script when it is called.\n",

    "onerror": "* onerror: When a loading of a document or image causes an error.\n  "
               "An attacker can use this to execute a script when it is called.\n",

    "onerrorupdate": "* onerrorupdate: When an error occurs while updating\n  "
                     "the associated data in the data source object.\n  "
                     "An attacker can use this to execute a script when it is called.\n",

    "onfilterchange": "* onfilterchange: When a visual filter completes state change.\n  "
                      "An attacker can use this to execute a script when it is called.\n",

    "onfinish": "* onfinish: When marquee is finished looping.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onfocus": "* onfocus: When the window gets focused.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onfocusin": "* onfocusin: When the window gets focused.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onfocusout": "* onfocusout: When the window looses focus.\n  "
                  "An attacker can use this to execute a script when it is called.\n",

    "onhashchange": "* onhashchange: When the fragment identifier part\n  "
                    "of the document’s current address changes.\n  "
                    "An attacker can use this to execute a script when it is called.\n",

    "onhelp": "* onhelp: When the user hits f1 while the window is on focus.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "oninput": "* oninput: When the text content of an element\n  "
               "is changed through the user interface.\n  "
               "An attacker can use this to execute a script when it is called.\n",

    "onkeydown": "* onkeydown: When the user depresses a key.\n  "
                 "An attacker can use this to execute a script when it is called.\n",

    "onkeypress": "* onkeypress: When the user presses or holds down a key.\n  "
                  "An attacker can use this to execute a script when it is called.\n",

    "onkeyup": "* onkeyup: Whan the user releases a key.\n  "
               "An attacker can use this to execute a script when it is called.\n",

    "onlayoutcomplete": "* onlayoutcomplete: When the user would have to print or print preview.\n  "
                        "An attacker can use this to execute a script when it is called.\n",

    "onload": "* onload: When the window loads itself.\n  "
              "An attacker can use this to execute a script when it is called.\n",

    "onlosecapture": "* onlosecapture: Can be exploited by the releasecapture() method.\n  "
                     "An attacker can use this to execute a script when it is called.\n",

    "onmediacomplete": "* onmediacomplete: When the streaming media file is being used,\n  "
                       "before the file starts playing.\n  "
                       "An attacker can use this to execute a script when it is called.\n",

    "onmediaerror": "* onmediaerror: When an error occurs while the user opens\n  "
                    "a page in the browser that contains a media file.\n  "
                    "An attacker can use this to execute a script when it is called.\n",

    "onmessage": "* onmessage: When the document received a message.\n  "
                 "An attacker can use this to execute a script when it is called.\n",

    "onmousedown": "* onmousedown: When the user to clicks on an image.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "onmouseenter": "* onmouseenter: When the user enters with his cursor\n  "
                    "an object or area. An attacker can use this\n  "
                    "to execute a script when it is called.\n",

    "onmouseleave": "* onmouseleave: When the user leaves with his cursor\n  "
                    "an image or table area. An attacker can use this\n  "
                    "to execute a script when it is called.\n",

    "onmousemove": "* onmousemove: When the user moves his cursor over an image or table.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "onmouseout": "* onmouseout: When the user leaves with his cursor\n  "
                    "an image or table area. An attacker can use this\n  "
                    "to execute a script when it is called.\n",

    "onmouseover": "* onmouseover: When the user moves his cursor over an object or area.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "onmouseup": "* onmouseup: When the user clicks on an image.\n  "
                 "An attacker can use this to execute a script when it is called.\n",

    "onmousewheel": "* onmousewheel: When the user uses his mouse wheel.\n  "
                    "An attacker can use this to execute a script when it is called.\n",

    "onmove": "* onmove: When the user moves the page.\n  "
              "An attacker can use this to execute a script when it is called.\n",

    "onmoveend": "* onmoveend: When the user finishes moving the page.\n  "
                 "An attacker can use this to execute a script when it is called.\n",

    "onmovestart": "* onmovestart: When the user starts moving the page.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "onoffline": "* onoffline: When the browser is on online mode\n  "
                 "and it begins to work on offline.\n  An attacker can use this "
                 "to execute a script when it is called.\n",

    "ononline": "* ononline: When the browser is on offline mode\n  "
                 "and it begins to work on online.\n  An attacker can use this "
                 "to execute a script when it is called.\n",

    "onoutofsync": "* onoutofsync: When the element’s ability to play its media\n  "
                   "as defined by the timeline is interrupted.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "onpaste": "* onpaste: When the user pastes or an attacker uses\n  "
               "the execcommand('paste') function.\n  An attacker can "
               "use this to execute a script when it is called.\n",

    "onpause": "* onpause: When the timeline pauses, including the body element.\n  "
               "An attacker can use this to execute a script when it is called.\n",

    "onpopstate": "* onpopstate: When the user navigates to the session history.\n  "
                  "An attacker can use this to execute a script when it is called.\n",

    "onprogress": "* onprogress: When a flash movie is loading.\n  "
                  "An attacker can use this to execute a script when it is called.\n",

    "onpropertychange": "* onpropertychange: When the user changes an element property.\n  "
                        "An attacker can use this to execute a script when it is called.\n",

    "onreadystatechange": "* onreadystatechange: When the user changes the 'readystate'.\n  "
                          "An attacker can use this to execute a script when it is called.\n",

    "onredo": "* onredo: When the user goes forward in the undo transaction history.\n  "
              "An attacker can use this to execute a script when it is called.\n",

    "onrepeat": "* onrepeat: When each repetition of the timeline,\n  "
                "excluding the first full cycle, is on.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onreset": "* onreset: When the user resets a form.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onresize": "* onresize: When the user resizes the window.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onresizeend": "* onresizeend: When the user ends resizing the window.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "onresizestart": "* onresizestart: When the user starts resizing the window.\n  "
                     "An attacker can use this to execute a script when it is called.\n",

    "onresume": "* onresume: When the timeline resumes, including the body element,\n  "
                "on every element that becomes active.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onreverse": "* onreverse: When the timeline begins to play backwards,\n  "
                 "and if the element has a repeat count greater than one.\n  "
                 "An attacker can use this to execute a script when it is called.\n",

    "onrowsenter": "* onrowsenter: When the user changes a row in a data source.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "onrowexit": "* onrowexit: When the user finishes changing a row in a data source.\n  "
                 "An attacker can use this to execute a script when it is called.\n",

    "onrowdelete": "* onrowdelete: When the user deletes a row in a data source.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "onrowinserted": "* onrowinserted: When the user inserts a row in a data source.\n  "
                     "An attacker can use this to execute a script when it is called.\n",

    "onscroll": "* onscroll: When the user scrolls, or attacker using\n  "
                "the scrollby() function. An attacker can use this\n  "
                "to execute a script when it is called.\n",

    "onseek": "* onseek: When the timeline is set to play\n  "
              "in any direction other than forward.\n  "
              "An attacker can use this to execute a script when it is called.\n",

    "onselect": "* onselect: When the user selects text.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "onselectionchange": "* onselectionchange: When the user selects text and changes it.\n  "
                         "An attacker can use this to execute a script when it is called.\n",

    "onselectstart": "* onselectstart: When the user starts to select text.\n  "
                     "An attacker can use this to execute a script when it is called.\n",

    "onstart": "* onstart: When each marquee loop begins.\n  "
               "An attacker can use this to execute a script when it is called.\n",

    "onstop": "* onstop: When the user presses the stop button,\n  "
              "or leaves the webpage.\n  An attacker can use this "
              "to execute a script when it is called.\n",

    "onstorage": "* onstorage: When the storage area is changing.\n  "
                 "An attacker can use this to execute a script when it is called.\n",

    "onsyncrestored": "* onsyncrestored: When the user interrupts the element’s\n  "
                      "ability to play its media as defined by the timeline to fire.\n  "
                      "An attacker can use this to execute a script when it is called.\n",

    "onsubmit": "* onsubmit: When the user submits a form.\n  "
                "An attacker can use this to execute a script when it is called.\n",

    "ontimeerror": "* ontimeerror: When the user sets a time property,\n  "
                   "such as dur, to an invalid value.\n  "
                   "An attacker can use this to execute a script when it is called.\n",

    "ontrackchange": "* ontrackchange: When the user changes track in a playlist.\n  "
                     "An attacker can use this to execute a script when it is called.\n",

    "onundo": "* onundo: When the user goes backward in the undo transaction history.\n  "
              "An attacker can use this to execute a script when it is called.\n",

    "onunload": "* onunload: When the user clicks any link, or presses\n  "
                "the back button.\n  An attacker can use this "
                "to execute a script when it is called.\n",

    "onurlflip": "* onurlflip: When an advanced streaming format (asf) file,\n  "
                 "played by an html+time (timed interactive multimedia extensions)\n  "
                 "media tag, processes script commands embedded in the asf file.\n  "
                 "An attacker can use this to execute a script when it is called.\n",

    "seeksegmenttime": "* seeksegmenttime: A method that locates the specified point\n  "
                       "on the element’s segment time line, and begins playing\n  from that point "
                       "the segment consists of one\n  repetition of the time line, "
                       "including reverse play using the autoreverse.\n",

    "hash_location": "* Hash Location: A variable that returns the location\n  "
                     "of the hash table with information about the users.\n  "
                     "An attacker can watch and use this information very badly.\n",

    "self_contained_payload": "* Self Contained Payload: It is an XSS attack that does not require\n  "
                              "vulnerable web resource to echo input.\n  Everything that is needed is "
                              "contained in a single URL.\n  Once this URL is executed, "
                              "the resource will be automatically assembled.\n",

    "c_style_loops": "* C Style Loops: An attacker can use C Style Loops,\n  "
                     "such as 'for' or 'while', in order to\n  "
                     "execute malicious code on the server side.\n",

    "c_style_short_condition": "* C Style Short Condition: An example for a C Style Short Condition is\n  "
                               "'1 == 1 ? true : false'. This can be very useful for an attacker\n  "
                               "in order to execute code on the server side.\n",

    "jquery_selector": "* Jquery Selector: Jquery Selector, like alert($(variable)),\n  "
                       "can display values of sensitive variables for the attacker,\n  "
                       "that might give him useful information about the server.\n",

    "conditional_tokens": "* Conditional Tokens: Like cc_on, conditional tokens can write\n  "
                          "a comment in javascript, and still get executed.\n  "
                          "An attacker can use this to receive information about the server.\n",

    "firefox_url_handler": "* Firefox URL Handler: The Firefox URL Handler can cause bugs\n  "
                           "and issue on the client side.\n",

    "blind_xss": "* Blind XSS: With blind XSS, the attacker can redirect or even inject\n  "
                 "the server malicious code, which is located\n  in another url or ip address.\n"
}

links_for_info = "For more information about XXE, check the following links:\n" \
                 "https://owasp.org/www-community/attacks/xss/\n" \
                 "https://portswigger.net/web-security/cross-site-scripting\n"
