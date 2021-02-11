import os
from random import randint
from PIL import Image
from captcha.image import ImageCaptcha

FIRST_FONT_FILE_PATH = "detective/toolbox/lenses/brute_force/fonts/font1.ttf"
SECOND_FONT_FILE_PATH = "detective/toolbox/lenses/brute_force/fonts/font10.ttf"
CAPTCHA_IMAGE_FILE_PATH = "detective/toolbox/lenses/brute_force/captcha.png"
MIN_VALUE = 10000
MAX_VALUE = 99999


def load_captcha():
    """
    This function will implement captcha in order
    to prevent bot logins to the site
    """
    user_code = ""
    number = 0
    while user_code != str(number):
        image = ImageCaptcha(fonts=[FIRST_FONT_FILE_PATH, SECOND_FONT_FILE_PATH])
        number = randint(MIN_VALUE, MAX_VALUE)
        image.write(str(number), CAPTCHA_IMAGE_FILE_PATH)
        captcha_image = Image.open(CAPTCHA_IMAGE_FILE_PATH)
        captcha_image.show()
        user_code = input("Enter the code: ")
    if os.path.exists(CAPTCHA_IMAGE_FILE_PATH):
        os.remove(CAPTCHA_IMAGE_FILE_PATH)


load_captcha()
