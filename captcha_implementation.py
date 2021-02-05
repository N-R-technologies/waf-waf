from random import randint
from captcha.image import ImageCaptcha
from PIL import Image
MIN_VALUE = 10000
MAX_VALUE = 99999


def captcha():
    """
    function implements captcha in order to prevent bot logins to the site,
    the user just need to enter the number in the picture
    """
    user_code = 0
    number = 1
    while user_code != str(number):
        image = ImageCaptcha(fonts=['font10.ttf', 'font1.ttf'])
        number = randint(MIN_VALUE, MAX_VALUE)
        image.write(str(number), 'out.png')
        captcha_image = Image.open('out.png')
        captcha_image.show()
        user_code = input("Enter the code:")


def main():
    captcha()


if __name__ == "__main__":
    main()
