from django.conf import settings
from django.core.mail import send_mail
import os
import re

def send_email(title, body_html, to_mails):
    """Function to send email"""
    try:
        subject = title
        sender = settings.EMAIL_HOST_USER
        to= to_mails
        sent_mail = send_mail(
            subject,
            body_html,
            sender,
            to,
            html_message=body_html,
        )
        return True, "success"

    except Exception as e:
        msg ='somthing went wrong'
        return False, f"{str(e)}"

def create_img_url(request,image):
    """creating url for image"""

    if image is not None and image !="" :
        image_path = os.path.join(settings.MEDIA_ROOT, image)
        image_url = request.build_absolute_uri(image_path)
        return image_url
    else :
        return ''

def is_valid_phone_number(phone_number):
    """Checking phone number valid or not"""
    pattern = r'^(?:\+\d{1,3}\s?)?\d{10}$'

    return bool(re.match(pattern, phone_number))


