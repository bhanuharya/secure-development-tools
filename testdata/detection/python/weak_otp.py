import random


def issue_otp():
    otp_code = random.randint(100000, 999999)
    return otp_code
