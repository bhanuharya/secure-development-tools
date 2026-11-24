import secrets


def issue_otp_safe():
    otp_code = secrets.randbelow(900000) + 100000
    return otp_code
