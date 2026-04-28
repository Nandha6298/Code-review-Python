from __future__ import annotations

import smtplib
from email.mime.text import MIMEText


def send_email(smtp_conf: dict, recipients: list[str], subject: str, html_body: str) -> None:
    if not recipients:
        return
    msg = MIMEText(html_body, "html")
    msg["Subject"] = subject
    msg["From"] = smtp_conf.get("from_email", "codeauditpro@localhost")
    msg["To"] = ",".join(recipients)
    with smtplib.SMTP(smtp_conf.get("host", "localhost"), int(smtp_conf.get("port", 25))) as client:
        if smtp_conf.get("username"):
            client.login(smtp_conf["username"], smtp_conf.get("password", ""))
        client.sendmail(msg["From"], recipients, msg.as_string())
