import os
import smtplib
from typing import Protocol

from services.config import SMTP_HOST, SMTP_PORT, SMTP_EMAIL


class MailSenderProtocol(Protocol):
    def send(self,
             recipient: str,
             subject: str,
             content: str) -> None:
        ...


class MailSender:
    def __init__(self) -> None:
        self._host: str = SMTP_HOST
        self._port: int = SMTP_PORT
        self._email: str = SMTP_EMAIL
        self._secret: str = os.getenv("SMTP_SECRET", "")

    def send(self,
             recipient: str,
             subject: str,
             content: str) -> None:
        message = (
            f"From: {self._email}\r\n"
            f"To: {recipient}\r\n"
            f"Subject: {subject}\r\n"
            f"\r\n"
            f"{content}"
        )

        with smtplib.SMTP(self._host, self._port) as server:
            server.starttls()
            server.login(self._email, self._secret)
            server.sendmail(self._email, recipient, message)
