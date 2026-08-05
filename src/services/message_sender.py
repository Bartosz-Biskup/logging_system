from typing import Protocol


class MessageSenderProtocol(Protocol):
    def send_message(self, receiver: str, content: str) -> None:
        ...


class MessageSender:
    def send_message(self, receiver: str, content: str) -> None:
        ...