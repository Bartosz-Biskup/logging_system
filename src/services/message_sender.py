from typing import Protocol


class MessageSenderProtocol(Protocol):
    def send_message(self, receiver: str, content: str) -> None:
        ...


class MessageSender:
    def send_message(self, receiver: str, content: str) -> None:
        print(f"message to {receiver}: {content}")
        with open("example.txt", "a") as file:
            file.write(f"message to {receiver}: {content}\n")


# class MessageSender:
#     def send_message(self, receiver: str, content: str) -> None:
#         ...