import pytest
from services.password_validator import is_password_valid


def test_valid_password():
    assert is_password_valid("StrongPass1!")


@pytest.mark.parametrize("password", [
    "Abc1!",
    "A" * 256 + "b1!",
])
def test_password_rejected_due_to_length(password):
    assert not is_password_valid(password)


def test_password_rejected_no_lowercase():
    assert not is_password_valid("STRONGPASS1!")


def test_password_rejected_no_uppercase():
    assert not is_password_valid("strongpass1!")


def test_password_rejected_no_digit():
    assert not is_password_valid("StrongPass!")


def test_password_rejected_no_special_char():
    assert not is_password_valid("StrongPass1")


def test_password_rejected_illegal_character():
    assert not is_password_valid("Strong Pass1!")
