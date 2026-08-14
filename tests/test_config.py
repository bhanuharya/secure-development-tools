import pytest

from src.config import ConfigurationError, parse_bool


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE", "Yes", "On", " 1 ", "yes "])
def test_parse_bool_true_values(value):
    assert parse_bool(value) is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "FALSE", "No", "Off", " 0 ", "off "])
def test_parse_bool_false_values(value):
    assert parse_bool(value) is False


def test_parse_bool_empty_is_false():
    assert parse_bool("") is False
    assert parse_bool("   ") is False


@pytest.mark.parametrize("value", ["banana", "2", "truefalse", "y", "n", "on1"])
def test_parse_bool_invalid_raises(value):
    with pytest.raises(ConfigurationError):
        parse_bool(value)
