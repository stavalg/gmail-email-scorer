import pytest

from app.analyzers.rules.data import WEIGHTS, validate_weights


def test_shipped_weights_are_valid():
    validate_weights(WEIGHTS)


@pytest.mark.parametrize("bad", [-1, 2.5, True, "10"])
def test_invalid_weights_are_rejected(bad):
    with pytest.raises(ValueError):
        validate_weights({"x": bad})
