import pytest

from arh.models.mock import MockCompliantModel


@pytest.fixture
def model():
    return MockCompliantModel()
