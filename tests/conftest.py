import pytest


@pytest.fixture
def sample_resources():
    return [
        {
            "id": "resource-1",
            "name": "Gmail Account",
            "username": "user@gmail.com",
            "uri": "https://gmail.com",
        },
        {
            "id": "resource-2",
            "name": "GitHub",
            "username": "developer",
            "uri": "https://github.com",
        },
    ]


@pytest.fixture
def mock_zxcvbn_strong():
    return {
        "score": 4,
        "feedback": {
            "warning": "",
            "suggestions": ["Add another word or two"],
        },
        "crack_times_display": {
            "offline_slow_hashing_1e4_per_second": "centuries",
        },
    }


@pytest.fixture
def mock_zxcvbn_weak():
    return {
        "score": 1,
        "feedback": {
            "warning": "This is a top-10 common password",
            "suggestions": ["Add another word or two"],
        },
        "crack_times_display": {
            "offline_slow_hashing_1e4_per_second": "less than a second",
        },
    }


@pytest.fixture
def mocker(mocker):
    return mocker
