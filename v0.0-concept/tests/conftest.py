"""
conftest.py — force pytest temp dirs to /tmp so SQLite WAL mode works.
The HomeLab folder is a FUSE mount; SQLite WAL journals fail on it.
"""
import pytest
import tempfile
import os


@pytest.fixture
def tmp_path(tmp_path_factory):
    """Override tmp_path to always use /tmp, not the project directory."""
    return tmp_path_factory.mktemp("pv")


def pytest_configure(config):
    # Ensure the base temp dir is always /tmp
    if not hasattr(config, "workerinput"):
        config.option.basetemp = "/tmp/pytest-phrasevault"
