import copy
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from common import load_yaml  # noqa: E402


@pytest.fixture
def firewall():
    """Pare-feu conforme, copié pour pouvoir être muté dans chaque test."""
    return copy.deepcopy(load_yaml(ROOT / "configs" / "firewall01.yml"))


@pytest.fixture
def switch():
    return copy.deepcopy(load_yaml(ROOT / "configs" / "switch01.yml"))


@pytest.fixture
def policy():
    return load_yaml(ROOT / "policies" / "security-policy.yml")
