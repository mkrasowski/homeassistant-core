"""Fixtures for Whois integration tests."""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from homeassistant.components.whois.const import DOMAIN
from homeassistant.const import CONF_DOMAIN
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util

from tests.common import MockConfigEntry


@pytest.fixture
def mock_config_entry() -> MockConfigEntry:
    """Return the default mocked config entry."""
    return MockConfigEntry(
        title="Home Assistant",
        domain=DOMAIN,
        data={
            CONF_DOMAIN: "home-assistant.io",
        },
        unique_id="home-assistant.io",
    )


@pytest.fixture
def mock_setup_entry() -> Generator[AsyncMock, None, None]:
    """Mock setting up a config entry."""
    with patch(
        "homeassistant.components.whois.async_setup_entry", return_value=True
    ) as mock_setup:
        yield mock_setup


@pytest.fixture
def mock_whois() -> Generator[MagicMock, None, None]:
    """Return a mocked query."""
    with patch(
        "homeassistant.components.whois.helper.ext_whois.whois",
    ) as whois_mock:
        mock_data = {
            "domain_name": ["HOME-ASSISTANT.IO"],
            "admin": "Admin",
            "creation_date": datetime(2019, 1, 1, 0, 0, 0),
            "dnssec": "signedDelegation",
            "expiration_date": datetime(2023, 1, 1, 0, 0, 0),
            "updated_date": [
                datetime(
                    2022,
                    1,
                    1,
                    0,
                    0,
                    0,
                    tzinfo=dt_util.get_time_zone("Europe/Amsterdam"),
                ),
                datetime(2023, 11, 20, 6, 55, 46, 110000),
            ],
            "name_servers": ["NS1.example.COM", "ns2.EXAMPLE.com"],
            "registrant_name": "registrant@example.com",
            "registrar": "My Registrar",
            "status": "OK",
        }

        whois_mock.return_value = mock_data
        yield whois_mock


@pytest.fixture
def mock_whois_missing_some_attrs() -> Generator[Mock, None, None]:
    """Return a mocked query that only sets one attribute."""
    with patch(
        "homeassistant.components.whois.helper.ext_whois.whois",
    ) as whois_mock:
        whois_mock.return_value = {
            "updated_date": datetime(
                2022, 1, 1, 0, 0, 0, tzinfo=dt_util.get_time_zone("Europe/Amsterdam")
            )
        }
        yield whois_mock


@pytest.fixture
def mock_whois_empty() -> Generator[Mock, None, None]:
    """Mock an empty response from the whois library."""
    with patch(
        "homeassistant.components.whois.helper.ext_whois.whois",
    ) as whois_mock:
        whois_mock.return_value = None
        yield whois_mock


@pytest.fixture
async def init_integration(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> MockConfigEntry:
    """Set up thewhois integration for testing."""
    mock_config_entry.add_to_hass(hass)

    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    return mock_config_entry
