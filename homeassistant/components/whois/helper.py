"""A helper class that abstracts away the usage of external whois libraries."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import whois as ext_whois
from whois.parser import PywhoisError, WhoisEntry


@dataclass(kw_only=True)
class Domain:
    """A class internally representing a domain."""

    admin: Any = None
    creation_date: Any = None
    dnssec: Any = None
    expiration_date: Any = None
    last_updated: Any = None
    name_servers: Any = None
    owner: Any = None
    registrar: Any = None
    reseller: Any = None
    registrant: Any = None
    status: Any = None
    statuses: Any = None


class WhoisUnknownTLD(Exception):
    """Exception class when unknown TLD encountered."""


class GenericWhoisError(Exception):
    """Exception class for all other exceptions originating from the external whois library."""


def query(domain: str) -> Domain | None:
    """Wrap around the external whois library call and return internal domain representation."""

    wh = None
    try:
        wh = ext_whois.whois(domain)
    except PywhoisError as ex:
        if "No whois server is known for this kind of object" in str(
            ex
        ) or "This TLD has no whois server" in str(ex):
            raise WhoisUnknownTLD from ex
        if "No match for" in str(ex):
            pass  # suppress this exception to maintain backward-compatible behavior
        else:
            raise GenericWhoisError from ex
    except Exception as ex:
        raise GenericWhoisError from ex

    # backward-compatibility
    if wh is None:
        return None

    # field mapping here
    return Domain(
        admin=get_attr_generic_single(wh, "admin"),
        creation_date=get_attr_generic_date(wh, "creation_date"),
        expiration_date=get_attr_generic_date(wh, "expiration_date"),
        last_updated=get_attr_generic_date(wh, "updated_date"),
        name_servers=get_attr_name_servers(wh),
        owner=get_attr_owner(wh),
        registrar=get_attr_generic_single(wh, "registrar"),
        reseller=None,
        registrant=get_attr_owner(wh),
        dnssec=get_attr_dnssec(wh),
        status=get_attr_generic_single(wh, "status"),
        statuses=get_attr_statuses(wh),
    )


def get_attr_generic_single(whois: WhoisEntry, attr_name: str) -> Any:
    """Retrieve and normalize generic single-value attributes from the external whois library."""
    if attr_name not in whois or not whois[attr_name]:
        return None
    attr = whois[attr_name]
    return attr[0] if isinstance(attr, list) else attr


def get_attr_generic_date(whois: WhoisEntry, attr_name: str) -> Any:
    """Retrieve and normalize generic date attributes from the external whois library."""
    attr = get_attr_generic_single(whois, attr_name)
    return attr if isinstance(attr, datetime) else None


def get_attr_name_servers(whois: WhoisEntry) -> list[str] | None:
    """Retrieve and normalize name_servers attribute from the external library."""
    if "name_servers" not in whois or not whois["name_servers"]:
        return None
    attr = whois["name_servers"]
    ns = attr if isinstance(attr, list) else [attr]
    return [str(n).lower() for n in ns]


def get_attr_owner(whois: WhoisEntry) -> str | None:
    """Retrieve and normalize owner information."""
    owner = (
        get_attr_generic_single(whois, "name")
        or get_attr_generic_single(whois, "org")
        or get_attr_generic_single(whois, "registrant_name")
    )
    return str(owner) if owner else None


def get_attr_admin(whois: WhoisEntry) -> str | None:
    """Retrieve and normalize admin information."""
    admin = get_attr_generic_single(whois, "admin") or get_attr_generic_single(
        whois, "admin_organization"
    )
    return str(admin) if admin else None


def get_attr_dnssec(whois: WhoisEntry) -> bool:
    """Retrieve and normalize DNSSEC information."""
    if "dnssec" not in whois or not whois["dnssec"]:
        return False
    attr = whois["dnssec"]
    attr = attr if isinstance(attr, list) else [attr]
    return any(v.lower() != "unsigned" for v in attr)


def get_attr_statuses(whois: WhoisEntry) -> list | None:
    """Retrieve and normalize statuses information."""
    if "status" not in whois or not whois["status"]:
        return None
    attr = whois["status"]
    return attr if isinstance(attr, list) else [attr]
