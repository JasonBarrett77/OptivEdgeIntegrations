"""PAN-OS XML API session primitives and transport-level error handling.

This module owns authenticated request execution, XML parsing, error modeling,
and secret sanitization for PAN-OS sessions. It should not own collection
orchestration, normalization, or persistence concerns.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import requests
import xmltodict
from urllib3 import disable_warnings

if TYPE_CHECKING:
    from optivedge_integrations.integrations.models import ManagementStation


DEFAULT_TIMEOUT = (5.0, 30.0)
_DEFAULT_FORCE_LIST = ("entry", "member")
SHOW_CLOCK_COMMAND = "<show><clock/></show>"
REDACTED = "[REDACTED]"


def build_secrets(*values: str | None) -> tuple[str, ...]:
    """Return non-empty secret values for sanitization."""
    return tuple(value for value in values if value)


def sanitize_text(value: str, *, secrets: tuple[str, ...]) -> str:
    """Redact exact secret values from text."""
    sanitized = value
    for secret in secrets:
        if secret:
            sanitized = sanitized.replace(secret, REDACTED)
    return sanitized


def sanitize_value(value: Any, *, secrets: tuple[str, ...]) -> Any:
    """Recursively sanitize strings and common containers."""
    if value is None:
        return None

    if isinstance(value, str):
        return sanitize_text(value, secrets=secrets)

    if isinstance(value, Mapping):
        return {
            str(key): sanitize_value(item, secrets=secrets)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [sanitize_value(item, secrets=secrets) for item in value]

    if isinstance(value, tuple):
        return tuple(sanitize_value(item, secrets=secrets) for item in value)

    if isinstance(value, set):
        return {sanitize_value(item, secrets=secrets) for item in value}

    text = str(value)
    sanitized_text = sanitize_text(text, secrets=secrets)
    return sanitized_text if sanitized_text != text else value


@dataclass(slots=True)
class PANErrorContext:
    hostname: str | None = None
    port: int | None = None
    request_type: str | None = None
    target_supplied: bool = False
    http_status: int | None = None
    api_status: str | None = None
    api_code: str | None = None
    api_message: str | None = None
    requests_exception_type: str | None = None
    response_preview: str | None = None
    is_authentication_error: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def sanitized(self, *, secrets: tuple[str, ...]) -> "PANErrorContext":
        return PANErrorContext(
            hostname=sanitize_value(self.hostname, secrets=secrets),
            port=self.port,
            request_type=sanitize_value(self.request_type, secrets=secrets),
            target_supplied=self.target_supplied,
            http_status=self.http_status,
            api_status=sanitize_value(self.api_status, secrets=secrets),
            api_code=sanitize_value(self.api_code, secrets=secrets),
            api_message=sanitize_value(self.api_message, secrets=secrets),
            requests_exception_type=sanitize_value(
                self.requests_exception_type,
                secrets=secrets,
            ),
            response_preview=sanitize_value(self.response_preview, secrets=secrets),
            is_authentication_error=self.is_authentication_error,
            details=sanitize_value(self.details, secrets=secrets) or {},
        )


class PANSessionError(Exception):
    """Base exception raised by PANSession for any PAN-OS session-related failure."""

    def __init__(
        self,
        message: str,
        *,
        context: PANErrorContext | None = None,
        secrets: tuple[str, ...] = (),
    ) -> None:
        self.context = (context or PANErrorContext()).sanitized(secrets=secrets)
        self.message = sanitize_text(message, secrets=secrets)
        super().__init__(self.message)

    def __str__(self) -> str:
        parts = [self.message]
        if self.context.api_code:
            parts.append(f"api_code={self.context.api_code}")
        if self.context.hostname:
            host = self.context.hostname
            if self.context.port:
                host = f"{host}:{self.context.port}"
            parts.append(f"host={host}")
        return " ".join(parts)


class PANSessionTransportError(PANSessionError):
    """Raised when the requests call fails before a usable XML API response is received."""


class PANSessionTimeoutError(PANSessionTransportError):
    """Raised when the requests call exceeds the configured timeout."""


class PANSessionParseError(PANSessionError):
    """Raised when the device responds but the XML cannot be parsed as expected."""


class PANSessionAPIError(PANSessionError):
    """Raised when the PAN-OS XML API returns a valid response with status='error'."""

    @property
    def is_authentication_error(self) -> bool:
        return self.context.is_authentication_error


@dataclass(slots=True)
class PANSessionOpenResult:
    session: "PANSession"
    validation_command: str
    validation_response: dict[str, Any]
    provided_api_key: bool
    provided_api_key_valid: bool
    api_key_refreshed: bool
    api_key: str


class PANSession(requests.Session):
    """
    Minimal PAN-OS XML API session.

    Design:
    - steady-state requests use API key auth
    - key generation uses POST data (type=keygen, user, password)
    - plaintext username/password are not stored on the session object
    """

    def __init__(
        self,
        hostname: str,
        *,
        port: int = 443,
        api_key: str | None = None,
        target: str | None = None,
        verify: bool | str = True,
        timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
        user_agent: str = "AegisGo/1.0",
    ) -> None:
        super().__init__()

        host = (hostname or "").strip().strip("/")
        if not host:
            raise ValueError("hostname is required")
        if "://" in host:
            raise ValueError("hostname must not include a URL scheme")
        if port <= 0:
            raise ValueError("port must be a positive integer")

        self.hostname = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.api_url = f"{self.base_url}/api/"
        self.management_station = None
        self.target = target
        self.verify = verify
        self.timeout = timeout
        self.api_key = (api_key or "").strip() or None

        if verify is False:
            disable_warnings()
            # urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.headers.update(
            {
                "Accept": "application/xml",
                "User-Agent": user_agent,
            }
        )

    @classmethod
    def open(
        cls,
        hostname: str,
        *,
        port: int = 443,
        api_key: str | None = None,
        credentials_provider: Callable[[], tuple[str, str]] | None = None,
        target: str | None = None,
        verify: bool | str = True,
        timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
        user_agent: str = "OptivAegis/1.0",
    ) -> PANSessionOpenResult:
        """
        Open a usable PANSession.

        Flow:
        - if an API key is supplied, validate it first
        - if validation fails with XML API code 403, refresh once using keygen
        - if no API key is supplied, credentials_provider is required
        """
        session = cls(
            hostname,
            port=port,
            api_key=api_key,
            target=target,
            verify=verify,
            timeout=timeout,
            user_agent=user_agent,
        )

        provided_api_key = bool(session.api_key)
        provided_api_key_valid = False
        api_key_refreshed = False

        if session.api_key:
            try:
                validation_command, validation_response = session.validate_connection()
                provided_api_key_valid = True
                return PANSessionOpenResult(
                    session=session,
                    validation_command=validation_command,
                    validation_response=validation_response,
                    provided_api_key=provided_api_key,
                    provided_api_key_valid=provided_api_key_valid,
                    api_key_refreshed=api_key_refreshed,
                    api_key=session.api_key,
                )
            except PANSessionAPIError as exc:
                if not exc.is_authentication_error:
                    raise
                if credentials_provider is None:
                    raise

        if credentials_provider is None:
            raise PANSessionError(
                "credentials_provider is required when API key refresh is needed",
                context=PANErrorContext(
                    hostname=hostname,
                    port=port,
                    request_type="keygen",
                ),
            )

        session.keygen(credentials_provider=credentials_provider)
        api_key_refreshed = True
        validation_command, validation_response = session.validate_connection()

        return PANSessionOpenResult(
            session=session,
            validation_command=validation_command,
            validation_response=validation_response,
            provided_api_key=provided_api_key,
            provided_api_key_valid=provided_api_key_valid,
            api_key_refreshed=api_key_refreshed,
            api_key=session.api_key or "",
        )

    def keygen(self, *, credentials_provider: Callable[[], tuple[str, str]]) -> str:
        """
        Generate an API key using XML API POST data:

            type=keygen
            user=<username>
            password=<password>

        credentials_provider is called only at the moment keygen is needed.
        """
        try:
            username, password = credentials_provider()
        except PANSessionError:
            raise
        except Exception as exc:
            raise PANSessionError(
                "credentials provider failed",
                context=PANErrorContext(
                    hostname=self.hostname,
                    port=self.port,
                    request_type="keygen",
                    details={"provider_exception_type": type(exc).__name__},
                ),
            ) from exc
        username = (username or "").strip()
        password = password or ""

        if not username or not password:
            raise PANSessionError(
                "username and password are required for key generation",
                context=PANErrorContext(
                    hostname=self.hostname,
                    port=self.port,
                    request_type="keygen",
                ),
            )

        secrets = build_secrets(username, password, self.api_key)

        try:
            response_data = self.request_xml_api(
                {
                    "type": "keygen",
                    "user": username,
                    "password": password,
                },
                target="",
                include_key=False,
                secrets=secrets,
            )
        finally:
            username = ""
            password = ""

        key = self._as_text(response_data.get("response", {}).get("result", {}).get("key"))
        if not key:
            raise PANSessionAPIError(
                "key generation succeeded but no API key was returned",
                context=PANErrorContext(
                    hostname=self.hostname,
                    port=self.port,
                    request_type="keygen",
                    target_supplied=False,
                ),
                secrets=secrets,
            )

        self.api_key = key
        return key

    def ensure_api_key(self) -> str:
        if self.api_key:
            return self.api_key
        raise PANSessionError(
            "API key is not available",
            context=PANErrorContext(
                hostname=self.hostname,
                port=self.port,
            ),
        )

    def op(
        self,
        cmd: str,
        *,
        target: str | None = None,
        extra_params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        params = {"type": "op", "cmd": cmd}
        return self.request_xml_api(params, target=target, extra_params=extra_params)

    def validate_connection(self) -> tuple[str, dict[str, Any]]:
        """
        Validate current API-key auth with a lightweight op command.
        """
        return ("show clock", self.op(SHOW_CLOCK_COMMAND))

    def request_xml_api(
        self,
        params: Mapping[str, str],
        *,
        target: str | None = None,
        extra_params: Mapping[str, str] | None = None,
        include_key: bool = True,
        secrets: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        payload: dict[str, str] = dict(params)
        if extra_params:
            payload.update(extra_params)

        effective_target = target if target is not None else self.target
        if effective_target:
            payload["target"] = effective_target

        headers: dict[str, str] = {}
        if include_key:
            api_key = self.ensure_api_key()
            headers["X-PAN-KEY"] = api_key
            secrets = build_secrets(*secrets, api_key)

        request_type = payload.get("type")

        try:
            response = self.post(
                self.api_url,
                data=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify,
            )
            response.raise_for_status()
        except requests.Timeout as exc:
            raise PANSessionTimeoutError(
                "request to PAN-OS XML API timed out",
                context=PANErrorContext(
                    hostname=self.hostname,
                    port=self.port,
                    request_type=request_type,
                    target_supplied=bool(effective_target),
                    requests_exception_type=type(exc).__name__,
                ),
                secrets=secrets,
            ) from exc
        except requests.RequestException as exc:
            error_response = getattr(exc, "response", None)
            if error_response is not None:
                api_error = self._build_api_error_from_http_response(
                    response=error_response,
                    request_type=request_type,
                    target_supplied=bool(effective_target),
                    secrets=secrets,
                )
                if api_error is not None:
                    raise api_error from exc

            http_status = getattr(error_response, "status_code", None)
            raise PANSessionTransportError(
                "request to PAN-OS XML API failed",
                context=PANErrorContext(
                    hostname=self.hostname,
                    port=self.port,
                    request_type=request_type,
                    target_supplied=bool(effective_target),
                    http_status=http_status,
                    requests_exception_type=type(exc).__name__,
                ),
                secrets=secrets,
            ) from exc

        parsed = self._parse_response(
            response,
            hostname=self.hostname,
            port=self.port,
            request_type=request_type,
            target_supplied=bool(effective_target),
            secrets=secrets,
        )

        response_root = parsed.get("response")
        if not isinstance(response_root, Mapping):
            raise PANSessionAPIError(
                "XML API returned an unexpected response structure",
                context=PANErrorContext(
                    hostname=self.hostname,
                    port=self.port,
                    request_type=request_type,
                    target_supplied=bool(effective_target),
                    http_status=response.status_code,
                ),
                secrets=secrets,
            )

        status = str(response_root.get("@status", "")).lower()
        if status != "success":
            code = self._as_text(response_root.get("@code"))
            message = self._extract_error_message(response_root) or "XML API returned an error"

            raise PANSessionAPIError(
                message,
                context=PANErrorContext(
                    hostname=self.hostname,
                    port=self.port,
                    request_type=request_type,
                    target_supplied=bool(effective_target),
                    http_status=response.status_code,
                    api_status=status,
                    api_code=code,
                    api_message=message,
                    is_authentication_error=self._classify_auth_error(code=code),
                    response_preview=self._response_preview(response.text, secrets=secrets),
                ),
                secrets=secrets,
            )

        return parsed

    def _build_api_error_from_http_response(
        self,
        *,
        response: requests.Response,
        request_type: str | None,
        target_supplied: bool,
        secrets: tuple[str, ...],
    ) -> PANSessionAPIError | None:
        try:
            parsed = self._parse_response(
                response,
                hostname=self.hostname,
                port=self.port,
                request_type=request_type,
                target_supplied=target_supplied,
                secrets=secrets,
            )
        except PANSessionParseError:
            return None

        response_root = parsed.get("response")
        if not isinstance(response_root, Mapping):
            return None

        status = str(response_root.get("@status", "")).lower()
        code = self._as_text(response_root.get("@code"))
        message = self._extract_error_message(response_root) or "XML API returned an error"
        if status == "success" and not code:
            return None

        return PANSessionAPIError(
            message,
            context=PANErrorContext(
                hostname=self.hostname,
                port=self.port,
                request_type=request_type,
                target_supplied=target_supplied,
                http_status=response.status_code,
                api_status=status or "error",
                api_code=code,
                api_message=message,
                is_authentication_error=self._classify_auth_error(code=code),
                response_preview=self._response_preview(response.text, secrets=secrets),
            ),
            secrets=secrets,
        )

    @staticmethod
    def _parse_response(
        response: requests.Response,
        *,
        hostname: str,
        port: int,
        request_type: str | None,
        target_supplied: bool,
        secrets: tuple[str, ...],
    ) -> dict[str, Any]:
        try:
            parsed = xmltodict.parse(response.content, force_list=_DEFAULT_FORCE_LIST)
        except Exception as exc:
            raise PANSessionParseError(
                "XML API returned invalid XML",
                context=PANErrorContext(
                    hostname=hostname,
                    port=port,
                    request_type=request_type,
                    target_supplied=target_supplied,
                    http_status=response.status_code,
                    response_preview=PANSession._response_preview(response.text, secrets=secrets),
                ),
                secrets=secrets,
            ) from exc

        if not isinstance(parsed, dict):
            raise PANSessionParseError(
                "XML API returned an unexpected parse result",
                context=PANErrorContext(
                    hostname=hostname,
                    port=port,
                    request_type=request_type,
                    target_supplied=target_supplied,
                    http_status=response.status_code,
                ),
                secrets=secrets,
            )

        return parsed

    @staticmethod
    def _response_preview(value: str, *, secrets: tuple[str, ...], limit: int = 300) -> str:
        preview = value[:limit]
        return sanitize_text(preview, secrets=secrets)

    @staticmethod
    def _extract_error_message(root: Mapping[str, Any]) -> str | None:
        candidates = (
            PANSession._dig_text(root, "msg", "line"),
            PANSession._dig_text(root, "msg"),
            PANSession._dig_text(root, "result", "msg"),
            PANSession._dig_text(root, "result"),
        )
        for candidate in candidates:
            if candidate:
                return " ".join(candidate.split())
        return None

    @staticmethod
    def _dig_text(value: Any, *path: str) -> str | None:
        current = value
        for key in path:
            if not isinstance(current, Mapping):
                return None
            current = current.get(key)
        return PANSession._as_text(current)

    @staticmethod
    def _as_text(value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, Mapping):
            text = value.get("#text")
            return text if isinstance(text, str) else None
        return str(value)

    @staticmethod
    def _classify_auth_error(*, code: str | None) -> bool:
        """
        Based on observed PAN-OS XML API behavior:
        - 403 => authentication / missing-or-invalid API key
        - 400 => missing required parameter / caller bug
        """
        return code == "403"

    @staticmethod
    def validate_management_station(management_station: "ManagementStation") -> None:
        from optivedge_integrations.integrations.models import ManagementStation

        allowed_types = {
            ManagementStation.StationType.PAN_PANORAMA,
            ManagementStation.StationType.PAN_FIREWALL,
        }
        station_type = getattr(management_station, "station_type", None)
        if station_type not in allowed_types:
            raise PANSessionError(
                "management_station station_type must be a Palo Alto type",
                context=PANErrorContext(
                    hostname=getattr(management_station, "hostname", None),
                    port=getattr(management_station, "port", None),
                ),
            )

    @staticmethod
    def resolve_management_station_verify(
        management_station: "ManagementStation",
    ) -> bool | str:
        if not management_station.verify_tls:
            return False
        if management_station.ca_bundle_path:
            return management_station.ca_bundle_path
        return True


def save_api_key(management_station: "ManagementStation", api_key: str) -> None:
    """Persist a refreshed PAN-OS API key."""
    management_station.api_key = api_key
    management_station.save(update_fields=["api_key"])


def default_credentials_provider(
    management_station: "ManagementStation",
) -> Callable[[], tuple[str, str]]:
    """
    Return a simple credentials provider for a ManagementStation.

    This is intentionally plain for now. Replace the body later with decrypt-at-call-time
    logic when you add encryption.
    """

    def provider() -> tuple[str, str]:
        username = (management_station.username or "").strip()
        password = management_station.password or ""

        if not username or not password:
            raise PANSessionError(
                "management_station credentials are not available",
                context=PANErrorContext(
                    hostname=management_station.hostname,
                    port=management_station.port,
                    request_type="keygen",
                ),
            )

        return username, password

    return provider


def open_session(
    management_station: "ManagementStation",
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    target: str | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANSession:
    """
    Open a PANSession for a ManagementStation.

    Behavior:
    - use the stored API key first
    - call credentials_provider only if key refresh is needed
    - persist a newly generated API key if it changed
    """
    PANSession.validate_management_station(management_station)

    provider = credentials_provider or default_credentials_provider(management_station)

    result = PANSession.open(
        hostname=management_station.hostname,
        port=management_station.port,
        api_key=management_station.api_key,
        credentials_provider=provider,
        target=target,
        verify=PANSession.resolve_management_station_verify(management_station),
        timeout=timeout,
        user_agent=user_agent,
    )
    result.session.management_station = management_station

    if (
        result.api_key_refreshed
        and result.api_key
        and result.api_key != (management_station.api_key or "")
    ):
        save_api_key(management_station, result.api_key)

    return result.session
