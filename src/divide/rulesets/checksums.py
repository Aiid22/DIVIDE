from __future__ import annotations

import zlib
from typing import Iterable

from divide.interfaces import ChecksumValidator


class GitHubTokenChecksum:
    """GitHub CRC32 -> Base62 -> six-character suffix validator.

    DIVIDE uses the 0-9A-Za-z alphabet and exposes it as a constructor argument
    for explicit format-version handling.
    """

    validator_id = "github-crc32-base62-six"
    DEFAULT_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def __init__(self, alphabet: str = DEFAULT_ALPHABET):
        if len(alphabet) != 62 or len(set(alphabet)) != 62:
            raise ValueError("Base62 alphabet must contain 62 unique characters")
        self.alphabet = alphabet

    def supports(self, credential_type: str, format_version: str | None = None) -> bool:
        return "github" in credential_type.casefold() and format_version in {None, "checksum-v1"}

    def _base62(self, value: int) -> str:
        if value == 0:
            return self.alphabet[0]
        output = ""
        while value:
            value, remainder = divmod(value, 62)
            output = self.alphabet[remainder] + output
        return output

    def suffix(self, payload: str) -> str:
        crc = zlib.crc32(payload.encode("utf-8")) & 0xFFFFFFFF
        return self._base62(crc).rjust(6, self.alphabet[0])[-6:]

    def validate(self, value: str, *, format_version: str | None = None) -> tuple[bool, str]:
        if len(value) < 7:
            return False, "value is shorter than the six-character checksum suffix"
        expected = self.suffix(value[:-6])
        valid = value[-6:] == expected
        return valid, f"expected GitHub checksum suffix {expected}"


class ChecksumRegistry:
    def __init__(self, validators: Iterable[ChecksumValidator] = (GitHubTokenChecksum(),)):
        self.validators = tuple(validators)

    def validate(
        self, validator_id: str, value: str, credential_type: str, format_version: str | None = None,
    ) -> tuple[bool, str]:
        for validator in self.validators:
            if validator.validator_id == validator_id and validator.supports(credential_type, format_version):
                return validator.validate(value, format_version=format_version)
        return False, f"checksum validator unavailable: {validator_id}"
