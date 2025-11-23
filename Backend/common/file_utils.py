"""JSON 입출력과 디렉터리 관리를 위한 재사용 가능한 파일 시스템 도우미입니다."""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
from pathlib import Path
from typing import Any, Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

JsonLike = Union[dict, list]
PathLike = Union[str, Path]


DEFAULT_NONCE_SIZE = 12
ALLOWED_AES_KEY_SIZES = {16, 24, 32}


def _to_path(path: PathLike) -> Path:
    """``path`` 값을 해석하지 않고 :class:`Path` 로 변환합니다."""
    return path if isinstance(path, Path) else Path(path)


def ensure_dir(directory: PathLike) -> Path:
    """``directory`` 가 존재하지 않으면 부모 디렉터리를 포함해 생성합니다."""
    path = _to_path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _bool_env(var_name: str, default: bool = False) -> bool:
    value = os.getenv(var_name)
    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


def _validate_aes_key(key: bytes) -> bytes:
    if len(key) not in ALLOWED_AES_KEY_SIZES:
        raise ValueError(
            "Encryption key must be 16, 24, or 32 bytes for AES-GCM; "
            f"got {len(key)} bytes"
        )
    return key


def _load_key_from_path(key_path: PathLike) -> bytes:
    path = _to_path(key_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Encryption key file not found: {path}")

    return _validate_aes_key(path.read_bytes())


def _decode_key(key_text: str) -> bytes:
    try:
        key_bytes = base64.b64decode(key_text, validate=True)
    except binascii.Error as exc:
        raise ValueError("DB_ENCRYPTION_KEY must be base64-encoded") from exc

    return _validate_aes_key(key_bytes)


def _get_encryption_key(
    *, key: Optional[bytes] = None, key_path: Optional[PathLike] = None
) -> bytes:
    if key is not None:
        return _validate_aes_key(key)

    env_key_path = key_path or os.getenv("DB_ENCRYPTION_KEY_PATH")
    if env_key_path:
        return _load_key_from_path(env_key_path)

    env_key = os.getenv("DB_ENCRYPTION_KEY")
    if env_key:
        return _decode_key(env_key)

    raise ValueError(
        "Encryption key is required when DB_ENCRYPTION is enabled. "
        "Provide DB_ENCRYPTION_KEY (base64) or DB_ENCRYPTION_KEY_PATH."
    )


def _should_use_encryption(use_encryption: Optional[bool]) -> bool:
    if use_encryption is not None:
        return use_encryption
    return _bool_env("DB_ENCRYPTION", default=False)


def encrypt_bytes(data: bytes, *, key: Optional[bytes] = None, key_path: Optional[PathLike] = None) -> bytes:
    """AES-GCM 으로 바이트를 암호화해 nonce + ciphertext 형태로 반환합니다."""

    aes_key = _get_encryption_key(key=key, key_path=key_path)
    nonce = secrets.token_bytes(DEFAULT_NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    return nonce + aesgcm.encrypt(nonce, data, None)


def decrypt_bytes(data: bytes, *, key: Optional[bytes] = None, key_path: Optional[PathLike] = None) -> bytes:
    """``encrypt_bytes`` 로 암호화된 바이트를 복호화합니다."""

    if len(data) <= DEFAULT_NONCE_SIZE:
        raise ValueError("Encrypted payload is too short to contain a nonce")

    aes_key = _get_encryption_key(key=key, key_path=key_path)
    nonce, ciphertext = data[:DEFAULT_NONCE_SIZE], data[DEFAULT_NONCE_SIZE:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def read_json(
    path: PathLike,
    *,
    use_encryption: Optional[bool] = None,
    key: Optional[bytes] = None,
    key_path: Optional[PathLike] = None,
) -> JsonLike:
    """UTF-8로 인코딩된 JSON 문서를 ``path`` 에서 읽어옵니다."""
    file_path = _to_path(path)
    if _should_use_encryption(use_encryption):
        raw = decrypt_bytes(file_path.read_bytes(), key=key, key_path=key_path)
        return json.loads(raw.decode("utf-8"))

    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(
    path: PathLike,
    data: JsonLike,
    *,
    ensure_ascii: bool = False,
    use_encryption: Optional[bool] = None,
    key: Optional[bytes] = None,
    key_path: Optional[PathLike] = None,
) -> None:
    """``data`` 를 UTF-8로 인코딩된 JSON 형태로 ``path`` 에 기록합니다."""
    file_path = _to_path(path)
    ensure_dir(file_path.parent)
    if _should_use_encryption(use_encryption):
        payload = json.dumps(data, indent=2, ensure_ascii=ensure_ascii).encode("utf-8")
        file_path.write_bytes(encrypt_bytes(payload, key=key, key_path=key_path))
        return

    with file_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=ensure_ascii)
