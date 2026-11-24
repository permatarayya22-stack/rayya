"""KOSPACE - Autentikasi pengguna dengan password Argon2id."""

from __future__ import annotations

import hmac
import os
import re
from datetime import datetime, timezone

import streamlit as st
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from psycopg.errors import UniqueViolation

from . import users

MAKS_PERCOBAAN = 5
MENIT_KUNCI = 15
MIN_PASSWORD = 12
MAKS_PASSWORD = 128

_SESSION_KEY = "auth_user"
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,49}$")

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
_DUMMY_HASH = _hasher.hash("kospace-dummy-password")


class AuthError(Exception):
    """Kesalahan autentikasi yang aman ditampilkan ke pengguna."""


# ---------------------------------------------------------------------------
# Hash & validasi
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def _needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except Exception:
        return True


def normalize_username(value) -> str:
    return str(value or "").strip().lower()


def validate_username(value) -> str:
    username = normalize_username(value)
    if not _USERNAME_RE.fullmatch(username):
        raise AuthError(
            "Username 3-50 karakter dan hanya boleh berisi huruf, angka, titik, "
            "garis bawah, atau strip."
        )
    return username


def validate_password(value) -> str:
    password = str(value or "")
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"Password minimal {MIN_PASSWORD} karakter.")
    if len(password) > MAKS_PASSWORD:
        raise AuthError(f"Password maksimal {MAKS_PASSWORD} karakter.")
    return password


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _is_locked(row: dict) -> bool:
    locked = _as_datetime(row.get("locked_until"))
    return bool(locked and locked > _now())


def _sisa_menit(locked_until) -> int:
    locked = _as_datetime(locked_until)
    if locked is None:
        return 0
    sisa = (locked - _now()).total_seconds()
    return max(1, int(sisa // 60) + 1)


def authenticate(username, password) -> dict:
    """Kembalikan data user bila kredensial valid, selain itu raise AuthError."""
    nama = normalize_username(username)
    sandi = str(password or "")
    if not nama or not sandi:
        raise AuthError("Username dan password wajib diisi.")

    row = users.find_by_username(nama)
    if row is None:
        # Tetap verifikasi hash dummy agar waktu respons mirip dengan user yang ada.
        verify_password(_DUMMY_HASH, sandi)
        raise AuthError("Username atau password salah.")

    if _is_locked(row):
        sisa = _sisa_menit(row["locked_until"])
        raise AuthError(f"Akun terkunci sementara. Coba lagi dalam {sisa} menit.")

    if not verify_password(row["password_hash"], sandi):
        users.record_login_failure(row["id"], MAKS_PERCOBAAN, MENIT_KUNCI)
        raise AuthError("Username atau password salah.")

    if not row["is_active"]:
        raise AuthError("Akun ini dinonaktifkan. Hubungi admin.")

    if _needs_rehash(row["password_hash"]):
        users.set_password_hash(row["id"], hash_password(sandi))

    users.record_login_success(row["id"])
    return row


# ---------------------------------------------------------------------------
# Sesi
# ---------------------------------------------------------------------------
def current_user() -> dict | None:
    return st.session_state.get(_SESSION_KEY)


def is_logged_in() -> bool:
    return current_user() is not None


def start_session(user: dict) -> None:
    st.session_state[_SESSION_KEY] = {
        "id": user["id"],
        "username": user["username"],
        "is_admin": bool(user["is_admin"]),
    }


def logout() -> None:
    st.session_state.pop(_SESSION_KEY, None)


# ---------------------------------------------------------------------------
# Kelola pengguna (khusus admin)
# ---------------------------------------------------------------------------
def create_user(username, password, is_admin: bool) -> str:
    nama = validate_username(username)
    sandi = validate_password(password)
    try:
        users.insert_user(nama, hash_password(sandi), bool(is_admin))
    except UniqueViolation:
        raise AuthError(f"Username {nama} sudah dipakai.") from None
    return nama


def signup_code() -> str | None:
    kode = _secret("SIGNUP_CODE")
    kode = kode.strip() if kode else ""
    return kode or None


def signup_enabled() -> bool:
    return signup_code() is not None


def demo_signup_code() -> str | None:
    """Tampilkan kode undangan pada mode demo lokal agar mudah dicoba."""
    return signup_code() if is_local_preview() else None


def register(username, password, confirm, code) -> dict:
    """Daftarkan akun non-admin baru dengan kode undangan dari admin."""
    kode_benar = signup_code()
    if kode_benar is None:
        raise AuthError(
            "Pendaftaran mandiri belum diaktifkan. Minta admin mengisi "
            "SIGNUP_CODE di Secrets."
        )
    if not hmac.compare_digest(str(code or "").strip(), kode_benar):
        raise AuthError("Kode undangan salah.")
    if str(password or "") != str(confirm or ""):
        raise AuthError("Konfirmasi password tidak sama.")
    nama = create_user(username, password, is_admin=False)
    row = users.find_by_username(nama)
    if row is None:
        raise AuthError("Akun berhasil dibuat. Silakan masuk.")
    return row


def reset_password(username, password) -> None:
    row = users.find_by_username(normalize_username(username))
    if row is None:
        raise AuthError("Pengguna tidak ditemukan.")
    users.set_password_hash(row["id"], hash_password(validate_password(password)))


def list_users() -> list[dict]:
    return users.list_users()


def set_user_active(user_id: int, active: bool) -> None:
    users.set_active(user_id, active)


# ---------------------------------------------------------------------------
# Inisialisasi & konfigurasi
# ---------------------------------------------------------------------------
def config_error() -> str | None:
    if users.database_url():
        return None
    return (
        "DATABASE_URL belum diatur. Tambahkan connection string Supabase pada "
        "Secrets (lokal: .streamlit/secrets.toml, cloud: Settings > Secrets)."
    )


def is_local_preview() -> bool:
    return users.is_sqlite()


def demo_credentials() -> tuple[str, str] | None:
    """Akun demo hanya ditampilkan pada mode preview lokal bila masih sinkron.

    Bila password sudah diganti lewat menu Pengaturan, info demo tidak
    ditampilkan agar layar login tidak memberi kredensial yang salah.
    """
    if not is_local_preview():
        return None
    username = _secret("ADMIN_USERNAME")
    password = _secret("ADMIN_PASSWORD")
    if not username or not password:
        return None
    try:
        row = users.find_by_username(normalize_username(username))
        if not row:
            return None
        _hasher.verify(row["password_hash"], password)
    except Exception:
        return None
    return username, password


def _secret(key: str) -> str | None:
    nilai = None
    try:
        if key in st.secrets:
            nilai = st.secrets[key]
    except Exception:
        nilai = None
    return str(nilai) if nilai else os.environ.get(key)


def _seed_admin() -> None:
    """Buat admin pertama hanya bila tabel users masih kosong."""
    if users.count_users() > 0:
        return
    username = _secret("ADMIN_USERNAME")
    password = _secret("ADMIN_PASSWORD")
    if not username or not password:
        return
    try:
        nama = validate_username(username)
        sandi = validate_password(password)
    except AuthError:
        return
    try:
        users.insert_user(nama, hash_password(sandi), True)
    except UniqueViolation:
        pass


@st.cache_resource(show_spinner=False)
def _init_once() -> None:
    users.ensure_schema()
    _seed_admin()


def bootstrap() -> None:
    if users.database_url() is None:
        return
    try:
        _init_once()
    except Exception:
        # Halaman login akan menampilkan pesan koneksi bila database tidak terjangkau.
        pass


def user_count() -> int:
    return users.count_users()
