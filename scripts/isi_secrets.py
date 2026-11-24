"""Isi .streamlit/secrets.toml lewat terminal.

Jalankan dari folder proyek:
    .venv\\Scripts\\python scripts\\isi_secrets.py

Tempel connection string Session Pooler Supabase dengan password MENTAH
(belum di-URL-encode); script akan meng-encode password secara otomatis.
"""

from __future__ import annotations

import json
from getpass import getpass
from pathlib import Path
from urllib.parse import quote


def _toml(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def build_url(mentah: str) -> str:
    """URL-encode bagian password tanpa merusak karakter khusus password."""
    if "://" not in mentah or "@" not in mentah:
        raise SystemExit("Connection string harus berbentuk postgresql://user:password@host/db.")
    scheme, sisa = mentah.split("://", 1)
    if not scheme.startswith("postgres"):
        raise SystemExit("Connection string harus diawali postgresql://")
    userinfo, hostpath = sisa.rsplit("@", 1)
    user, _, password = userinfo.partition(":")
    if not user or not password:
        raise SystemExit("Connection string tidak memiliki username/password.")
    return f"{scheme}://{quote(user, safe='')}:{quote(password, safe='')}@{hostpath}"


def main() -> None:
    mentah = input("Tempel connection string Session Pooler Supabase: ").strip()
    url = build_url(mentah)

    admin_user = input("Username admin [pemilik]: ").strip() or "pemilik"
    admin_pass = getpass("Password admin (minimal 12 karakter, tidak ditampilkan): ")
    if len(admin_pass) < 12:
        raise SystemExit("Password admin minimal 12 karakter.")
    kode = input("Kode undangan halaman Daftar (opsional, Enter untuk menonaktifkan): ").strip()

    baris = [
        "# File ini di-gitignore. Jangan di-commit.",
        f"DATABASE_URL = {_toml(url)}",
        f"ADMIN_USERNAME = {_toml(admin_user)}",
        f"ADMIN_PASSWORD = {_toml(admin_pass)}",
    ]
    if kode:
        baris.append(f"SIGNUP_CODE = {_toml(kode)}")

    path = Path(".streamlit/secrets.toml")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(baris) + "\n", encoding="utf-8")
    print(f"Tersimpan di {path}. Muat ulang halaman aplikasi.")


if __name__ == "__main__":
    main()
