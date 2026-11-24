"""Halaman masuk dan pendaftaran KOSPACE."""

from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

import streamlit as st

from .. import auth, ui

_ASSETS = Path(__file__).resolve().parents[2] / "assets"

_LABELS = ["🔑 Masuk", "📝 Daftar"]


@lru_cache(maxsize=1)
def _logo_b64() -> str:
    return base64.b64encode((_ASSETS / "kospace-logo.png").read_bytes()).decode("ascii")


def _render_masuk() -> None:
    demo = auth.demo_credentials()
    if demo:
        st.markdown(
            f"""
            <div class="ks-demo">
              <div class="ks-demo-title">🔓 Akun demo</div>
              <div class="ks-demo-row"><span>Username</span><code>{ui.esc(demo[0])}</code></div>
              <div class="ks-demo-row"><span>Password</span><code>{ui.esc(demo[1])}</code></div>
              <div class="ks-demo-note">
                Ditampilkan karena aplikasi masih tahap demo (SQLite lokal).
                Password dapat diganti di menu Pengaturan → Pengguna.
                Sebelum produksi, hapus info ini dan gunakan Supabase.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if "_prefill_username" in st.session_state:
        st.session_state["login_username"] = st.session_state.pop("_prefill_username")

    with st.form("form_login", clear_on_submit=True):
        username = st.text_input("Username", placeholder="contoh: pemilik", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        masuk = st.form_submit_button("Masuk", type="primary")

    if masuk:
        try:
            user = auth.authenticate(username, password)
        except auth.AuthError as exc:
            st.error(str(exc))
        except Exception:
            st.error("Gagal masuk karena masalah koneksi database. Coba lagi.")
        else:
            auth.start_session(user)
            st.rerun()

    if auth.is_local_preview():
        st.caption(
            "Mode preview lokal: akun disimpan di SQLite (kospace_auth.db). "
            "Gunakan DATABASE_URL Supabase untuk produksi."
        )


def _render_daftar() -> None:
    st.caption(
        "Buat akun pengelola dengan kode undangan dari admin. "
        "Akun baru otomatis berperan Pengelola (bukan Admin)."
    )

    kode_demo = auth.demo_signup_code()
    if kode_demo:
        st.markdown(
            f"""
            <div class="ks-demo">
              <div class="ks-demo-title">🎟️ Kode undangan demo</div>
              <div class="ks-demo-row"><span>Kode</span><code>{ui.esc(kode_demo)}</code></div>
              <div class="ks-demo-note">
                Hanya tampil pada mode preview lokal. Pada produksi (Supabase),
                bagikan kode ini secara pribadi kepada pengelola yang berhak.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if not auth.signup_enabled():
        st.info(
            "Pendaftaran mandiri belum diaktifkan. Minta admin mengisi "
            "SIGNUP_CODE di Secrets (lokal: .streamlit/secrets.toml, "
            "cloud: Settings > Secrets)."
        )
        return

    with st.form("form_daftar", clear_on_submit=True):
        username = st.text_input(
            "Username",
            placeholder="contoh: pengelola.baru",
            key="daftar_username",
        )
        password = st.text_input(
            "Password",
            type="password",
            help=f"Minimal {auth.MIN_PASSWORD} karakter.",
            key="daftar_password",
        )
        confirm = st.text_input("Ulangi password", type="password", key="daftar_confirm")
        code = st.text_input(
            "Kode undangan",
            type="password",
            help="Tanyakan kode undangan kepada admin kos.",
            key="daftar_code",
        )
        daftar = st.form_submit_button("Daftar", type="primary")

    if daftar:
        try:
            nama = auth.register(username, password, confirm, code)["username"]
        except auth.AuthError as exc:
            st.error(str(exc))
        except Exception:
            st.error("Pendaftaran gagal karena masalah koneksi database. Coba lagi.")
        else:
            st.session_state["_prefill_username"] = nama
            st.session_state["_tab_target_Masuk"] = _LABELS[0]
            ui.flash("success", f"Akun {nama} berhasil dibuat. Silakan masuk.")
            st.rerun()


def render() -> None:
    _, tengah, _ = st.columns([1, 1.15, 1])

    with tengah:
        st.markdown(
            f"""
            <div class="ks-login-brand">
              <img src="data:image/png;base64,{_logo_b64()}" alt="KOSPACE" />
            </div>
            <div class="ks-login-title">Masuk ke KOSPACE</div>
            <div class="ks-login-sub">Administrasi Kos · akses khusus pengelola</div>
            """,
            unsafe_allow_html=True,
        )

        error = auth.config_error()
        if error:
            st.error(error)
            st.caption(
                "Isi DATABASE_URL dengan connection string Session Pooler Supabase, "
                "lalu muat ulang halaman."
            )
            return

        try:
            jumlah = auth.user_count()
        except Exception:
            st.error("Tidak bisa terhubung ke database pengguna.")
            st.caption("Periksa DATABASE_URL di Secrets, lalu muat ulang halaman.")
            return

        if jumlah == 0:
            st.info(
                "Belum ada akun. Isi ADMIN_USERNAME dan ADMIN_PASSWORD di Secrets "
                f"(password minimal {auth.MIN_PASSWORD} karakter), lalu muat ulang halaman."
            )

        ui.show_flash()
        tabs = dict(zip(_LABELS, ui.tabbed("Masuk", _LABELS)))
        with tabs[_LABELS[0]]:
            _render_masuk()
        with tabs[_LABELS[1]]:
            _render_daftar()

        st.markdown(
            '<div class="ks-login-footer">KOSPACE v1.0 · Akun dikelola oleh admin</div>',
            unsafe_allow_html=True,
        )
