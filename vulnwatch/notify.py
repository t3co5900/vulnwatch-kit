"""Envío por Telegram y mail (SMTP)."""
import os
import smtplib
from email.message import EmailMessage
from html import escape
from pathlib import Path

import requests

MAX_ITEMS = 15
ICON ={"crítico": "🔴", "alto": "🟠", "medio": "🟡", "bajo": "🟢"}


def telegram_configured():
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"))


def send_telegram(text):
    token, chat = os.environ["TELEGRAM_BOT_TOKEN"], os.environ["TELEGRAM_CHAT_ID"]
    chunks, cur = [], ""
    for block in text.split("\n\n"):
        if len(cur) + len(block) > 3800:
            chunks.append(cur)
            cur = ""
        cur += block + "\n\n"
    chunks.append(cur)
    for chunk in chunks:
        r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", timeout=30, data={
            "chat_id": chat, "text": chunk.strip(), "parse_mode": "HTML",
            "disable_web_page_preview": "true"})
        r.raise_for_status()


def format_alert(vulns):
    parts = [f"<b>🚨 {len(vulns)} vulnerabilidad(es) nueva(s)</b>"]
    if len(vulns) > MAX_ITEMS:
        parts.append(f"Se muestran las {MAX_ITEMS} más graves; el resto va en el reporte semanal.")
    for v in vulns[:MAX_ITEMS]:
        lines = [f"{ICON[v['level']]} <b>{escape(v['id'])}</b> — {v['level'].upper()}"
                 f" (CVSS {v.get('score') or 'n/d'})",
                 f"Producto: {escape(', '.join(v['products']))}"]
        if v.get("affects_me") is True:
            lines.append("⚠️ <b>Afecta una versión que tenés instalada</b>")
        if v.get("kev"):
            lines.append("🔥 <b>Explotación activa confirmada (CISA KEV)</b>")
        if v.get("epss"):
            lines.append(f"Prob. de explotación (EPSS): {v['epss'] * 100:.0f}%")
        if v.get("fixed"):
            lines.append(f"Corregida en: {escape(v['fixed'])}")
        lines.append(escape(v.get("description", "")[:300]))
        if v.get("refs"):
            lines.append(escape(v["refs"][0]))
        parts.append("\n".join(lines))
    return "\n\n".join(parts)


def send_mail(subject, body, attachments):
    user, pwd = os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"]
    msg = EmailMessage()
    msg["Subject"], msg["From"] = subject, user
    msg["To"] = os.environ.get("MAIL_TO") or user
    msg.set_content(body)
    for p in attachments:
        p = Path(p)
        sub = "pdf" if p.suffix == ".pdf" else "vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        msg.add_attachment(p.read_bytes(), maintype="application", subtype=sub, filename=p.name)
    host = os.environ.get("SMTP_HOST") or "smtp.gmail.com"
    port = int(os.environ.get("SMTP_PORT") or 465)
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=60)
    else:  # 587 u otro puerto: STARTTLS
        server = smtplib.SMTP(host, port, timeout=60)
        server.starttls()
    with server as s:
        s.login(user, pwd)
        s.send_message(msg)
