#!/usr/bin/env python3
import argparse
import os
import smtplib
import sys
from email.message import EmailMessage


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Envio simple de correo por Gmail SMTP")
    parser.add_argument("--to", required=True, help="Destinatarios separados por coma")
    parser.add_argument("--subject", required=True, help="Asunto")
    parser.add_argument("--body", required=True, help="Mensaje de texto")
    parser.add_argument("--from-name", default="Filencrypt Admin", help="Nombre visible del remitente")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    gmail_user = os.getenv("GMAIL_USER", "").strip()
    gmail_app_password = os.getenv("GMAIL_APP_PASSWORD", "").strip()

    if not gmail_user or not gmail_app_password:
        print("Error: faltan GMAIL_USER o GMAIL_APP_PASSWORD en el entorno.")
        return 1

    recipients = [x.strip() for x in args.to.split(",") if x.strip()]
    if not recipients:
        print("Error: no hay destinatarios validos.")
        return 1

    msg = EmailMessage()
    msg["Subject"] = args.subject
    msg["From"] = f"{args.from_name} <{gmail_user}>"
    msg["To"] = ", ".join(recipients)
    msg.set_content(args.body)

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(gmail_user, gmail_app_password)
            server.send_message(msg)
    except Exception as exc:
        print(f"Error enviando correo: {exc}")
        return 1

    print(f"OK: correo enviado a {len(recipients)} destinatario(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
