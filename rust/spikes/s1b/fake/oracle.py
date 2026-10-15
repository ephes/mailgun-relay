"""Python oracle: run mailgun_relay.smtp_client.submit against the fake server.

Usage (from the repo root): uv run python rust/spikes/s1b/fake/oracle.py \
    PORT STARTTLS(true|false) CA_FILE USER(or -) FROM TO1,TO2,... [TIMEOUT_S]
Password comes from S1B_SMTP_PASS. Prints the HTTP status the route would map to.
"""

from __future__ import annotations

import os
import sys
from email.message import EmailMessage

from mailgun_relay.smtp_client import FailureCategory, SmtpSubmitError, SmtpTransport, submit

STATUS = {FailureCategory.PERMANENT: 502, FailureCategory.TEMPORARY: 503, FailureCategory.AUTH: 502}


def main() -> None:
    port, starttls, ca_file, user, sender, rcpts = sys.argv[1:7]
    timeout_s = float(sys.argv[7]) if len(sys.argv) > 7 else 30.0
    recipients = rcpts.split(",")
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = "s1b oracle"
    msg.set_content("spike body\n")
    transport = SmtpTransport(
        host="localhost",
        port=int(port),
        username=None if user == "-" else user,
        password=None if user == "-" else os.environ.get("S1B_SMTP_PASS", ""),
        use_starttls=starttls == "true",
        timeout_s=timeout_s,
        ca_file=ca_file or None,
    )
    try:
        refused = submit(msg, envelope_sender=sender, recipients=recipients, transport=transport)
    except SmtpSubmitError as exc:
        print(f"status={STATUS[exc.category]} reason={exc.reason}")
        return
    print(f"status=200 refused={sorted((a, c) for a, (c, _t) in refused.items())}")


if __name__ == "__main__":
    main()
