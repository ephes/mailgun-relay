from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("MAILGUN_RELAY_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("MAILGUN_RELAY_BIND_PORT", "8085"))
    log_level = os.environ.get("MAILGUN_RELAY_LOG_LEVEL", "info").lower()
    uvicorn.run(
        "mailgun_relay.app:create_app",
        factory=True,
        host=host,
        port=port,
        log_level=log_level,
        access_log=False,
    )


if __name__ == "__main__":
    main()
