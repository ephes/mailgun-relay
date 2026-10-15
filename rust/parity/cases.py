"""The case corpus of the parity harness (rust/PLAN.md 7.4).

Each request case is sent byte for byte to both implementations; ``status``
is what Python answers (the oracle, checked on every run). A case whose
Rust answer differs on purpose names its entry of PLAN.md section 3
(``divergence``) and the Rust status. ``profile`` selects the environment
the pair of processes runs with (``PROFILES``); ``smtp``/``cert`` script the
fake SMTP server (the scenario format of ``smtp_fake.py``).

The secrets carry the twelve production policies (labels, domains and
senders of the startup record and ``handoff/fix-403-result.md``,
``e2e-probe-result.md``) with fake tokens, plus two test-only policies.
Standard library only.
"""

from __future__ import annotations

import base64
import json
import random
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# ------------------------------------------------------------------ secrets

WD = "wersdoerfer.de"
MG = "mg.wersdoerfer.de"
DJANGO = "jochen-django@wersdoerfer.de"
POLICIES: list[tuple[str, list[str], list[str], list[str] | None]] = [
    ("homepage-staging", [MG], [WD], ["jochen-homepage@wersdoerfer.de", DJANGO]),
    ("homepage-production", [MG], [WD], ["jochen-homepage@wersdoerfer.de", DJANGO]),
    (
        "python-podcast-staging",
        ["mg.python-podcast.de"],
        ["mg.python-podcast.de", WD],
        ["noreply@mg.python-podcast.de", DJANGO],
    ),
    (
        "python-podcast-production",
        ["mg.python-podcast.de"],
        ["mg.python-podcast.de", WD],
        ["noreply@mg.python-podcast.de", DJANGO],
    ),
    ("villakunterbunt-staging", [MG], [WD], ["jochen-villakunterbunt@wersdoerfer.de"]),
    ("recorder-production", [MG], [WD], ["recorder@wersdoerfer.de"]),
    ("lead-production", [MG], [WD], ["jochen-lead@wersdoerfer.de", DJANGO]),
    ("lead-staging", [MG], [WD], ["jochen-lead@wersdoerfer.de", DJANGO]),
    ("konektom-staging", ["mg.konektom.org"], ["konektom.org"], ["noreply@konektom.org"]),
    (
        "registry-staging",
        ["mg.staging.django-cast.com"],
        ["email.mg.staging.django-cast.com"],
        ["noreply@email.mg.staging.django-cast.com"],
    ),
    ("ggs-lennestrasse-staging", [MG], [WD], ["jochen-ggs@wersdoerfer.de"]),
    (
        "nyxmon-relay-probe",
        [MG],
        ["xn--wersdrfer-47a.de"],
        ["nyxmon-relay-probe@xn--wersdrfer-47a.de"],
    ),
    # Test-only: a domain-only policy and an IDN one.
    ("parity-domain-only", ["mg.example.org"], ["example.org"], None),
    ("parity-idn", ["mg.wersdörfer.de"], ["wersdörfer.de"], ["Jochen@Wersdörfer.de"]),
]
PRODUCTION_LABELS = [p[0] for p in POLICIES[:12]]


def token(label: str) -> str:
    """The fake token of a label (never a production value)."""
    return f"parity-token-{label}"


def secrets_yaml() -> str:
    import hashlib

    lines = ["smtp:", "  username: mailgun-relay@xn--wersdrfer-47a.de", "  password: parity-smtp"]
    lines.append("tokens:")
    for label, mailgun, from_domains, addresses in POLICIES:
        digest = hashlib.sha256(token(label).encode()).hexdigest()
        lines += [f"  - label: {label}", f"    token_sha256: '{digest}'"]
        lines.append(f"    mailgun_domains: {json.dumps(mailgun, ensure_ascii=False)}")
        lines.append(f"    allowed_from_domains: {json.dumps(from_domains, ensure_ascii=False)}")
        if addresses is not None:
            lines.append(f"    allowed_from_addresses: {json.dumps(addresses, ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ requests

PROFILES: dict[str, dict[str, str]] = {
    "default": {},
    # Small limits for the N / N+1 cases (PLAN.md 2.3 steps 1, 3, 4, 6-8).
    "small": {
        "MAILGUN_RELAY_MAX_BODY_BYTES": "3000",
        "MAILGUN_RELAY_MAX_ATTACHMENTS": "2",
        "MAILGUN_RELAY_MAX_ATTACHMENT_BYTES": "500",
        "MAILGUN_RELAY_MAX_RECIPIENTS": "3",
        "MAILGUN_RELAY_MAX_HEADER_VALUE_LENGTH": "40",
    },
    "strict": {"MAILGUN_RELAY_FAIL_ON_PARTIAL_REFUSAL": "true"},
    "plain": {"MAILGUN_RELAY_SMTP_STARTTLS": "false"},
}


@dataclass
class Request:
    method: str = "POST"
    path: str = "/v3/mg.wersdoerfer.de/messages"
    # Without Host, Connection and the framing headers.
    headers: list[tuple[str, str | bytes]] = field(default_factory=list)
    body: bytes = b""
    # "auto": Content-Length of the body; None: no length; else the raw value.
    length: str | None = "auto"
    # A chunked body (Transfer-Encoding) instead of a length.
    chunks: list[bytes] | None = None
    # Send the body in two writes, split at this offset.
    split: int | None = None


@dataclass
class Case:
    name: str
    request: Request
    status: int | frozenset[int]
    smtp: dict[str, Any] = field(default_factory=dict)
    cert: str = "good"
    profile: str = "default"
    divergence: str | None = None
    rust_status: int | None = None


@dataclass
class StartupCase:
    name: str
    env: dict[str, str]
    probe: Request
    python: str  # "serves <status>" or "exits <code>"
    rust: str | None = None
    divergence: str | None = None
    secrets_mode: int | None = None


def basic(label: str | None, *, user: str = "api", password: str | None = None) -> str:
    secret = password if password is not None else token(label or "")
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


Fields = list[tuple[str, str]]
# (field, filename, content type, data)
Upload = tuple[str, str, str, bytes]


def urlencoded(fields: Fields) -> tuple[str, bytes]:
    """As ``requests`` (Anymail) encodes ``data``: ``quote_plus``, UTF-8."""
    return "application/x-www-form-urlencoded", urllib.parse.urlencode(fields).encode()


def _quote_param(value: str) -> str:
    # urllib3's HTML5 form encoding of names and filenames.
    return value.replace('"', "%22").replace("\r", "%0D").replace("\n", "%0A")


def multipart(
    fields: Fields,
    files: tuple[Upload, ...] | list[Upload] = (),
    *,
    boundary: str = "9b5f2c1d0e3a4f6b8c7d9e0f1a2b3c4d",
    charset: str | None = None,
    parts: list[tuple[str, str] | Upload] | None = None,
) -> tuple[str, bytes]:
    """As ``requests`` (Anymail with files) and Go's ``mime/multipart``
    (recorder) write a form: the fields, then the files (or ``parts`` in
    the given order)."""
    out = b""
    for part in parts if parts is not None else [*fields, *files]:
        name = _quote_param(part[0])
        if len(part) == 2:
            out += f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            out += part[1].encode() + b"\r\n"
        else:
            _, filename, content_type, data = part  # type: ignore[misc]
            out += (
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
                f'filename="{_quote_param(filename)}"\r\nContent-Type: {content_type}\r\n\r\n'
            ).encode()
            out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    content_type = f"multipart/form-data; boundary={boundary}"
    if charset is not None:
        content_type += f"; charset={charset}"
    return content_type, out


def post(
    fields: Fields,
    *,
    label: str | None = "homepage-production",
    domain: str = MG,
    files: tuple[Upload, ...] | list[Upload] = (),
    encoding: str = "urlencoded",
    headers: tuple[tuple[str, str | bytes], ...] = (),
    authorization: str | bytes | None = None,
    **request: Any,
) -> Request:
    if files or encoding == "multipart":
        content_type, body = multipart(fields, files)
    else:
        content_type, body = urlencoded(fields)
    head: list[tuple[str, str | bytes]] = []
    if authorization is not None:
        head.append(("Authorization", authorization))
    elif label is not None:
        head.append(("Authorization", basic(label)))
    head.append(("Content-Type", content_type))
    # Anymail quotes the sender domain into the path (``quote(d, safe="")``).
    path = f"/v3/{urllib.parse.quote(domain, safe='')}/messages"
    return Request(path=path, headers=head + list(headers), body=body, **request)


HOMEPAGE_FROM = "Homepage <jochen-homepage@wersdoerfer.de>"
PODCAST_FROM = "Python Podcast <noreply@mg.python-podcast.de>"
ADMIN = "jochen-admin@wersdoerfer.de"


def minimal(**overrides: str) -> Fields:
    fields = {"from": HOMEPAGE_FROM, "to": ADMIN, "subject": "Hallo", "text": "Hallo Welt"}
    fields.update(overrides)
    return list(fields.items())


def _traceback(path: str) -> str:
    frames = "".join(
        f'  File "/home/app/site/.venv/lib/python3.14/site-packages/django/core/handlers/{n}.py",'
        f" line {40 + i * 13}, in inner\n    response = get_response(request)\n"
        for i, n in enumerate(("exception", "base", "exception", "base"))
    )
    return (
        f"Internal Server Error: {path}\n\nTraceback (most recent call last):\n{frames}"
        "ZeroDivisionError: division by zero\n\n\n<WSGIRequest: GET '"
        f"{path}'>\n\nrequest.META:\n" + "".join(f"HTTP_X_{i}: wert-{i} ü\n" for i in range(60))
    )


GERMAN_TEXTS = [
    "Hallo,\n\nSie erhalten diese E-Mail, weil Sie oder jemand anderes ein Passwort für Ihr "
    "Benutzerkonto angefordert hat.\nKlicken Sie auf den Link, um es zurückzusetzen:\n\n"
    "https://python-podcast.de/accounts/password/reset/key/1-abc/\n\nGrüße\nIhr Team\n",
    "Größenänderung der Seite „Über uns“ wurde veröffentlicht.\n\n— Wagtail\n",
    "Neue Episode: Ärger mit Unicode \N{EN DASH} ß, ä, ö, ü, € und 😀 im Betreff\n",
]
GERMAN_SUBJECTS = [
    "[Python Podcast] Passwort zurücksetzen",
    "Seite „Über uns“ wurde veröffentlicht",
    "Bestätigung Ihrer E-Mail-Adresse",
    "[Django] ERROR (EXTERNAL IP): Internal Server Error: /episodes/ärger/",
]


# ------------------------------------------------------------------ corpus


def production_cases() -> list[Case]:
    """The client shapes of PLAN.md 7.4 (P1-P12 of phase 1)."""
    cases = [
        Case("anymail homepage default from", post(minimal()), 200),
        Case(
            "anymail homepage SERVER_EMAIL error mail",
            post(
                [
                    ("from", DJANGO),
                    ("to", "jochen-homepage@wersdoerfer.de"),
                    ("subject", "[Django] ERROR (EXTERNAL IP): Internal Server Error: /blog/x/"),
                    ("text", _traceback("/blog/x/")),
                ],
                label="homepage-staging",
            ),
            200,
        ),
        Case(
            "anymail python-podcast two admins german",
            post(
                [
                    ("from", PODCAST_FROM),
                    ("to", "jochen-pythonpodcast@wersdoerfer.de"),
                    ("to", "Dominik Geldmacher <admin@example.com>"),
                    ("subject", GERMAN_SUBJECTS[0]),
                    ("text", GERMAN_TEXTS[0]),
                ],
                label="python-podcast-production",
                domain="mg.python-podcast.de",
            ),
            200,
        ),
        Case(
            "anymail python-podcast SERVER_EMAIL cross-domain",
            post(
                [
                    ("from", DJANGO),
                    ("to", "jochen-pythonpodcast@wersdoerfer.de"),
                    ("subject", GERMAN_SUBJECTS[3]),
                    ("text", _traceback("/episodes/ärger/")),
                ],
                label="python-podcast-staging",
                domain="mg.python-podcast.de",
            ),
            200,
        ),
        Case(
            "anymail ggs wagtail notification html auto-submitted",
            post(
                [
                    ("from", "jochen-ggs@wersdoerfer.de"),
                    ("to", "Redaktion <redaktion@example.org>"),
                    ("subject", GERMAN_SUBJECTS[1]),
                    ("h:Auto-Submitted", "auto-generated"),
                    ("text", GERMAN_TEXTS[1]),
                    ("html", "<p>Größenänderung der Seite <b>„Über uns“</b></p>\n"),
                ],
                label="ggs-lennestrasse-staging",
            ),
            200,
        ),
        Case(
            "anymail allauth unknown account to external IDN address",
            post(
                [
                    ("from", HOMEPAGE_FROM),
                    ("to", "jemand@bücher.example"),
                    ("subject", "[Homepage] Unknown account"),
                    ("text", "You are receiving this e-mail because you or someone else tried"),
                ]
            ),
            200,
        ),
        Case(
            "anymail villakunterbunt",
            post(
                minimal(**{"from": "jochen-villakunterbunt@wersdoerfer.de"}),
                label="villakunterbunt-staging",
            ),
            200,
        ),
        Case(
            "anymail lead default from",
            post(minimal(**{"from": "Lead <jochen-lead@wersdoerfer.de>"}), label="lead-production"),
            200,
        ),
        Case(
            "anymail lead SERVER_EMAIL",
            post(minimal(**{"from": DJANGO}), label="lead-staging"),
            200,
        ),
        Case(
            "anymail konektom",
            post(
                minimal(**{"from": "Konektom <noreply@konektom.org>"}),
                label="konektom-staging",
                domain="mg.konektom.org",
            ),
            200,
        ),
        Case(
            "anymail registry signup verification",
            post(
                [
                    ("from", "noreply@email.mg.staging.django-cast.com"),
                    ("to", "new-user@example.com"),
                    ("subject", "Please Confirm Your Email Address"),
                    ("text", "Hello from django-cast!\n\nTo confirm, go to https://x.test/c/\n"),
                    ("html", "<p>Hello from django-cast!</p>"),
                ],
                label="registry-staging",
                domain="mg.staging.django-cast.com",
            ),
            200,
        ),
        Case(
            "nyxmon relay probe",
            post(
                [
                    ("from", "nyxmon-relay-probe@xn--wersdrfer-47a.de"),
                    ("to", "monitor@xn--wersdrfer-47a.de"),
                    ("subject", "[nyxmon-relay] 6f1c0d2e9a7b"),
                    ("text", "nyxmon relay probe 6f1c0d2e9a7b\n"),
                ],
                label="nyxmon-relay-probe",
            ),
            200,
        ),
        Case(
            "anymail with reply-to cc bcc and duplicates",
            post(
                [
                    ("from", HOMEPAGE_FROM),
                    ("to", "a@example.com"),
                    ("to", "b@example.com"),
                    ("cc", "a@example.com"),
                    ("cc", "Carla <c@example.com>"),
                    ("bcc", "b@example.com"),
                    ("bcc", "hidden@example.net"),
                    ("subject", "Verteiler"),
                    ("h:Reply-To", '"Doe, Jane" <jane@example.org>, support@example.org'),
                    ("text", "x"),
                ]
            ),
            200,
        ),
        Case(
            "anymail amp-html",
            post([*minimal(html="<p>h</p>"), ("amp-html", "<html ⚡4email><body>a</body></html>")]),
            200,
        ),
    ]
    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256))
    pdf = b"%PDF-1.4\n" + bytes(range(256)) * 4
    attachments = [
        ("attachment", [("attachment", "rechnung.pdf", "application/pdf", pdf)], None),
        (
            "attachment non-ascii name",
            [("attachment", "Übersicht ä.txt", "text/plain", b"x\n")],
            None,
        ),
        (
            "two attachments",
            [
                ("attachment", "a.txt", "text/plain", "Grüße\n".encode()),
                ("attachment", "b.bin", "application/octet-stream", bytes(range(256))),
            ],
            None,
        ),
        (
            "inline with html",
            [("inline", "logo.png", "image/png", png)],
            '<img src="cid:logo.png">',
        ),
        ("inline without html", [("inline", "logo.png", "image/png", png)], None),
        (
            "inline and attachment with html",
            [
                ("inline", "logo.png", "image/png", png),
                ("attachment", "a.bin", "multipart/mixed", b"payload"),
            ],
            '<p><img src="cid:logo.png"></p>',
        ),
        ("attachment empty type", [("attachment", "x.dat", "", b"data")], None),
        ("attachment empty filename", [("attachment", "", "text/plain", b"data")], None),
        (
            "attachment message type",
            [("attachment", "m.eml", "message/rfc822", b"Subject: x\r\n\r\nb")],
            None,
        ),
    ]
    for name, files, html in attachments:
        fields = minimal(**({"html": html} if html else {}))
        cases.append(Case(f"anymail multipart {name}", post(fields, files=files), 200))
    cases += _anymail_variants() + _recorder_cases()
    return cases


def _anymail_variants() -> list[Case]:
    """Seeded Anymail 15.2 urlencoded sends: from, 1-2 to, subject, text,
    sometimes html and h:Auto-Submitted, in Anymail's field order."""
    rng = random.Random(6)  # noqa: S311 - a seeded corpus, not a secret
    senders = [
        ("homepage-production", MG, HOMEPAGE_FROM),
        ("homepage-staging", MG, DJANGO),
        ("python-podcast-production", "mg.python-podcast.de", PODCAST_FROM),
        ("python-podcast-staging", "mg.python-podcast.de", DJANGO),
        ("ggs-lennestrasse-staging", MG, "jochen-ggs@wersdoerfer.de"),
        ("villakunterbunt-staging", MG, "Villa <jochen-villakunterbunt@wersdoerfer.de>"),
        ("lead-production", MG, "Lead <jochen-lead@wersdoerfer.de>"),
    ]
    recipients = [
        "jochen-admin@wersdoerfer.de",
        "Jochen Wersdörfer <jochen@wersdoerfer.de>",
        "user+tag@example.com",
        '"Müller, Hans" <hans@example.de>',
        "info@xn--bcher-kva.example",
        "o'brien@example.ie",
    ]
    cases = []
    for i in range(24):
        label, domain, sender = senders[i % len(senders)]
        fields: Fields = [("from", sender)]
        fields += [("to", r) for r in rng.sample(recipients, rng.choice((1, 2)))]
        fields.append(("subject", rng.choice([*GERMAN_SUBJECTS, "Test " * rng.randint(1, 60)])))
        if rng.random() < 0.4:
            fields.append(("h:Auto-Submitted", "auto-generated"))
        text = rng.choice([*GERMAN_TEXTS, _traceback(f"/p/{i}/")])
        fields.append(("text", text))
        if rng.random() < 0.3:
            fields.append(("html", "<p>" + text.replace("\n", "<br>") + "</p>"))
        cases.append(
            Case(f"anymail variant {i:02d} {label}", post(fields, label=label, domain=domain), 200)
        )
    return cases


def _recorder_cases() -> list[Case]:
    """The recorder (Go ``mime/multipart``): four text fields in random
    order (a Go map), a 60-hex-digit boundary."""
    rng = random.Random(7)  # noqa: S311 - a seeded corpus, not a secret
    fields = [
        ("from", "Recorder <recorder@wersdoerfer.de>"),
        ("to", "jochen@wersdoerfer.de"),
        ("subject", "Ihr Login-Link für den Recorder"),
        ("text", "Hallo,\n\nhier ist Ihr Link: https://recorder.example/login/abc\n"),
    ]
    cases = []
    for i in range(10):
        order = fields[:]
        rng.shuffle(order)
        boundary = "".join(rng.choice("0123456789abcdef") for _ in range(60))
        content_type, body = multipart(order, boundary=boundary)
        request = Request(
            headers=[
                ("Authorization", basic("recorder-production")),
                ("Content-Type", content_type),
                ("User-Agent", "Go-http-client/1.1"),
                ("Accept-Encoding", "gzip"),
            ],
            body=body,
        )
        names = "-".join(n for n, _ in order)
        cases.append(Case(f"recorder multipart {i} {names}", request, 200))
    return cases


def policy_cases() -> list[Case]:
    """Every production policy: its sender passes, a foreign sender of an
    allowed domain, a foreign from domain and a foreign path domain are
    403 (PLAN.md 2.3 step 5, 2.6)."""
    cases = []
    for label, mailgun, from_domains, addresses in POLICIES:
        path = mailgun[0]
        sender = addresses[0] if addresses else f"someone@{from_domains[0]}"
        domain = from_domains[0]
        base = minimal(**{"from": sender})
        cases.append(Case(f"policy {label} allowed", post(base, label=label, domain=path), 200))
        if addresses is not None:
            other = minimal(**{"from": f"someone-else@{domain}"})
            cases.append(
                Case(f"policy {label} other address", post(other, label=label, domain=path), 403)
            )
        foreign = minimal(**{"from": "x@evil.test"})
        cases.append(
            Case(
                f"policy {label} foreign from domain", post(foreign, label=label, domain=path), 403
            )
        )
        other_path = "mg.python-podcast.de" if path != "mg.python-podcast.de" else MG
        cases.append(
            Case(f"policy {label} foreign path", post(base, label=label, domain=other_path), 403)
        )
    homepage = minimal()
    cases += [
        Case("policy path upper case", post(homepage, domain="MG.WERSDOERFER.DE"), 200),
        Case("policy path trailing dot", post(homepage, domain="mg.wersdoerfer.de."), 403),
        Case("policy parent domain as path", post(homepage, domain=WD), 403),
        Case("policy path invalid", post(homepage, domain="a_b.de"), 400),
        Case(
            "policy path IDN",
            post(
                minimal(**{"from": "jochen@xn--wersdrfer-47a.de"}),
                label="parity-idn",
                domain="mg.wersdörfer.de",
            ),
            200,
        ),
        Case(
            "policy path punycode",
            post(
                minimal(**{"from": "JOCHEN@wersdörfer.de"}),
                label="parity-idn",
                domain="mg.xn--wersdrfer-47a.de",
            ),
            200,
        ),
        Case(
            "policy idn other address",
            post(
                minimal(**{"from": "anna@wersdörfer.de"}),
                label="parity-idn",
                domain="mg.xn--wersdrfer-47a.de",
            ),
            403,
        ),
        Case(
            "policy from upper case",
            post(minimal(**{"from": "Jochen-Homepage@WERSDOERFER.DE"})),
            200,
        ),
        Case(
            "policy from in angle brackets only",
            post(minimal(**{"from": "<jochen-homepage@wersdoerfer.de>"})),
            200,
        ),
        Case(
            "policy ggs with django sender",
            post(minimal(**{"from": DJANGO}), label="ggs-lennestrasse-staging"),
            403,
        ),
        Case(
            "policy ggs webmaster localhost",
            post(minimal(**{"from": "webmaster@localhost"}), label="ggs-lennestrasse-staging"),
            400,
        ),
        Case("policy from not an address", post(minimal(**{"from": "not-an-email"})), 400),
        Case(
            "policy from with crlf injection",
            post(minimal(**{"from": "jochen-homepage@wersdoerfer.de\nBcc: x@evil.test"})),
            400,
        ),
        Case(
            "policy from two addresses",
            post(minimal(**{"from": "jochen-homepage@wersdoerfer.de, x@evil.test"})),
            400,
        ),
        Case("policy from EAI local part", post(minimal(**{"from": "jörg@wersdoerfer.de"})), 400),
        Case(
            "policy from IDN",
            post(
                minimal(**{"from": "Jochen <jochen@wersdörfer.de>"}),
                label="parity-idn",
                domain="mg.wersdörfer.de",
            ),
            200,
        ),
        Case(
            "policy path snowman (D-10)",
            post(homepage, domain="☃.de"),
            400,
            divergence="D-10",
            rust_status=403,
        ),
    ]
    return cases


def auth_cases() -> list[Case]:
    fields = minimal()
    raw = [
        ("auth missing", None, 401),
        ("auth wrong token", basic(None, password="nope"), 401),  # noqa: S106
        ("auth wrong user", basic("homepage-production", user="API"), 401),
        ("auth lower-case scheme", "basic " + basic("homepage-production")[6:], 401),
        ("auth bearer", "Bearer " + token("homepage-production"), 401),
        ("auth surrounding whitespace", "Basic  " + basic("homepage-production")[6:] + " \t", 200),
        ("auth no colon", "Basic " + base64.b64encode(b"api" + token("x").encode()).decode(), 401),
        ("auth non-ascii byte", b"Basic \xe4" + basic("homepage-production")[6:].encode(), 401),
        (
            "auth embedded space",
            basic("homepage-production")[:10] + " " + basic("homepage-production")[10:],
            401,
        ),
    ]
    cases = []
    for name, header, status in raw:
        request = post(fields, label=None, authorization=header)
        cases.append(Case(name, request, status))
    # The body is not read when authentication fails.
    malformed = Request(
        headers=[("Content-Type", "multipart/form-data; boundary=x")], body=b"garbage"
    )
    cases.append(Case("auth missing before malformed multipart", malformed, 401))
    # Non-zero trailing bits before the padding decode the same (PLAN.md 2.3 step 2).
    encoded = basic("lead-staging")[6:]
    assert encoded.endswith("=") and not encoded.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    bits = alphabet[alphabet.index(encoded[-2]) | 1]
    lead = minimal(**{"from": "jochen-lead@wersdoerfer.de"})
    for name, value, status in (
        ("auth padding", encoded, 200),
        ("auth trailing bits", encoded[:-2] + bits + "=", 200),
        ("auth padding missing", encoded[:-1], 401),
        ("auth padding doubled", encoded + "=", 401),
    ):
        cases.append(Case(name, post(lead, label=None, authorization="Basic " + value), status))
    return cases


def field_cases() -> list[Case]:
    """PLAN.md 2.3 steps 4 and 6-9: field rules, subject, custom headers,
    recipients, message construction."""
    crlf_name = "=?utf-8?B?YQ0KYg==?= <a@example.org>"
    plain: list[tuple[str, Fields | None, int]] = [
        ("field o:tag", [*minimal(), ("o:tag", "x")], 400),
        ("field v:var", [*minimal(), ("v:x", "1")], 400),
        ("field t:version", [*minimal(), ("t:version", "1")], 400),
        ("field template", [*minimal(), ("template", "t")], 400),
        ("field recipient-variables", [*minimal(), ("recipient-variables", "{}")], 400),
        ("field unknown", [*minimal(), ("foo", "bar")], 400),
        ("field two from", [*minimal(), ("from", HOMEPAGE_FROM)], 400),
        ("field no from", [(k, v) for k, v in minimal() if k != "from"], 400),
        ("field no subject", [(k, v) for k, v in minimal() if k != "subject"], 400),
        ("field empty subject", minimal(subject=""), 200),
        ("field no body", [(k, v) for k, v in minimal() if k != "text"], 400),
        ("field empty text (D-1)", minimal(text=""), 400),
        ("field empty text with html", [*minimal(text=""), ("html", "<p>h</p>")], 200),
        ("field empty html with text", [*minimal(), ("html", "")], 200),
        (
            "field html only",
            [(k, v) for k, v in minimal() if k != "text"] + [("html", "<b>x</b>")],
            200,
        ),
        ("field last subject wins", [*minimal(), ("subject", "Zweiter")], 200),
        ("field subject crlf", minimal(subject="a\r\nBcc: x@evil.test"), 400),
        ("field subject stripped", minimal(subject="  padded  "), 200),
        ("field subject non-ascii long", minimal(subject="Grüße " * 100), 200),
        ("field subject encoded word", minimal(subject="=?utf-8?q?Gr=C3=BC=C3=9Fe?="), 200),
        ("field subject control char", minimal(subject="a\x01b"), 400),
        ("field subject tab", minimal(subject="a\tb"), 200),
        ("field h:Bcc", [*minimal(), ("h:Bcc", "x@evil.test")], 400),
        ("field h:Resent-From", [*minimal(), ("h:Resent-From", "x@evil.test")], 400),
        ("field h:content-type lower", [*minimal(), ("h:content-type", "text/html")], 400),
        ("field h:X-Foo final newline (D-19)", [*minimal(), ("h:X-Foo\n", "v")], 400),
        ("field h:Bcc final newline (D-19)", [*minimal(), ("h:Bcc\n", "x@evil.test")], 400),
        ("field h:1bad name", [*minimal(), ("h:1X", "v")], 400),
        ("field h:X-Foo crlf value", [*minimal(), ("h:X-Foo", "a\r\nBcc: x@evil.test")], 400),
        ("field h:X-Foo unicode", [*minimal(), ("h:X-Foo", "Grüße aus Düsseldorf")], 200),
        ("field h:X-Foo case variants", [*minimal(), ("h:X-Foo", "a"), ("h:x-foo", "b")], 200),
        ("field h:X-Foo last wins", [*minimal(), ("h:X-Foo", "a"), ("h:X-Foo", "b")], 200),
        (
            "field h:Reply-To case variants",
            [*minimal(), ("h:Reply-To", "a@x.de"), ("h:reply-to", "b@x.de")],
            400,
        ),
        ("field h:Reply-To malformed", [*minimal(), ("h:Reply-To", "not an address")], 400),
        ("field h:Reply-To IDN", [*minimal(), ("h:Reply-To", "Jörg <j@bücher.example>")], 200),
        (
            "field h:In-Reply-To and References",
            [
                *minimal(),
                ("h:In-Reply-To", "<a.b@example.org>"),
                ("h:References", "<x@example.org> <a.b@example.org>"),
            ],
            200,
        ),
        ("field h:References non-ascii", [*minimal(), ("h:References", "<ä@example.org>")], 400),
        (
            "field h:List-Unsubscribe",
            [*minimal(), ("h:List-Unsubscribe", "<https://x.test/u>")],
            200,
        ),
        ("field no recipients", [(k, v) for k, v in minimal() if k != "to"], 400),
        (
            "field bcc only",
            [(k, v) for k, v in minimal() if k != "to"] + [("bcc", "hidden@example.net")],
            200,
        ),
        (
            "field cc only",
            [(k, v) for k, v in minimal() if k != "to"] + [("cc", "c@example.net")],
            200,
        ),
        ("field to malformed", minimal(to="not-an-email"), 400),
        ("field to two addresses", minimal(to="a@x.de, b@x.de"), 400),
        ("field to quoted comma", minimal(to='"Doe, Jane" <jane@example.org>'), 200),
        ("field to EAI", minimal(to="jörg@example.org"), 400),
        ("field bcc EAI", [*minimal(), ("bcc", "jörg@example.org")], 400),
        ("field to IDN (D-2)", minimal(to="Jörg <joerg@bücher.example>"), 200),
        ("field to IDN punycode", minimal(to="joerg@xn--bcher-kva.example"), 200),
        ("field to special-use", minimal(to="a@printer.local"), 400),
        ("field to comment display name", minimal(to="j@example.de (Kommentar)"), 200),
        ("field to crlf display name (D-16)", minimal(to=crlf_name), 400),
        ("field cc crlf display name (D-16)", [*minimal(), ("cc", crlf_name)], 400),
        ("field to crlf plus invalid cc", [*minimal(to=crlf_name), ("cc", "nope")], 400),
        (
            "field from crlf display name",
            minimal(
                **{"from": crlf_name.replace("a@example.org", "jochen-homepage@wersdoerfer.de")}
            ),
            200,
        ),
        ("field bcc crlf display name", [*minimal(), ("bcc", crlf_name)], 200),
        (
            "field to encoded display name",
            minimal(to="=?utf-8?q?J=C3=B6rg?= <joerg@example.org>"),
            200,
        ),
        ("field to control display name", minimal(to="=?utf-8?q?a=01b?= <a@example.org>"), 200),
        ("field reply-to crlf display name", [*minimal(), ("h:Reply-To", crlf_name)], 400),
        ("field header value 998", [*minimal(), ("h:X-Long", "x" * 998)], 200),
        ("field header value 999", [*minimal(), ("h:X-Long", "x" * 999)], 400),
        ("field subject 998", minimal(subject="s" * 998), 200),
        ("field subject 999", minimal(subject="s" * 999), 400),
        (
            "field text with dots and long lines",
            minimal(text=".\n..\n." + "x" * 2000 + "\n.end"),
            200,
        ),
        ("field text crlf and cr", minimal(text="a\r\nb\rc\n"), 200),
        ("field text control chars", minimal(text="a\x01b\x7fc"), 200),
        ("field text no final newline", minimal(text="ohne Zeilenende"), 200),
        ("field text trailing blank lines", minimal(text="a\n\n\n"), 200),
        # Decision order (PLAN.md 2.3): field rules before the policy, the
        # policy before subject, headers and recipients.
        ("order foreign path before o:tag", None, 400),
        ("order policy before subject", None, 403),
        ("order policy before headers", None, 403),
        ("order subject before headers", None, 400),
        ("order recipients before addresses", None, 400),
        ("order empty text after policy", None, 403),
    ]
    order = {
        "order foreign path before o:tag": post(
            [*minimal(), ("o:tag", "x")], domain="mg.python-podcast.de"
        ),
        "order policy before subject": post(
            minimal(**{"from": "x@evil.test", "subject": "a\r\nb"})
        ),
        "order policy before headers": post(
            [*minimal(**{"from": "x@evil.test"}), ("h:Bcc", "x@y.de")]
        ),
        "order subject before headers": post([*minimal(subject="a\r\nb"), ("h:Bcc", "x@y.de")]),
        "order recipients before addresses": post([(k, v) for k, v in minimal() if k != "to"]),
        "order empty text after policy": post(minimal(**{"from": "x@evil.test", "text": ""})),
    }
    cases = []
    for name, fields, status in plain:
        if fields is None:
            cases.append(Case(name, order[name], status))
            continue
        # Both encodings of the same fields (PLAN.md 2.3 step 3).
        cases.append(Case(name, post(fields), status))
        cases.append(Case(f"{name} [multipart]", post(fields, encoding="multipart"), status))
    # Exotic header input Rust refuses (D-21) and address forms it refuses (D-11).
    cases += [
        Case(
            "field h:Orig-Date (D-21)",
            post([*minimal(), ("h:Orig-Date", "x")]),
            200,
            divergence="D-21",
            rust_status=400,
        ),
        Case(
            "field h:References unterminated (D-21)",
            post([*minimal(), ("h:References", "<a@b")]),
            200,
            divergence="D-21",
            rust_status=400,
        ),
        Case(
            "field subject koi8 encoded word with umlaut (D-21)",
            post(minimal(subject="Grüße =?koi8-r?b?8sXE?=")),
            200,
            divergence="D-21",
            rust_status=400,
        ),
        Case(
            "field to comment inside addr-spec (D-11)",
            post(minimal(to="a(c)@example.org")),
            200,
            divergence="D-11",
            rust_status=400,
        ),
        Case(
            "field to group (D-11)",
            post(minimal(to="grp: a@example.org;")),
            200,
            divergence="D-11",
            rust_status=400,
        ),
    ]
    return cases


def body_cases() -> list[Case]:
    """PLAN.md 2.3 step 3 against real uvicorn: content types, multipart
    framing, charsets (D-9), truncation, chunking (D-20), lengths (D-12)."""
    auth = ("Authorization", basic("homepage-production"))
    content_type, good = multipart(minimal(), boundary="b0und4ry")

    def raw(ct: str | None, body: bytes, **request: Any) -> Request:
        headers: list[tuple[str, str | bytes]] = [auth]
        if ct is not None:
            headers.append(("Content-Type", ct))
        return Request(headers=headers, body=body, **request)

    truncated = good[: good.rindex(b"--b0und4ry--")]
    # A trailing field after the message fields: cut inside it, the
    # completed parts form a valid message (PLAN.md 2.3 step 3).
    trailing = multipart([*minimal(), ("h:X-Trailer", "t" * 30)], boundary="b0und4ry")[1]
    form_ct, form_body = urlencoded(minimal())
    latin = multipart(minimal(text="Gr\xfc\xdfe"), boundary="b0und4ry")[1]
    cases = [
        Case("body no content type", raw(None, form_body), 400),
        Case("body text/plain", raw("text/plain", form_body), 400),
        Case("body json", raw("application/json", b'{"from":"x"}'), 400),
        Case(
            "body urlencoded upper case", raw("APPLICATION/X-WWW-FORM-URLENCODED", form_body), 200
        ),
        Case("body urlencoded with charset", raw(form_ct + "; charset=utf-8", form_body), 200),
        Case(
            "body multipart capitalised type",
            raw("Multipart/Form-Data; boundary=b0und4ry", good),
            400,
        ),
        Case("body multipart no boundary", raw("multipart/form-data", good), 400),
        Case(
            "body multipart long boundary",
            raw("multipart/form-data; boundary=" + "b" * 257, good),
            400,
        ),
        Case(
            "body multipart quoted boundary",
            raw('multipart/form-data; boundary="b0und4ry"', good),
            200,
        ),
        # The text part is never closed, so it is dropped: no body (400).
        Case("body multipart no final boundary", raw(content_type, truncated), 400),
        Case("body multipart cut inside the text", raw(content_type, good[:-40]), 400),
        Case("body multipart cut inside a trailing field", raw(content_type, trailing[:-30]), 200),
        Case(
            "body multipart trailing field without final boundary",
            raw(content_type, trailing[: trailing.rindex(b"--b0und4ry--")]),
            200,
        ),
        Case("body multipart crlf preamble", raw(content_type, b"\r\n\r\n" + good), 200),
        Case("body multipart text preamble", raw(content_type, b"preamble\r\n" + good), 400),
        Case(
            "body multipart lf then text preamble (D-20)",
            raw(content_type, b"\ntext" + good),
            # Python's decision depends on how the body is read (one read: 200).
            frozenset({200, 400}),
            divergence="D-20",
            rust_status=400,
        ),
        Case("body multipart epilogue", raw(content_type, good + b"epilogue"), 200),
        Case(
            "body multipart part without name",
            raw(content_type, good.replace(b'name="subject"', b"x=1")),
            400,
        ),
        Case(
            "body multipart text field as file",
            post(minimal(), files=[("text", "t.txt", "text/plain", b"x")]),
            400,
        ),
        Case(
            "body multipart attachment as field",
            post([*minimal(), ("attachment", "x")], encoding="multipart"),
            400,
        ),
        Case(
            "body multipart charset latin-1",
            raw(
                content_type + "; charset=latin-1", latin.replace("Grüße".encode(), b"Gr\xfc\xdfe")
            ),
            200,
        ),
        Case(
            "body multipart charset utf-8 invalid bytes",
            raw(content_type, latin.replace("Grüße".encode(), b"Gr\xfc\xdfe")),
            200,
        ),
        Case(
            "body multipart charset cp1252 (D-9)",
            raw(content_type + "; charset=cp1252", good),
            200,
            divergence="D-9",
            rust_status=400,
        ),
        Case(
            "body urlencoded raw utf-8 bytes",
            raw(form_ct, form_body.replace(b"Welt", "Wält".encode())),
            200,
        ),
        Case(
            "body urlencoded percent and plus",
            raw(form_ct, form_body + b"&h:X-A=a%2Bb+c%ZZ%C3%A4"),
            200,
        ),
        Case(
            "body chunked urlencoded",
            raw(form_ct, b"", length=None, chunks=[form_body[:10], form_body[10:]]),
            200,
        ),
        Case(
            "body chunked multipart",
            raw(content_type, b"", length=None, chunks=[good[:7], good[7:]]),
            200,
        ),
        Case("body split across writes", raw(content_type, good, split=len(good) // 2), 200),
        # Unparseable lengths: rejected by the HTTP server in both (D-12).
        Case("body content-length not a number (D-12)", raw(form_ct, form_body, length="abc"), 400),
        Case("body content-length negative (D-12)", raw(form_ct, form_body, length="-1"), 400),
        Case(
            "body content-length plus sign (D-12)",
            raw(form_ct, form_body, length=f"+{len(form_body)}"),
            400,
        ),
        Case(
            "body content-length two values (D-12)",
            raw(form_ct, form_body, length=f"{len(form_body)}, {len(form_body)}"),
            400,
        ),
    ]
    return cases


def route_cases() -> list[Case]:
    def req(method: str, path: str) -> Request:
        return Request(method=method, path=path)

    return [
        Case("route GET /health", req("GET", "/health"), 200),
        Case("route HEAD /health", Request(method="HEAD", path="/health"), 405),
        Case("route POST /health", req("POST", "/health"), 405),
        Case("route GET /health/ redirect", req("GET", "/health/"), 307),
        Case("route GET /health/?a=1 redirect", req("GET", "/health/?a=1"), 307),
        Case("route GET /health%0A", req("GET", "/health%0A"), 200),
        Case("route GET /", req("GET", "/"), 404),
        Case("route GET messages", req("GET", "/v3/mg.wersdoerfer.de/messages"), 405),
        Case("route PUT messages", req("PUT", "/v3/mg.wersdoerfer.de/messages"), 405),
        Case("route POST messages/ redirect", req("POST", "/v3/mg.wersdoerfer.de/messages/"), 307),
        Case("route POST messages.mime", req("POST", "/v3/mg.wersdoerfer.de/messages.mime"), 404),
        Case("route POST empty domain", req("POST", "/v3//messages"), 404),
        Case("route POST encoded slash", req("POST", "/v3/mg%2Fx/messages"), 404),
        Case("route POST /v2", req("POST", "/v2/mg.wersdoerfer.de/messages"), 404),
    ]


def limit_cases() -> list[Case]:
    """N and N+1 at every limit (profile ``small``: body 3000 bytes, two
    files of at most 500 bytes, three recipients, values of 40 code points)."""
    s = "small"
    auth = ("Authorization", basic("homepage-production"))
    form_ct, form_body = urlencoded(minimal())

    def case(name: str, request: Request, status: int) -> Case:
        return Case(f"limit {name}", request, status, profile=s)

    def files(n: int, size: int = 10, field: str = "attachment") -> list[Upload]:
        return [(field, f"f{i}.bin", "application/octet-stream", b"x" * size) for i in range(n)]

    many = [("to", f"r{i}@example.com") for i in range(110)]
    big: Upload = ("attachment", "big.bin", "application/octet-stream", b"x" * 501)
    return [
        case("recipients 3", post([*minimal(), ("cc", "c@x.de"), ("bcc", "b@x.de")]), 200),
        case(
            "recipients 4",
            post([*minimal(), ("cc", "c@x.de"), ("bcc", "b@x.de"), ("bcc", "c@x.de")]),
            413,
        ),
        case(
            "recipients duplicates count",
            post([*minimal(), ("to", ADMIN), ("to", ADMIN), ("to", ADMIN)]),
            413,
        ),
        case("attachments 2", post(minimal(), files=files(2)), 200),
        case("attachments 3", post(minimal(), files=files(3)), 413),
        case("inline counts", post(minimal(), files=files(1) + files(2, field="inline")), 413),
        case("attachment 500 bytes", post(minimal(), files=files(1, 500)), 200),
        case("attachment 501 bytes", post(minimal(), files=files(1, 501)), 413),
        case("files over the parser cap", post(minimal(), files=files(4)), 413),
        case("fields over the parser cap", post(minimal() + many, encoding="multipart"), 413),
        case("fields urlencoded many recipients", post(minimal() + many[:20]), 413),
        case("subject 40", post(minimal(subject="ä" * 40)), 200),
        case("subject 41", post(minimal(subject="ä" * 41)), 400),
        case("header value 40", post([*minimal(), ("h:X-A", "x" * 40)]), 200),
        case("header value 41", post([*minimal(), ("h:X-A", "x" * 41)]), 400),
        # Raw latin-1 bytes decode to two UTF-8 bytes each: the decoded texts
        # outgrow the body (PLAN.md 2.3 step 4).
        case(
            "text aggregate over the limit",
            Request(
                headers=[auth, ("Content-Type", form_ct)],
                body=form_body.replace(b"Hallo+Welt", b"\xe4" * 1600),
            ),
            413,
        ),
        case(
            "text aggregate at the limit",
            Request(
                headers=[auth, ("Content-Type", form_ct)],
                body=form_body.replace(b"Hallo+Welt", b"\xe4" * 1400),
            ),
            200,
        ),
        case(
            "declared length over the limit",
            Request(headers=[auth, ("Content-Type", form_ct)], body=b"x" * 3001),
            413,
        ),
        case(
            "declared length over the limit on /health",
            Request(method="GET", path="/health", body=b"x" * 3001),
            413,
        ),
        case("declared length over the limit on 404", Request(path="/nope", body=b"x" * 3001), 413),
        case(
            "declared length at the limit",
            Request(
                headers=[auth, ("Content-Type", form_ct)],
                body=form_body + b"&h:X-P=" + b"p" * (3000 - len(form_body) - 7),
            ),
            400,
        ),
        case(
            "chunked over the limit",
            Request(
                headers=[auth, ("Content-Type", form_ct)],
                length=None,
                chunks=[form_body, b"&text=" + b"t" * 3000],
            ),
            413,
        ),
        case(
            "chunked over the limit bad auth",
            Request(headers=[("Content-Type", form_ct)], length=None, chunks=[b"x" * 4000]),
            401,
        ),
        case(
            "chunked over the limit no content type",
            Request(headers=[auth], length=None, chunks=[b"x" * 4000]),
            400,
        ),
        case("attachment before o:tag is 413", _form([*minimal(), big, ("o:tag", "x")]), 413),
        case("o:tag before attachment is 400", _form([*minimal(), ("o:tag", "x"), big]), 400),
        Case(
            "limit chunked malformed over the limit (D-20)",
            Request(
                headers=[auth, ("Content-Type", "multipart/form-data; boundary=b")],
                length=None,
                chunks=[b"--b\r\nbroken\r\n", b"x" * 4000],
                # The framing error arrives first, alone: Python's 400.
                split=40,
            ),
            frozenset({400, 413}),
            profile=s,
            divergence="D-20",
            rust_status=413,
        ),
    ]


def _form(parts: list[tuple[str, str] | Upload]) -> Request:
    content_type, body = multipart([], parts=parts)
    auth = ("Authorization", basic("homepage-production"))
    return Request(headers=[auth, ("Content-Type", content_type)], body=body)


def smtp_cases() -> list[Case]:
    """Every scenario of ``smtp_outcomes.json`` (Python's ``submit``
    against the same server, PLAN.md 2.4) through the endpoint, with the
    route's records; the recipients are the fixture's."""
    fixture = json.loads((FIXTURES / "smtp_outcomes.json").read_text(encoding="utf-8"))
    cases = []
    for entry in fixture["cases"]:
        python = entry.get("python", entry["expected"])
        fields = [("from", HOMEPAGE_FROM)] + [("to", r) for r in entry["recipients"]]
        fields += [("subject", "SMTP"), ("text", "Ergebnis")]
        cases.append(
            Case(
                f"smtp {entry['name']}",
                post(fields),
                python["status"],
                smtp=entry["scenario"],
                cert=entry["cert"],
                profile="default" if entry["starttls"] else "plain",
                divergence=entry.get("divergence"),
                rust_status=entry["expected"]["status"] if "divergence" in entry else None,
            )
        )
    partial = [
        ("from", HOMEPAGE_FROM),
        ("to", "ok@example.org"),
        ("cc", "gone@Example.org"),
        ("bcc", "grey@example.net"),
        ("subject", "Teil"),
        ("text", "x"),
    ]
    cases += [
        Case(
            "smtp partial refusal records",
            post(partial),
            200,
            smtp={"rcpt": {"gone": 550, "grey": 450}},
        ),
        Case(
            "smtp strict partial refusal",
            post(partial),
            502,
            smtp={"rcpt": {"gone": 550}},
            profile="strict",
        ),
        Case("smtp strict full acceptance", post(partial), 200, profile="strict"),
        Case(
            "smtp strict all refused",
            post(partial),
            503,
            smtp={"rcpt": {"ok": 550, "gone": 550, "grey": 450}},
            profile="strict",
        ),
    ]
    return cases


def request_cases() -> list[Case]:
    return (
        production_cases()
        + policy_cases()
        + auth_cases()
        + field_cases()
        + body_cases()
        + route_cases()
        + limit_cases()
        + smtp_cases()
    )


_PROBE = post(minimal())
STARTUP_CASES = [
    StartupCase("default configuration", {}, _PROBE, "serves 200"),
    StartupCase(
        "CA file missing (D-22)",
        {"MAILGUN_RELAY_SMTP_CA_FILE": "/nonexistent/ca.pem"},
        _PROBE,
        "serves 503",
        rust="exits 1",
        divergence="D-22",
    ),
    StartupCase(
        "CA file missing, STARTTLS off (D-22)",
        {
            "MAILGUN_RELAY_SMTP_CA_FILE": "/nonexistent/ca.pem",
            "MAILGUN_RELAY_SMTP_STARTTLS": "false",
        },
        _PROBE,
        "serves 502",
        rust="exits 1",
        divergence="D-22",
    ),
    StartupCase("log level warn", {"MAILGUN_RELAY_LOG_LEVEL": "warn"}, _PROBE, "exits 1"),
    # uvicorn registers TRACE with logging before the app reads its level.
    StartupCase("log level trace", {"MAILGUN_RELAY_LOG_LEVEL": "trace"}, _PROBE, "serves 200"),
    StartupCase("empty max recipients", {"MAILGUN_RELAY_MAX_RECIPIENTS": ""}, _PROBE, "exits 1"),
    StartupCase(
        "missing secrets",
        {"MAILGUN_RELAY_SECRETS_PATH": "/nonexistent/secrets.yml"},
        _PROBE,
        "exits 1",
    ),
    StartupCase("secrets world-readable", {}, _PROBE, "exits 1", secrets_mode=0o644),
    StartupCase("secrets 0400", {}, _PROBE, "serves 200", secrets_mode=0o400),
]
