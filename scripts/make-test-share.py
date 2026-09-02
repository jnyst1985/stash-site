#!/usr/bin/env python3
"""Seal a test share and upload it, so the viewer can be opened for real.

This is the python stand-in for the iPhone: it mirrors StashKit's
`ShareCodec.compressedWire` + `ShortShareCodec.seal` byte for byte, then POSTs the
envelope to the shares API. Authority for every value here is link-saver
`docs/superpowers/specs/2026-08-24-stash-short-share-links-design.md` §1 - if this
script and the Swift codec ever disagree, the spec settles it and BOTH are wrong
until they agree again.

    payload -> short-key JSON -> raw DEFLATE -> AES-128-GCM -> 0x01 || nonce || ct+tag

Dev only, never deployed (`.assetsignore` keeps `scripts/` off getstash.link).

    python3 scripts/make-test-share.py --base-url http://localhost:8787

Needs `cryptography` for AES-GCM, which the standard library does not provide.
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
import zlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit(
        "make-test-share.py needs the `cryptography` package for AES-128-GCM.\n"
        "  pip install cryptography\n"
        "(or run it with an interpreter that already has it)"
    )

SHARE_CONTENT_TYPE = "application/vnd.stash-share.v1"
ENVELOPE_MAX = 65536

# Two different version numbers that are both 1 today, kept apart on purpose -
# exactly as Swift keeps `ShareCodec.version` and `ShortShareCodec.version` apart.
# The wire one says how to read the JSON, the envelope one how to open the seal;
# bumping either must not silently move the other.
WIRE_VERSION = 1
ENVELOPE_VERSION = 1

# The wire rows the app would send: title, url, host, and an optional summary.
# People-shares carry no notes and no tags - that exclusion is the sharing spec's,
# and it is not this script's to relax.
SAMPLE_LINKS = [
    {
        "t": "The Cost of a Cache Miss",
        "u": "https://example.com/posts/cache-miss",
        "h": "example.com",
        "s": "Why the second lookup is the expensive one.",
    },
    {
        "t": "Notes on eventual consistency",
        "u": "https://blog.example.org/eventual-consistency",
        "h": "blog.example.org",
    },
    {
        "t": "A field guide to URL fragments",
        "u": "https://developer.example.net/fragments",
        "h": "developer.example.net",
        "s": "The half of a URL that never reaches a server.",
    },
]


def base64url(raw: bytes) -> str:
    """Unpadded base64url - the alphabet both the id and the key are written in."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def compressed_wire(name: str, links: list) -> bytes:
    """Short-key JSON -> raw DEFLATE, matching `ShareCodec.encodeJSON` exactly.

    Sorted keys and unescaped slashes are what Swift's JSONEncoder emits with
    `.sortedKeys, .withoutEscapingSlashes`; a nil summary is omitted, never
    written as `"s": null`.
    """
    wire = {"l": links, "n": name, "v": WIRE_VERSION}
    raw = json.dumps(wire, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(raw.encode("utf-8")) + compressor.flush()


def seal(plaintext: bytes) -> tuple:
    """-> (id, key, envelope). Both 16-byte values come from the system CSPRNG."""
    share_id = base64url(os.urandom(16))
    key = os.urandom(16)
    nonce = os.urandom(12)

    # Spec §1: the AAD is the version byte followed by the ascii id, which binds
    # this envelope to this slot - a blob copied to another id will not open.
    aad = bytes([ENVELOPE_VERSION]) + share_id.encode("ascii")
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)

    envelope = bytes([ENVELOPE_VERSION]) + nonce + sealed
    if len(envelope) > ENVELOPE_MAX:
        sys.exit(f"envelope is {len(envelope)} bytes, over the {ENVELOPE_MAX} cap")
    return share_id, base64url(key), envelope


def upload(base_url: str, share_id: str, envelope: bytes) -> str:
    """POST the envelope, -> the deletion token. Any non-201 is fatal and printed."""
    request = urllib.request.Request(
        f"{base_url}/api/share",
        data=envelope,
        method="POST",
        headers={"Content-Type": SHARE_CONTENT_TYPE, "X-Stash-Share-Id": share_id},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", "replace").strip()
        sys.exit(f"POST /api/share -> {err.code} {detail}")
    except urllib.error.URLError as err:
        sys.exit(f"POST /api/share failed: {err.reason}\nis `wrangler dev` up at {base_url}?")

    token = body.get("deletionToken")
    if not token:
        sys.exit(f"POST /api/share returned no deletionToken: {body}")
    return token


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--base-url",
        default="http://localhost:8787",
        help="origin serving the worker (default: the `wrangler dev` port)",
    )
    parser.add_argument("--name", default="Weekend reading", help="share name")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    share_id, key, envelope = seal(compressed_wire(args.name, SAMPLE_LINKS))
    token = upload(base_url, share_id, envelope)

    print(f"id      {share_id}")
    print(f"key     {key}")
    print(f"bytes   {len(envelope)}")
    print(f"token   {token}")
    print(f"url     {base_url}/s/{share_id}#{key}")
    print(f"delete  curl -i -X DELETE -H 'X-Stash-Delete-Token: {token}' "
          f"{base_url}/api/share/{share_id}")


if __name__ == "__main__":
    main()
