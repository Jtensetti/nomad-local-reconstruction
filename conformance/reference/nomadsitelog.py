#!/usr/bin/env python3
"""A second implementation of the site descriptor log, sharing no Go code.

PROD-03 asks that the public wire objects have a consumer that is not the
encoder that produced them. The descriptor log adds three: the log entry, the
signed checkpoint, and the two proof shapes. All three are read by verifiers who
are not the log, which is the whole point of publishing them, so an
implementation that only the log's own code can parse would be a log nobody can
check.

This file was written from docs/SITE_IDENTITY.md and RFC 6962, not from the Go
source. Where the two disagree the specification wins and the disagreement is a
finding.

The tree hashing is RFC 6962's, and the two details that matter are the ones
easiest to get wrong:

  - The prefixes. A leaf is H(0x00 || entry) and a node is H(0x01 || l || r).
    Without them the concatenation of two leaf hashes hashes to the same value
    as the node above them, and a two-entry log's root verifies as a one-entry
    log containing an entry nobody ever wrote.
  - The split. At size n it is the largest power of two strictly *below* n, not
    the midpoint. The midpoint produces a perfectly self-consistent tree that no
    other implementation agrees with, which is the failure mode a second
    implementation exists to catch.

Proof paths are ordered leaf to root. The splits, though, are only knowable from
the head down, so verification descends first to learn which side each level
falls on and then applies the path in the opposite order. Consuming the path
top-down instead is wrong in a way that still passes any example whose sides
happen to read the same forwards and backwards.

The signature check uses `cryptography` where it is importable, because a
reviewed library is the better check. Where it is not -- and in the container
these tools run in it is present but its extension panics -- it falls back to
the RFC 8032 reference algorithm in ed25519ref.py rather than skipping the
check. The sibling topology tool does skip it, and for canonical-encoding
conformance that is defensible. Here it is not: a checkpoint's signature is the
property being tested, and a tool that printed a pass while silently checking
nothing would be worse than one that failed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any

CHECKPOINT_VERSION = "nomad-site-log-checkpoint-v1"
CHECKPOINT_DOMAIN = b"nomad-site-log-checkpoint-signature-v1"
LOG_ENTRY_DOMAIN = b"nomad-site-log-entry-v1"

CHECKPOINT_MEMBERS = ("version", "origin", "size", "root", "time", "signature")

MAX_CHECKPOINT_BYTES = 4096
MAX_ORIGIN_BYTES = 255
MAX_CLOCK_SKEW_SECONDS = 300

try:  # pragma: no cover - presence depends on the environment
    import contextlib
    import io

    with contextlib.redirect_stderr(io.StringIO()):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    SIGNATURES_CHECKABLE = True
    SIGNATURE_BACKEND = "cryptography"
except BaseException:  # noqa: BLE001  # pragma: no cover
    # A broken install is caught as well as a missing one: the container these
    # tools run in has `cryptography` present but unusable, and its pyo3
    # extension raises a PanicException, which derives from BaseException and
    # so escapes the narrower clause.
    #
    # Unlike the topology tool, this one does not carry on unchecked. A
    # checkpoint's signature is the property; reporting a pass while skipping it
    # would be worse than failing. ed25519ref is the RFC 8032 reference
    # algorithm, for conformance only -- see its module docstring for why that
    # is acceptable here and nowhere else.
    import ed25519ref

    SIGNATURES_CHECKABLE = True
    SIGNATURE_BACKEND = "rfc8032-reference"


class LogError(Exception):
    """Something this implementation refuses.

    `tag` is a stable machine-readable reason, not prose. Two implementations
    write their refusals in their own words, so comparing messages across them
    tests translation rather than agreement; comparing tags tests that both
    refused the document for the same reason, which is the thing worth
    checking. A refusal with no tag is a structural one.
    """

    def __init__(self, message: str, tag: str = "structure"):
        super().__init__(message)
        self.tag = tag


def hash_leaf(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def split_below(size: int) -> int:
    """RFC 6962's k: the largest power of two strictly less than size."""
    if size < 2:
        return 1
    return 1 << (size - 1).bit_length() - 1


def root_of(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = split_below(len(leaves))
    return hash_node(root_of(leaves[:split]), root_of(leaves[split:]))


def log_entry(encoded_descriptor: bytes) -> bytes:
    """The exact byte string a descriptor occupies in the log."""
    return LOG_ENTRY_DOMAIN + len(encoded_descriptor).to_bytes(8, "big") + encoded_descriptor


def _descend(index: int, size: int) -> list[bool]:
    """Which side the entry falls on at each level, head first."""
    sides: list[bool] = []
    while size > 1:
        split = split_below(size)
        if index < split:
            sides.append(False)
            size = split
            continue
        sides.append(True)
        index -= split
        size -= split
    return sides


def verify_inclusion(index: int, size: int, path: list[bytes], entry: bytes, root: bytes) -> None:
    if size == 0:
        raise LogError("an inclusion proof against an empty tree proves nothing")
    if index >= size:
        raise LogError(f"entry {index} is not in a tree of {size}")
    sides = _descend(index, size)
    if len(path) != len(sides):
        raise LogError(f"inclusion path has {len(path)} hashes; entry {index} of {size} "
                       f"needs {len(sides)}")
    computed = hash_leaf(entry)
    for step, sibling in enumerate(path):
        if sides[len(sides) - 1 - step]:
            computed = hash_node(sibling, computed)
        else:
            computed = hash_node(computed, sibling)
    if computed != root:
        raise LogError("inclusion proof does not reach the checkpoint root")


def _descend_consistency(old: int, size: int) -> list[bool]:
    sides: list[bool] = []
    while old != size:
        split = split_below(size)
        if old <= split:
            sides.append(False)
            size = split
            continue
        sides.append(True)
        old -= split
        size -= split
    return sides


def verify_consistency(old: int, new: int, path: list[bytes],
                       old_root: bytes, new_root: bytes) -> None:
    if old > new:
        raise LogError(f"a log cannot shrink from {old} to {new}")
    if old == 0:
        if path:
            raise LogError("a proof from an empty log carries no path")
        if old_root != hashlib.sha256(b"").digest():
            raise LogError("a proof claiming an empty earlier log was offered against a "
                           "non-empty head")
        return
    if old == new:
        if path:
            raise LogError("a proof between equal sizes carries no path")
        if old_root != new_root:
            raise LogError("the log reports two roots at one size")
        return

    sides = _descend_consistency(old, new)
    seeded = old & (old - 1) != 0
    expected = len(sides) + (1 if seeded else 0)
    if len(path) != expected:
        raise LogError(f"consistency path has {len(path)} hashes; {old} to {new} "
                       f"needs {expected}")
    if seeded:
        left = right = path[0]
        rest = path[1:]
    else:
        left = right = old_root
        rest = path
    for step, sibling in enumerate(rest):
        if sides[len(sides) - 1 - step]:
            left = hash_node(sibling, left)
            right = hash_node(sibling, right)
        else:
            right = hash_node(right, sibling)
    if left != old_root:
        raise LogError("the log's earlier head is not a prefix of its current one, so it "
                       "rewrote history rather than appending")
    if right != new_root:
        raise LogError("the log's current head is not an extension of the head this reader "
                       "holds: either it rewrote history rather than appending, or the "
                       "proof was corrupted")


def _canonical_hex(value: Any, size: int, what: str, tag: str) -> bytes:
    if not isinstance(value, str):
        raise LogError(f"{what} is not a string", tag)
    try:
        raw = binascii.unhexlify(value)
    except (binascii.Error, ValueError) as error:
        raise LogError(f"{what} is not hex: {error}", tag) from error
    if len(raw) != size or raw.hex() != value:
        raise LogError(f"{what} is not {size} bytes of canonical lower-case hex", tag)
    return raw


def _canonical_base64(value: Any, size: int, what: str, tag: str) -> bytes:
    if not isinstance(value, str):
        raise LogError(f"{what} is not a string", tag)
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise LogError(f"{what} is not base64: {error}", tag) from error
    if len(raw) != size:
        raise LogError(f"{what} is {len(raw)} bytes, not {size}", tag)
    if base64.b64encode(raw).decode() != value:
        raise LogError(f"{what} is not in canonical base64 form", tag)
    return raw


def _canonical_time(value: Any) -> str:
    """RFC3339 in UTC, seconds resolution, 'Z' rather than an offset.

    Written out rather than delegated to datetime.fromisoformat, which accepts
    spellings this format does not -- offsets, fractional seconds, and in some
    versions a lowercase 't'. A second implementation that accepted more than
    the specification would hide exactly the disagreements it exists to find.
    """
    if not isinstance(value, str) or len(value) != 20 or value[10] != "T" or value[19] != "Z":
        raise LogError(f"time {value!r} is not canonical UTC RFC3339", "time")
    for position in (4, 7):
        if value[position] != "-":
            raise LogError(f"time {value!r} is not canonical UTC RFC3339", "time")
    for position in (13, 16):
        if value[position] != ":":
            raise LogError(f"time {value!r} is not canonical UTC RFC3339", "time")
    digits = value[:4] + value[5:7] + value[8:10] + value[11:13] + value[14:16] + value[17:19]
    if not digits.isdigit() or not digits.isascii():
        raise LogError(f"time {value!r} is not canonical UTC RFC3339", "time")
    year, month, day = int(value[:4]), int(value[5:7]), int(value[8:10])
    hour, minute, second = int(value[11:13]), int(value[14:16]), int(value[17:19])
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 61):
        raise LogError(f"time {value!r} is not a real instant", "time")
    if year < 1:
        raise LogError(f"time {value!r} is not a real instant", "time")
    return value


def checkpoint_signing_message(origin: str, size: int, root: bytes, when: str) -> bytes:
    """Every variable-length field length-prefixed, so no two checkpoints can
    produce one message by moving a boundary."""
    origin_bytes = origin.encode()
    when_bytes = when.encode()
    return (len(CHECKPOINT_DOMAIN).to_bytes(8, "big") + CHECKPOINT_DOMAIN
            + len(origin_bytes).to_bytes(8, "big") + origin_bytes
            + size.to_bytes(8, "big") + root
            + len(when_bytes).to_bytes(8, "big") + when_bytes)


def parse_checkpoint(raw: bytes) -> dict:
    """Parse a published checkpoint, refusing everything the format does not allow."""
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise LogError(f"checkpoint is {len(raw)} bytes, over the {MAX_CHECKPOINT_BYTES} limit",
                       "size")
    text = raw.decode("utf-8", errors="strict")
    seen: list[str] = []

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict:
        for name, _ in pairs:
            if name in seen:
                raise LogError(f"duplicate member {name!r}", "duplicate")
            seen.append(name)
        return dict(pairs)

    try:
        document = json.loads(text, object_pairs_hook=object_pairs)
    except json.JSONDecodeError as error:
        raise LogError(f"not JSON: {error}") from error
    if not isinstance(document, dict):
        raise LogError("a checkpoint is a JSON object")
    unknown = set(document) - set(CHECKPOINT_MEMBERS)
    if unknown:
        raise LogError(f"unknown members: {sorted(unknown)}", "unknown")
    missing = set(CHECKPOINT_MEMBERS) - set(document)
    if missing:
        raise LogError(f"missing members: {sorted(missing)}", "unknown")
    if document["version"] != CHECKPOINT_VERSION:
        raise LogError(f"unrecognised checkpoint version {document['version']!r}, which is "
                       "refused rather than interpreted", "version")
    origin = document["origin"]
    if not isinstance(origin, str) or not origin:
        raise LogError("a checkpoint with no origin could be replayed as another log's", "origin")
    if len(origin.encode()) > MAX_ORIGIN_BYTES:
        raise LogError(f"origin is over the {MAX_ORIGIN_BYTES}-byte limit", "origin")
    size = document["size"]
    # bool is an int in Python and JSON true would otherwise parse as size 1.
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise LogError("size is not a non-negative integer", "size")
    return {
        "version": document["version"],
        "origin": origin,
        "size": size,
        "root": _canonical_hex(document["root"], 32, "checkpoint root", "root"),
        "time": _canonical_time(document["time"]),
        "signature": _canonical_base64(document["signature"], 64, "checkpoint signature",
                                       "signature"),
    }


def verify_checkpoint(raw: bytes, expected_origin: str, log_key: bytes) -> dict:
    """Check a published checkpoint against the log's key.

    expected_origin is supplied by the caller, never read from the document: a
    checkpoint that named its own log would authenticate nothing.
    """
    if not expected_origin:
        raise LogError("no expected origin was named, so any log's checkpoint would pass")
    if len(log_key) != 32:
        raise LogError("log key is not an Ed25519 public key")
    checkpoint = parse_checkpoint(raw)
    if checkpoint["origin"] != expected_origin:
        raise LogError(f"checkpoint is from log {checkpoint['origin']!r}, "
                       f"not {expected_origin!r}", "origin")
    message = checkpoint_signing_message(checkpoint["origin"], checkpoint["size"],
                                         checkpoint["root"], checkpoint["time"])
    if SIGNATURE_BACKEND == "cryptography":
        try:
            Ed25519PublicKey.from_public_bytes(log_key).verify(checkpoint["signature"], message)
        except InvalidSignature as error:
            raise LogError("checkpoint signature does not verify against the log's key",
                           "signature") from error
    elif not ed25519ref.verify(log_key, message, checkpoint["signature"]):
        raise LogError("checkpoint signature does not verify against the log's key", "signature")
    checkpoint["signing_message"] = message
    checkpoint["signature_backend"] = SIGNATURE_BACKEND
    return checkpoint
