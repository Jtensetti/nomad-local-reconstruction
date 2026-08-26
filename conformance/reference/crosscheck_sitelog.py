#!/usr/bin/env python3
"""Run the published log corpus against the second implementation, both ways.

PROD-03 asks that the public wire objects have a consumer that is not the
encoder that produced them. Reading one direction is not enough: an
implementation that only *reads* the other's output can be wrong in any way that
happens to be permissive, and one that only writes can be wrong in any way the
reader tolerates. So this does both, and then the direction that decides whether
either means anything.

Direction A -- the second implementation reproduces what Go published: log
entries, leaf hashes, RFC 6962 reference roots, checkpoint signing preimages,
and checkpoint signatures, byte for byte.

Direction B -- the second implementation checks every proof in the corpus,
which requires reproducing every intermediate hash rather than a summary.

Direction C -- the refusals. Two implementations that both accept everything
also agree. Each document the corpus publishes as refused must be refused here
too, and the reason is checked, not only the refusal: nearly every malformed
checkpoint also fails a *later* check, so a tool that asked "did this raise"
would pass with the check under test deleted.

Direction D -- the second implementation emits proofs Go has never seen, to a
file a Go test then verifies.

Usage:
    crosscheck_sitelog.py <corpus.json> [--emit <path for direction D>]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import nomadsitelog  # noqa: E402


class Failure(Exception):
    pass


def unhex(value: str) -> bytes:
    return binascii.unhexlify(value)


def check_reference(corpus: dict) -> int:
    """RFC 6962's own vectors. If these disagree, nothing else matters."""
    leaves = [nomadsitelog.hash_leaf(unhex(v)) for v in corpus["rfc6962_reference_leaves_hex"]]
    roots = corpus["rfc6962_reference_roots_hex"]
    if len(roots) != len(leaves) + 1:
        raise Failure(f"corpus publishes {len(roots)} roots for {len(leaves)} leaves")
    for size, want in enumerate(roots):
        got = nomadsitelog.root_of(leaves[:size]).hex()
        if got != want:
            raise Failure(f"RFC 6962 root at size {size}: {got} != {want}")
    return len(roots)


def check_entries(corpus: dict) -> int:
    for entry in corpus["entries"]:
        built = nomadsitelog.log_entry(unhex(entry["payload_hex"]))
        if built.hex() != entry["log_entry_hex"]:
            raise Failure(f"{entry['name']}: log entry {built.hex()} != {entry['log_entry_hex']}")
        leaf = nomadsitelog.hash_leaf(built).hex()
        if leaf != entry["leaf_hash_hex"]:
            raise Failure(f"{entry['name']}: leaf hash {leaf} != {entry['leaf_hash_hex']}")
    return len(corpus["entries"])


def check_checkpoints(corpus: dict) -> int:
    origin = corpus["origin"]
    log_key = unhex(corpus["log_public_key_hex"])
    for item in corpus["checkpoints"]:
        document = base64.b64decode(item["document_json_base64"], validate=True)
        checkpoint = nomadsitelog.verify_checkpoint(document, origin, log_key)
        if checkpoint["size"] != item["size"]:
            raise Failure(f"checkpoint claims size {item['size']}, carries {checkpoint['size']}")
        if checkpoint["root"].hex() != item["root_hex"]:
            raise Failure(f"checkpoint at size {item['size']} carries a root the corpus "
                          f"disagrees with")
        if checkpoint["signing_message"].hex() != item["signing_message_hex"]:
            raise Failure(f"checkpoint at size {item['size']}: the reconstructed signing "
                          f"preimage is not the published one")
    return len(corpus["checkpoints"])


def check_proofs(corpus: dict) -> tuple[int, int]:
    for item in corpus["inclusion_proofs"]:
        nomadsitelog.verify_inclusion(
            item["index"], item["size"], [unhex(h) for h in item["path_hex"]],
            unhex(item["entry_hex"]), unhex(item["root_hex"]))
    for item in corpus["consistency_proofs"]:
        nomadsitelog.verify_consistency(
            item["old"], item["new"], [unhex(h) for h in item["path_hex"]],
            unhex(item["old_root_hex"]), unhex(item["new_root_hex"]))
    return len(corpus["inclusion_proofs"]), len(corpus["consistency_proofs"])


def check_refusals(corpus: dict) -> int:
    """Every published refusal must be refused here, for its published reason.

    The reason is checked because a malformed checkpoint usually fails several
    ways at once: an edited root also breaks the signature, a malformed time
    also breaks the signature. A tool that only asked whether something was
    raised would agree with an implementation that had no root check at all.

    What is compared is the corpus's machine tag against this implementation's
    own tag, not the wording. Two implementations write their refusals in their
    own words -- and in a second language they would not even be English -- so
    matching prose would test translation rather than agreement.
    """
    origin = corpus["origin"]
    log_key = unhex(corpus["log_public_key_hex"])
    for refusal in corpus["refusals"]:
        document = base64.b64decode(refusal["document_json_base64"], validate=True)
        try:
            nomadsitelog.verify_checkpoint(document, origin, log_key)
        except nomadsitelog.LogError as error:
            because = refusal["because"]
            if error.tag != because:
                raise Failure(
                    f"{refusal['name']!r} was refused as {error.tag!r} rather than "
                    f"{because!r} ({error}); a refusal that comes from a later check "
                    f"leaves the one under test untested") from error
            continue
        raise Failure(f"{refusal['name']!r} was accepted; the corpus publishes it as refused "
                      f"because of its {refusal['because']}")
    return len(corpus["refusals"])


def check_negative_controls(corpus: dict) -> int:
    """Proofs this implementation must refuse, built here rather than published.

    The corpus cannot carry these without an encoder willing to emit a broken
    proof, and an encoder that could would be a defect of its own. They are
    derived from valid corpus entries so that only the named thing is wrong.
    """
    checked = 0
    inclusion = [p for p in corpus["inclusion_proofs"] if p["size"] >= 4 and p["path_hex"]]
    if not inclusion:
        raise Failure("the corpus carries no inclusion proof big enough to corrupt")
    item = inclusion[0]
    path = [unhex(h) for h in item["path_hex"]]
    entry, root = unhex(item["entry_hex"]), unhex(item["root_hex"])

    tampered = list(path)
    tampered[0] = bytes([tampered[0][0] ^ 1]) + tampered[0][1:]
    cases = {
        "a tampered sibling": (item["index"], item["size"], tampered, entry, root),
        "a truncated path": (item["index"], item["size"], path[:-1], entry, root),
        "an over-long path": (item["index"], item["size"], path + [b"\x00" * 32], entry, root),
        "another entry": (item["index"], item["size"], path, entry + b"!", root),
        "an index outside the tree": (item["size"], item["size"], path, entry, root),
    }
    for name, arguments in cases.items():
        try:
            nomadsitelog.verify_inclusion(*arguments)
        except nomadsitelog.LogError:
            checked += 1
            continue
        raise Failure(f"an inclusion proof with {name} was accepted")

    # The leaf/node domain separation, which is what stops an interior node
    # being presented as a logged entry.
    two = [nomadsitelog.hash_leaf(b"first"), nomadsitelog.hash_leaf(b"second")]
    forged = two[0] + two[1]
    if hashlib.sha256(forged).digest() == nomadsitelog.root_of(two):
        raise Failure("the node hash is unprefixed; a forged leaf would be accepted")
    try:
        nomadsitelog.verify_inclusion(0, 1, [], forged, nomadsitelog.root_of(two))
    except nomadsitelog.LogError:
        checked += 1
    else:
        raise Failure("the concatenation of two leaf hashes verified as one logged entry")

    # A log that rewrote history: take a real consistency proof and offer it
    # against an earlier head it does not extend.
    consistency = [p for p in corpus["consistency_proofs"]
                   if p["old"] >= 1 and p["new"] > p["old"]]
    if not consistency:
        raise Failure("the corpus carries no consistency proof to corrupt")
    proof = consistency[-1]
    wrong_old = unhex(corpus["consistency_proofs"][0]["new_root_hex"])
    if wrong_old != unhex(proof["old_root_hex"]):
        try:
            nomadsitelog.verify_consistency(
                proof["old"], proof["new"], [unhex(h) for h in proof["path_hex"]],
                wrong_old, unhex(proof["new_root_hex"]))
        except nomadsitelog.LogError:
            checked += 1
        else:
            raise Failure("a consistency proof verified against a head it does not extend")

    # A proof claiming the reader held nothing must not act as a wildcard.
    try:
        nomadsitelog.verify_consistency(0, proof["new"], [], unhex(proof["old_root_hex"]),
                                        unhex(proof["new_root_hex"]))
    except nomadsitelog.LogError:
        checked += 1
    else:
        raise Failure("a proof claiming an empty earlier log was accepted against a real head")

    # A hostile size must return rather than spin.
    for size in (1 << 32, 1 << 62, (1 << 64) - 1):
        try:
            nomadsitelog.verify_inclusion(0, size, [], entry, root)
        except nomadsitelog.LogError:
            checked += 1
        else:
            raise Failure(f"an inclusion proof claiming a tree of {size} was accepted")
    return checked


def emit(corpus: dict, destination: pathlib.Path) -> int:
    """Direction D: proofs the Go implementation has never seen.

    The tree is built here, from entries this file chooses, with this file's own
    hashing. If Go verifies these, the agreement is not an artefact of Go having
    produced both sides.
    """
    entries = [nomadsitelog.log_entry(f"an entry the Go side never wrote: {index}".encode())
               for index in range(11)]
    leaves = [nomadsitelog.hash_leaf(entry) for entry in entries]

    def inclusion_path(subset: list[bytes], index: int) -> list[bytes]:
        if len(subset) <= 1:
            return []
        split = nomadsitelog.split_below(len(subset))
        if index < split:
            return inclusion_path(subset[:split], index) + [nomadsitelog.root_of(subset[split:])]
        return inclusion_path(subset[split:], index - split) + [nomadsitelog.root_of(subset[:split])]

    def consistency_path(subset: list[bytes], old: int, whole: bool) -> list[bytes]:
        if old == len(subset):
            return [] if whole else [nomadsitelog.root_of(subset)]
        split = nomadsitelog.split_below(len(subset))
        if old <= split:
            return consistency_path(subset[:split], old, whole) + [
                nomadsitelog.root_of(subset[split:])]
        return consistency_path(subset[split:], old - split, False) + [
            nomadsitelog.root_of(subset[:split])]

    document = {
        "version": "nomad-site-log-crosscheck-v1",
        "entries_hex": [entry.hex() for entry in entries],
        "inclusion_proofs": [],
        "consistency_proofs": [],
    }
    for size in range(1, len(entries) + 1):
        root = nomadsitelog.root_of(leaves[:size])
        for index in range(size):
            document["inclusion_proofs"].append({
                "index": index, "size": size,
                "path_hex": [h.hex() for h in inclusion_path(leaves[:size], index)],
                "root_hex": root.hex(),
            })
        for old in range(0, size + 1):
            hashes = [] if old == 0 else consistency_path(leaves[:size], old, True)
            document["consistency_proofs"].append({
                "old": old, "new": size,
                "path_hex": [h.hex() for h in hashes],
                "old_root_hex": nomadsitelog.root_of(leaves[:old]).hex(),
                "new_root_hex": root.hex(),
            })
    destination.write_text(json.dumps(document, indent=2) + "\n")
    return len(document["inclusion_proofs"]) + len(document["consistency_proofs"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus")
    parser.add_argument("--emit")
    arguments = parser.parse_args()

    corpus = json.loads(pathlib.Path(arguments.corpus).read_text())
    if corpus.get("version") != "nomad-site-log-corpus-v1":
        print(f"unrecognised corpus version {corpus.get('version')!r}", file=sys.stderr)
        return 1

    try:
        roots = check_reference(corpus)
        entries = check_entries(corpus)
        checkpoints = check_checkpoints(corpus)
        inclusion, consistency = check_proofs(corpus)
        refusals = check_refusals(corpus)
        controls = check_negative_controls(corpus)
    except (Failure, nomadsitelog.LogError) as error:
        print(f"DISAGREEMENT: {error}", file=sys.stderr)
        return 1

    emitted = 0
    if arguments.emit:
        emitted = emit(corpus, pathlib.Path(arguments.emit))

    print(f"signature backend: {nomadsitelog.SIGNATURE_BACKEND}")
    print(f"A: {roots} RFC 6962 roots, {entries} log entries, "
          f"{checkpoints} checkpoint signatures reproduced")
    print(f"B: {inclusion} inclusion and {consistency} consistency proofs verified")
    print(f"C: {refusals} published refusals refused for their published reason, "
          f"{controls} negative controls refused")
    if emitted:
        print(f"D: {emitted} proofs emitted for the Go side to verify")
    print("AGREED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
