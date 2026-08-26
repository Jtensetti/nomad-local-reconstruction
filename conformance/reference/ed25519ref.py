"""Ed25519 verification, from RFC 8032, for the conformance tools only.

This exists because the container these tools run in has `cryptography`
installed but unusable: its pyo3 extension panics rather than raising, so the
sibling modules fall back to not checking signatures at all. For a topology
document that is tolerable, because the interoperability that matters there is
reproducing canonical bytes. For a log checkpoint it is not: the signature is
the property. A conformance tool that reported a pass while silently skipping
the only check that mattered would be worse than one that failed.

So this is the fallback, and its limits are stated rather than implied:

  - It is the RFC 8032 reference algorithm, transcribed from the specification.
    It is independent of the Go implementation, which is the independence a
    second implementation is for.
  - It is NOT production code and nothing outside conformance/ may import it.
    It is straightforward big-integer arithmetic with no side-channel defences.
    That is acceptable here and only here: verification touches a public key, a
    public message and a public signature, so there is no secret for a timing
    difference to leak. It must never be used for signing, which does touch a
    secret.
  - It is slow. Verifying a checkpoint takes milliseconds rather than
    microseconds, which does not matter for a corpus of them.

Where `cryptography` works, it is preferred: a reviewed library is the better
check. This runs when it does not.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493


def _modp_inv(value: int) -> int:
    return pow(value, _P - 2, _P)


_D = -121665 * _modp_inv(121666) % _P
_SQRT_MINUS_ONE = pow(2, (_P - 1) // 4, _P)


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


def _point_add(left: tuple, right: tuple) -> tuple:
    a = (left[1] - left[0]) * (right[1] - right[0]) % _P
    b = (left[1] + left[0]) * (right[1] + right[0]) % _P
    c = 2 * left[3] * right[3] * _D % _P
    d = 2 * left[2] * right[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(scalar: int, point: tuple) -> tuple:
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_equal(left: tuple, right: tuple) -> bool:
    if (left[0] * right[2] - right[0] * left[2]) % _P != 0:
        return False
    return (left[1] * right[2] - right[1] * left[2]) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    square = (y * y - 1) * _modp_inv(_D * y * y + 1) % _P
    if square == 0:
        return None if sign else 0
    x = pow(square, (_P + 3) // 8, _P)
    if (x * x - square) % _P != 0:
        x = x * _SQRT_MINUS_ONE % _P
    if (x * x - square) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * _modp_inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _decompress(encoded: bytes) -> tuple | None:
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True if signature is a valid Ed25519 signature over message."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point = _decompress(public_key)
    if point is None:
        return False
    commitment_bytes = signature[:32]
    commitment = _decompress(commitment_bytes)
    if commitment is None:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    # A scalar at or above the group order is refused rather than reduced.
    # Accepting it would make signatures malleable: the same signature would
    # have several encodings, and two verifiers could disagree about identity.
    if scalar >= _Q:
        return False
    challenge = _sha512_modq(commitment_bytes + public_key + message)
    return _point_equal(_point_mul(scalar, _G),
                        _point_add(commitment, _point_mul(challenge, point)))
