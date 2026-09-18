"""
ECDSA Nonce-Reuse Key Recovery Demonstration (secp256k1)
==========================================================
Implements ECDSA signing from scratch over the secp256k1 curve (the curve
used by Bitcoin and Ethereum) and demonstrates the classical nonce-reuse
private-key recovery attack: given two signatures produced with the same
secret nonce k, the long-term private key d can be recovered algebraically.

This is used as the empirical component of the M542 Cryptology report.
"""

import hashlib
import os
import random
import time

# ---- secp256k1 domain parameters (standard, publicly specified) ----
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G  = (Gx, Gy)


def inv_mod(x, m):
    return pow(x, -1, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * inv_mod(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv_mod((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def sha256_int(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N


def keygen():
    d = random.randrange(1, N - 1)
    Q = scalar_mult(d, G)
    return d, Q


def ecdsa_sign_with_nonce(z: int, d: int, k: int):
    R = scalar_mult(k, G)
    r = R[0] % N
    s = (inv_mod(k, N) * (z + r * d)) % N
    return r, s


def recover_key_from_nonce_reuse(r, s1, z1, s2, z2, n=N):
    """Given two signatures (r, s1, z1) and (r, s2, z2) sharing nonce k,
    recover the nonce k and the long-term private key d."""
    s_diff = (s1 - s2) % n
    k = ((z1 - z2) % n) * inv_mod(s_diff, n) % n
    d = ((s1 * k - z1) % n) * inv_mod(r, n) % n
    return k, d


def run_trials(num_trials=20):
    results = []
    for i in range(1, num_trials + 1):
        d_true, Q = keygen()
        k = random.randrange(1, N - 1)  # the (vulnerable) reused nonce

        msg1 = f"transaction-{i}-A-{os.urandom(4).hex()}".encode()
        msg2 = f"transaction-{i}-B-{os.urandom(4).hex()}".encode()
        z1, z2 = sha256_int(msg1), sha256_int(msg2)

        t0 = time.perf_counter()
        r1, s1 = ecdsa_sign_with_nonce(z1, d_true, k)
        r2, s2 = ecdsa_sign_with_nonce(z2, d_true, k)
        assert r1 == r2  # same nonce -> same r, the detectable signal

        k_rec, d_rec = recover_key_from_nonce_reuse(r1, s1, z1, s2, z2)
        t1 = time.perf_counter()

        correct = (d_rec == d_true) and (k_rec == k)
        results.append({
            "trial": i,
            "correct": correct,
            "time_ms": (t1 - t0) * 1000,
        })
    return results


if __name__ == "__main__":
    random.seed(42)  # reproducibility for the report
    results = run_trials(20)

    successes = sum(1 for r in results if r["correct"])
    times = [r["time_ms"] for r in results]
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)

    print(f"{'Trial':<7}{'Key Recovered':<16}{'Time (ms)':<12}")
    for r in results:
        print(f"{r['trial']:<7}{'Yes' if r['correct'] else 'No':<16}{r['time_ms']:<12.3f}")

    print()
    print(f"Success rate: {successes}/{len(results)} ({100*successes/len(results):.1f}%)")
    print(f"Average recovery time: {avg_time:.3f} ms")
    print(f"Min / Max recovery time: {min_time:.3f} ms / {max_time:.3f} ms")

    # Save for report table generation
    import json
    with open("/home/claude/crypto/results.json", "w") as f:
        json.dump({
            "results": results,
            "successes": successes,
            "total": len(results),
            "avg_time_ms": avg_time,
            "min_time_ms": min_time,
            "max_time_ms": max_time,
        }, f, indent=2)
