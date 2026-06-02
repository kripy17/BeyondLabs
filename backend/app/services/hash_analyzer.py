import hashlib
import re


HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


HASH_TYPES = {
    32: "MD5",
    40: "SHA1",
    64: "SHA256",
    128: "SHA512",
}


def identify_hash(value: str) -> dict:
    cleaned = value.strip()

    if not cleaned:
        return {
            "valid": False,
            "type": "unknown",
            "message": "Empty hash value.",
        }

    if not HEX_RE.match(cleaned):
        return {
            "valid": False,
            "type": "unknown",
            "length": len(cleaned),
            "message": "Hash contains non-hex characters.",
        }

    hash_type = HASH_TYPES.get(len(cleaned), "unknown")

    notes = []

    if hash_type == "MD5":
        notes.append("MD5 is cryptographically broken and should not be used for integrity/security decisions.")
    elif hash_type == "SHA1":
        notes.append("SHA1 is deprecated for cryptographic security use.")
    elif hash_type in ["SHA256", "SHA512"]:
        notes.append("Modern hash length detected.")
    else:
        notes.append("Unknown hash length.")

    return {
        "valid": hash_type != "unknown",
        "type": hash_type,
        "length": len(cleaned),
        "value": cleaned.lower(),
        "notes": notes,
    }


def generate_hashes(text: str) -> dict:
    encoded = text.encode("utf-8")

    return {
        "md5": hashlib.md5(encoded).hexdigest(),
        "sha1": hashlib.sha1(encoded).hexdigest(),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "sha512": hashlib.sha512(encoded).hexdigest(),
    }


def compare_hash(text: str, expected_hash: str) -> dict:
    generated = generate_hashes(text)
    identified = identify_hash(expected_hash)

    expected_clean = expected_hash.strip().lower()
    matched = []

    for hash_type, value in generated.items():
        if value == expected_clean:
            matched.append(hash_type.upper())

    return {
        "expected": identified,
        "matched": bool(matched),
        "matched_algorithms": matched,
        "generated": generated,
    }
