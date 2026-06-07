import hashlib

def compute_hash(title: str, url: str, pub_date: str) -> str:
    raw = f'{title}|{url}|{pub_date}'
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()
