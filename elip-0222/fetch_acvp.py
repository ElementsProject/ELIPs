"""Fetch NIST's ACVP test vectors for ML-KEM-768 (FIPS 203) into `acvp/`.

Source: usnistgov/ACVP-Server, `gen-val/json-files/ML-KEM-*-FIPS203/internalProjection.json`,
pinned to `ACVP_COMMIT`. Only the ML-KEM-768 test groups for the functions HKE
uses are kept; the test cases themselves are copied unmodified.

    .venv/bin/python fetch_acvp.py
"""

import json
import urllib.request
from pathlib import Path

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{commit}/gen-val/json-files/{name}/internalProjection.json"
OUT = Path(__file__).with_name("acvp")

FILES = {
    "ML-KEM-keyGen-FIPS203": "keyGen",
    "ML-KEM-encapDecap-FIPS203": "encapDecap",
}
FUNCTIONS = {None, "encapsulation", "decapsulation", "encapsulationKeyCheck"}


def fetch(name: str) -> dict:
    with urllib.request.urlopen(URL.format(commit=ACVP_COMMIT, name=name)) as r:
        return json.load(r)


def main():
    OUT.mkdir(exist_ok=True)
    for name, short in FILES.items():
        data = fetch(name)
        data["testGroups"] = [
            g
            for g in data["testGroups"]
            if g["parameterSet"] == "ML-KEM-768" and g.get("function") in FUNCTIONS
        ]
        data["source"] = URL.format(commit=ACVP_COMMIT, name=name)
        path = OUT / f"ML-KEM-768-{short}.json"
        path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {path}: {sum(len(g['tests']) for g in data['testGroups'])} tests")


if __name__ == "__main__":
    main()
