"""Read the exact Docker interpreter version; optionally verify this runtime."""

import argparse
import platform
import re
from pathlib import Path


def docker_python_version():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    images = re.findall(
        r"^FROM\s+python:([^\s]+)", dockerfile.read_text(), re.MULTILINE
    )
    if len(images) != 1:
        raise ValueError("Expected exactly one Python base image in Dockerfile")
    match = re.fullmatch(
        r"(\d+\.\d+\.\d+)-alpine[\d.]+(?:@sha256:[a-f0-9]{64})?", images[0]
    )
    if not match:
        raise ValueError("Dockerfile must pin an exact Python patch version on Alpine")
    return match[1]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = docker_python_version()
    if args.check:
        actual = platform.python_version()
        if actual != expected:
            raise SystemExit(
                f"Expected Python {expected} from Dockerfile, got {actual}"
            )
        print(f"Verified Python {actual} matches Dockerfile")
    else:
        print(expected)
