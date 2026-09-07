#!/usr/bin/env python3

import argparse
import json
import sys
import time

import serial
from cryptography.hazmat.primitives import serialization


def load_raw_private_key(key_path: str) -> bytes:
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    numbers = key.private_numbers()
    return numbers.private_value.to_bytes(32, "big")  # P-256 scalar, 32 bytes big-endian


def send_json(ser: serial.Serial, obj: dict) -> dict:
    line = json.dumps(obj) + "\n"
    ser.reset_input_buffer()
    ser.write(line.encode("ascii"))
    ser.flush()
    raw = ser.readline().decode("ascii", errors="replace").strip()
    if not raw:
        raise RuntimeError(f"No response to {obj.get('cmd')} (timed out)")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(f"Non-JSON response to {obj.get('cmd')!r}: {raw!r}")


def ensure_authenticated(ser: serial.Serial, pin: str) -> None:
    send_json(ser, {"cmd": "CREATE_PIN", "pin": pin})

    resp = send_json(ser, {"cmd": "VERIFY_PIN", "pin": pin})
    if resp.get("type") == "error" or resp.get("event") != "PIN_OK":
        raise RuntimeError(
            f"Could not authenticate with pin {pin!r}: {resp}. "
            "If the device already has a different PIN, pass --pin with that value, "
            "or factory-reset the bench unit first."
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True, help="Path to EC private key (PEM)")
    parser.add_argument("--cert", required=True, help="Path to leaf cert (DER)")
    parser.add_argument("--port", required=True, help="Serial port, e.g. COM19")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--pin", default="123456", help="Bench-only PIN used to authenticate first")
    args = parser.parse_args()

    priv_bytes = load_raw_private_key(args.key)
    if len(priv_bytes) != 32:
        print(f"ERROR: private key is {len(priv_bytes)} bytes, expected 32", file=sys.stderr)
        return 1

    with open(args.cert, "rb") as f:
        cert_der = f.read()

    if len(cert_der) == 0 or len(cert_der) > 2000:
        print(f"ERROR: cert DER is {len(cert_der)} bytes, expected 1..2000", file=sys.stderr)
        return 1

    try:
        with serial.Serial(args.port, args.baud, timeout=5) as ser:
            time.sleep(2)
            ser.reset_input_buffer()

            ensure_authenticated(ser, args.pin)

            resp = send_json(ser, {
                "cmd": "PROVISION_ATTESTATION",
                "privkey": priv_bytes.hex(),
                "cert": cert_der.hex(),
            })
    except (serial.SerialException, RuntimeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if resp.get("type") == "event" and resp.get("event") == "ATTESTATION_PROVISIONED":
        print("Device provisioned successfully.")
        return 0
    else:
        print(f"Provisioning failed: {resp}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())