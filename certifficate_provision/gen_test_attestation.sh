set -euo pipefail

OUT_DIR="${1:-./attestation_test}"
DAYS="${2:-3650}"

mkdir -p "$OUT_DIR"

openssl ecparam -name prime256v1 -genkey -noout -out "$OUT_DIR/attest_key.pem"

openssl req -new -x509 \
  -key "$OUT_DIR/attest_key.pem" \
  -out "$OUT_DIR/attest_cert.pem" \
  -days "$DAYS" \
  -subj "/O=Vault Bench Test/CN=Vault Bench Test FIDO2 Attestation"

openssl x509 -in "$OUT_DIR/attest_cert.pem" -outform DER -out "$OUT_DIR/attest_cert.der"

echo "Wrote:"
echo "  $OUT_DIR/attest_key.pem   (EC private key, PEM)"
echo "  $OUT_DIR/attest_cert.pem  (self-signed cert, PEM)"
echo "  $OUT_DIR/attest_cert.der  (self-signed cert, DER — what the device stores)"