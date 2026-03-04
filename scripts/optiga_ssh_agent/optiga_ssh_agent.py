#!/usr/bin/env python3
"""
OPTIGA Trust M SSH Agent

Custom SSH agent that uses OPTIGA Trust M hardware chip for key storage
and signing operations. Implements SSH agent protocol (RFC draft-miller-ssh-agent).

WAŻNE: Musi być uruchamiany z LD_PRELOAD shimem przekierowującym /dev/i2c-1 → /dev/i2c-3
Użyj wrappera optiga_run.sh lub ustaw LD_PRELOAD w środowisku.

Usage:
    Manual:   LD_PRELOAD=~/OPTIGA-Trust-M/i2c_redirect.so ./optiga_ssh_agent.py
    Debug:    LD_PRELOAD=~/OPTIGA-Trust-M/i2c_redirect.so ./optiga_ssh_agent.py --debug
    Custom:   LD_PRELOAD=~/OPTIGA-Trust-M/i2c_redirect.so ./optiga_ssh_agent.py --socket /tmp/optiga.sock

Then:
    export SSH_AUTH_SOCK=/run/user/$(id -u)/optiga-ssh-agent.sock
    ssh-add -l    # should show optiga key
    ssh user@host
"""

import argparse
import logging
import os
import signal
import socket
import struct
import sys
import threading

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import optigatrust as optiga
from optigatrust import objects, crypto

# SSH Agent Protocol Constants
SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENT_IDENTITIES_ANSWER   = 12
SSH2_AGENTC_SIGN_REQUEST       = 13
SSH2_AGENT_SIGN_RESPONSE       = 14
SSH_AGENT_FAILURE              = 5

logger = logging.getLogger("optiga-ssh-agent")


class OPTIGATrustM:
    """Interface to OPTIGA Trust M chip via optigatrust library."""

    SSH_SLOT_OID = 0xE0F1

    def __init__(self, pubkey_pem_path):
        """
        :param pubkey_pem_path: Ścieżka do pliku PEM z kluczem publicznym SSH slotu.
                                Wygenerowany przez phase2_keygen.py jako *_SSH_Auth.pem
        """
        self._chip            = None
        self._key_obj         = None
        self._pubkey_pem_path = pubkey_pem_path
        self.lock             = threading.Lock()

    def init(self):
        """
        Inicjalizuje połączenie z chipem i weryfikuje stan slotu SSH.
        WYMAGA LD_PRELOAD=i2c_redirect.so — bez tego PAL szuka /dev/i2c-1 zamiast /dev/i2c-3.
        """
        self._chip = optiga.Chip(interface="i2c")

        obj  = optiga.Object(self.SSH_SLOT_OID)
        meta = obj.meta
        if meta.get("algorithm") != "secp256r1":
            raise RuntimeError(
                f"Slot {hex(self.SSH_SLOT_OID)} nie ma klucza ECC P-256. "
                f"Uruchom najpierw phase2_keygen.py."
            )

        self._key_obj = objects.ECCKey(self.SSH_SLOT_OID)
        logger.info(f"OPTIGA Trust M: {self._chip.name}")
        logger.info(f"Slot {hex(self.SSH_SLOT_OID)}: lcso={meta.get('lcso')}, "
                    f"key_usage={meta.get('key_usage')}")

    def get_public_key_raw(self):
        """
        Zwraca surowy klucz publiczny jako 64 bajty X||Y (bez prefiksu 0x04).

        Czyta z pliku PEM wygenerowanego przez phase2_keygen.py.
        UWAGA: obj.read() ma buga w optigatrust v1.5.1 dla key slotów
        (TypeError: 'EnumType' object cannot be interpreted as an integer)
        — dlatego PEM file jest jedynym niezawodnym źródłem klucza publicznego.
        """
        with open(self._pubkey_pem_path, 'rb') as f:
            pem_data = f.read()

        pub = serialization.load_pem_public_key(pem_data)
        # X962 UncompressedPoint: 0x04 || X(32) || Y(32)
        raw = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return bytes(raw[1:65])  # X||Y bez prefiksu 0x04

    def sign(self, data):
        """
        Podpisuje dane przez chip. SHA-256 jest liczony wewnętrznie przez ecdsa_sign.
        Zwraca 64 bajty raw signature R||S (wymagane przez SSH agent protokół).

        ecdsa_sign zwraca DER ASN.1 SEQUENCE { INTEGER r, INTEGER s }
        — dekodujemy do raw R||S przez decode_dss_signature.
        """
        with self.lock:
            sig_result = crypto.ecdsa_sign(self._key_obj, data)
            r, s       = decode_dss_signature(sig_result.signature)
            r_bytes    = r.to_bytes(32, 'big')
            s_bytes    = s.to_bytes(32, 'big')
            logger.debug(f"Podpisano {len(data)}B → R: {r_bytes.hex()[:16]}...")
            return r_bytes + s_bytes


def build_ssh_public_key_blob(raw_pub_key):
    """
    Buduje SSH public key blob z surowego 64-bajtowego klucza ECC (X||Y).
    Format per RFC 5656: string(key_type) || string(curve) || string(point)
    """
    key_type = b"ecdsa-sha2-nistp256"
    curve    = b"nistp256"
    point    = b'\x04' + raw_pub_key

    blob  = struct.pack(">I", len(key_type)) + key_type
    blob += struct.pack(">I", len(curve))    + curve
    blob += struct.pack(">I", len(point))    + point
    return blob


def build_ssh_signature_blob(raw_signature):
    """
    Buduje SSH signature blob z surowego 64-bajtowego podpisu ECDSA (R||S).
    SSH ECDSA używa mpint encoding dla R i S (RFC 5656).
    """
    sig_type = b"ecdsa-sha2-nistp256"

    def to_mpint(b):
        i = 0
        while i < len(b) - 1 and b[i] == 0:
            i += 1
        b = b[i:]
        if b[0] & 0x80:
            b = b'\x00' + b
        return b

    r_mpint = to_mpint(raw_signature[0:32])
    s_mpint = to_mpint(raw_signature[32:64])

    inner  = struct.pack(">I", len(r_mpint)) + r_mpint
    inner += struct.pack(">I", len(s_mpint)) + s_mpint

    blob  = struct.pack(">I", len(sig_type)) + sig_type
    blob += struct.pack(">I", len(inner))    + inner
    return blob


def read_message(conn):
    """Odczytuje jeden komunikat protokołu SSH agent z socketu."""
    length_bytes = b""
    while len(length_bytes) < 4:
        chunk = conn.recv(4 - len(length_bytes))
        if not chunk:
            return None, None
        length_bytes += chunk

    msg_len = struct.unpack(">I", length_bytes)[0]
    if msg_len == 0 or msg_len > 256 * 1024:
        return None, None

    data = b""
    while len(data) < msg_len:
        chunk = conn.recv(msg_len - len(data))
        if not chunk:
            return None, None
        data += chunk

    return data[0], data[1:]


def send_message(conn, msg_type, payload=b""):
    """Wysyła jeden komunikat protokołu SSH agent."""
    msg = bytes([msg_type]) + payload
    conn.sendall(struct.pack(">I", len(msg)) + msg)


def handle_identities(key_blob):
    """Obsługuje REQUEST_IDENTITIES — zwraca nasz klucz publiczny."""
    comment  = b"optiga-trust-m-E0F1"
    payload  = struct.pack(">I", 1)
    payload += struct.pack(">I", len(key_blob)) + key_blob
    payload += struct.pack(">I", len(comment))  + comment
    return payload


def handle_sign(chip, key_blob, payload):
    """Obsługuje SIGN_REQUEST — podpisuje dane chipem."""
    offset = 0

    blob_len     = struct.unpack(">I", payload[offset:offset+4])[0]; offset += 4
    req_key_blob = payload[offset:offset+blob_len];                  offset += blob_len
    data_len     = struct.unpack(">I", payload[offset:offset+4])[0]; offset += 4
    data         = payload[offset:offset+data_len];                  offset += data_len
    flags        = struct.unpack(">I", payload[offset:offset+4])[0] if offset + 4 <= len(payload) else 0

    if req_key_blob != key_blob:
        logger.warning("Sign request dla nieznanego klucza")
        return None

    logger.debug(f"Podpisuję {len(data)}B (flags={flags})")
    raw_sig  = chip.sign(data)
    sig_blob = build_ssh_signature_blob(raw_sig)
    return struct.pack(">I", len(sig_blob)) + sig_blob


def handle_client(conn, chip, key_blob):
    """Obsługuje jedno połączenie klienta."""
    try:
        while True:
            msg_type, payload = read_message(conn)
            if msg_type is None:
                break

            if msg_type == SSH2_AGENTC_REQUEST_IDENTITIES:
                logger.debug("REQUEST_IDENTITIES")
                send_message(conn, SSH2_AGENT_IDENTITIES_ANSWER, handle_identities(key_blob))

            elif msg_type == SSH2_AGENTC_SIGN_REQUEST:
                logger.debug("SIGN_REQUEST")
                resp = handle_sign(chip, key_blob, payload)
                send_message(conn, SSH2_AGENT_SIGN_RESPONSE if resp else SSH_AGENT_FAILURE, resp or b"")

            else:
                logger.debug(f"Nieznany typ komunikatu: {msg_type}")
                send_message(conn, SSH_AGENT_FAILURE)

    except Exception as e:
        logger.error(f"Błąd klienta: {e}", exc_info=True)
    finally:
        conn.close()


def run_agent(socket_path, chip):
    """Główna pętla agenta."""
    raw_pub  = chip.get_public_key_raw()
    key_blob = build_ssh_public_key_blob(raw_pub)

    # Wyświetl klucz SSH — skopiuj do authorized_keys na docelowym serwerze
    x   = int.from_bytes(raw_pub[0:32], 'big')
    y   = int.from_bytes(raw_pub[32:64], 'big')
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    ssh_pub = pub.public_bytes(Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    print(f"\nSSH public key (dodaj do ~/.ssh/authorized_keys na serwerze):")
    print(f"  {ssh_pub.decode()} optiga-E0F1\n")

    if os.path.exists(socket_path):
        os.unlink(socket_path)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(socket_path)
    os.chmod(socket_path, 0o600)
    sock.listen(5)

    logger.info(f"Nasłuchuję na {socket_path}")
    print(f"Aby użyć agenta:")
    print(f"  export SSH_AUTH_SOCK={socket_path}")
    print(f"  ssh-add -l")
    print(f"  ssh user@host\n")

    def cleanup(signum=None, frame=None):
        logger.info("Zatrzymuję agenta...")
        sock.close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        sys.exit(0)

    signal.signal(signal.SIGINT,  cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        while True:
            conn, _ = sock.accept()
            logger.debug("Klient połączony")
            t = threading.Thread(target=handle_client, args=(conn, chip, key_blob))
            t.daemon = True
            t.start()
    except Exception as e:
        logger.error(f"Błąd agenta: {e}")
    finally:
        cleanup()


def main():
    parser = argparse.ArgumentParser(description="OPTIGA Trust M SSH Agent")
    parser.add_argument(
        "--pubkey", default=None,
        help="Ścieżka do PEM z kluczem publicznym SSH (domyślnie: auto-detect *_SSH_Auth.pem)"
    )
    parser.add_argument(
        "--socket", default=None,
        help="Ścieżka socketu (domyślnie: /run/user/$UID/optiga-ssh-agent.sock)"
    )
    parser.add_argument("--debug", action="store_true", help="Włącz debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # Auto-detect PEM jeśli nie podano
    if args.pubkey:
        pem_path = args.pubkey
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [f for f in os.listdir(script_dir) if f.endswith("_SSH_Auth.pem")]
        if not candidates:
            logger.error(
                "Nie znaleziono *_SSH_Auth.pem w katalogu skryptu. "
                "Podaj ścieżkę przez --pubkey lub uruchom najpierw phase2_keygen.py."
            )
            sys.exit(1)
        pem_path = os.path.join(script_dir, candidates[0])
        logger.info(f"Auto-detected PEM: {pem_path}")

    if not os.path.exists(pem_path):
        logger.error(f"Plik PEM nie istnieje: {pem_path}")
        sys.exit(1)

    # Socket path
    if args.socket:
        socket_path = args.socket
    else:
        uid         = os.getuid()
        runtime_dir = f"/run/user/{uid}"
        if not os.path.exists(runtime_dir):
            runtime_dir = "/tmp"
        socket_path = os.path.join(runtime_dir, "optiga-ssh-agent.sock")

    chip = OPTIGATrustM(pubkey_pem_path=pem_path)
    try:
        chip.init()
    except Exception as e:
        logger.error(f"Inicjalizacja chipa nieudana: {e}")
        sys.exit(1)

    run_agent(socket_path, chip)


if __name__ == "__main__":
    main()
