#!/usr/bin/env python3
"""
ATECC608A SSH Agent

Custom SSH agent that uses ATECC608A hardware chip for key storage
and signing operations. Implements SSH agent protocol (RFC draft-miller-ssh-agent).

Usage:
    Manual:   ./atecc_ssh_agent.py
    Debug:    ./atecc_ssh_agent.py --debug
    Custom:   ./atecc_ssh_agent.py --socket /tmp/atecc-ssh.sock

Then:
    export SSH_AUTH_SOCK=/run/user/$(id -u)/atecc-ssh-agent.sock
    ssh user@host
"""

import argparse
import hashlib
import logging
import os
import signal
import socket
import struct
import sys
import threading
import time

from cryptoauthlib import *

# SSH Agent Protocol Constants
SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENTC_SIGN_REQUEST = 13
SSH2_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_FAILURE = 5

# SSH signature flags
SSH_AGENT_RSA_SHA2_256 = 2
SSH_AGENT_RSA_SHA2_512 = 4

logger = logging.getLogger("atecc-ssh-agent")


class ATECC608A:
    """Interface to ATECC608A chip over I2C."""

    def __init__(self, bus=1, address=0xC0, slot=0):
        self.bus = bus
        self.address = address
        self.slot = slot
        self.lock = threading.Lock()
        self._initialized = False

    def init(self):
        """Initialize I2C connection to chip."""
        cfg = cfg_ateccx08a_i2c_default()
        cfg.cfg.atcai2c.bus = self.bus
        cfg.cfg.atcai2c.address = self.address
        cfg.devtype = 3  # ATECC608A

        status = atcab_init(cfg)
        if status != 0:
            raise RuntimeError(f"ATECC608A init failed: {status}")

        time.sleep(0.05)

        # Verify chip is locked and operational
        config = bytearray(128)
        status = atcab_read_config_zone(config)
        if status != 0:
            raise RuntimeError(f"Read config failed: {status}")

        if config[87] != 0x00:
            raise RuntimeError("Config Zone not locked!")
        if config[86] != 0x00:
            raise RuntimeError("Data Zone not locked!")

        serial = bytearray(9)
        atcab_read_serial_number(serial)
        logger.info(f"ATECC608A connected, serial: {serial.hex()}")

        self._initialized = True

    def release(self):
        """Release I2C connection."""
        if self._initialized:
            atcab_release()
            self._initialized = False

    def get_public_key(self):
        """Read public key from slot (64 bytes raw, X||Y)."""
        with self.lock:
            pub = bytearray(64)
            status = atcab_get_pubkey(self.slot, pub)
            if status != 0:
                raise RuntimeError(f"Get pubkey failed: {status}")
            return bytes(pub)

    def sign(self, digest):
        """Sign a SHA-256 digest (32 bytes). Returns 64-byte raw signature (R||S)."""
        if len(digest) != 32:
            raise ValueError(f"Digest must be 32 bytes, got {len(digest)}")

        with self.lock:
            sig = bytearray(64)
            status = atcab_sign(self.slot, bytearray(digest), sig)
            if status != 0:
                raise RuntimeError(f"Sign failed: {status}")
            logger.debug(f"Signed digest, sig: {sig.hex()[:20]}...")
            return bytes(sig)


def build_ssh_public_key_blob(raw_pub_key):
    """Build SSH public key blob from raw 64-byte ECC public key."""
    key_type = b"ecdsa-sha2-nistp256"
    curve = b"nistp256"
    # Uncompressed point: 0x04 || X(32) || Y(32)
    point = b'\x04' + raw_pub_key

    blob = b""
    blob += struct.pack(">I", len(key_type)) + key_type
    blob += struct.pack(">I", len(curve)) + curve
    blob += struct.pack(">I", len(point)) + point
    return blob


def build_ssh_signature_blob(raw_signature):
    """Build SSH signature blob from raw 64-byte ECDSA signature (R||S).

    SSH ECDSA signatures use mpint encoding for R and S per RFC 5656.
    """
    sig_type = b"ecdsa-sha2-nistp256"

    r_bytes = raw_signature[0:32]
    s_bytes = raw_signature[32:64]

    # Strip leading zeros but keep sign bit handling (mpint)
    def to_mpint(b):
        # Remove leading zero bytes
        i = 0
        while i < len(b) - 1 and b[i] == 0:
            i += 1
        b = b[i:]
        # Add leading zero if high bit set (mpint is signed)
        if b[0] & 0x80:
            b = b'\x00' + b
        return b

    r_mpint = to_mpint(r_bytes)
    s_mpint = to_mpint(s_bytes)

    # Inner blob: mpint(r) || mpint(s)
    inner = b""
    inner += struct.pack(">I", len(r_mpint)) + r_mpint
    inner += struct.pack(">I", len(s_mpint)) + s_mpint

    # Outer blob: string(sig_type) || string(inner)
    blob = b""
    blob += struct.pack(">I", len(sig_type)) + sig_type
    blob += struct.pack(">I", len(inner)) + inner
    return blob


def read_message(conn):
    """Read one SSH agent protocol message from socket."""
    # First 4 bytes: message length
    length_bytes = b""
    while len(length_bytes) < 4:
        chunk = conn.recv(4 - len(length_bytes))
        if not chunk:
            return None, None
        length_bytes += chunk

    msg_len = struct.unpack(">I", length_bytes)[0]
    if msg_len == 0 or msg_len > 256 * 1024:
        return None, None

    # Read full message
    data = b""
    while len(data) < msg_len:
        chunk = conn.recv(msg_len - len(data))
        if not chunk:
            return None, None
        data += chunk

    msg_type = data[0]
    payload = data[1:]
    return msg_type, payload


def send_message(conn, msg_type, payload=b""):
    """Send one SSH agent protocol message."""
    msg = bytes([msg_type]) + payload
    conn.sendall(struct.pack(">I", len(msg)) + msg)


def handle_identities(chip, key_blob):
    """Handle SSH2_AGENTC_REQUEST_IDENTITIES — return our public key."""
    comment = b"atecc608a-slot0"

    # nkeys(uint32) || key_blob_len(uint32) || key_blob || comment_len(uint32) || comment
    payload = struct.pack(">I", 1)  # 1 key
    payload += struct.pack(">I", len(key_blob)) + key_blob
    payload += struct.pack(">I", len(comment)) + comment
    return payload


def handle_sign(chip, key_blob, payload):
    """Handle SSH2_AGENTC_SIGN_REQUEST — sign data with chip."""
    offset = 0

    # Parse key blob from request
    blob_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    req_key_blob = payload[offset:offset + blob_len]
    offset += blob_len

    # Parse data to sign
    data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    data = payload[offset:offset + data_len]
    offset += data_len

    # Parse flags
    flags = 0
    if offset + 4 <= len(payload):
        flags = struct.unpack(">I", payload[offset:offset + 4])[0]

    # Verify it's asking for our key
    if req_key_blob != key_blob:
        logger.warning("Sign request for unknown key")
        return None

    # Hash the data (SSH sends raw data, chip needs SHA-256 digest)
    digest = hashlib.sha256(data).digest()
    logger.debug(f"Signing {len(data)} bytes, digest: {digest.hex()[:16]}...")

    # Sign with ATECC608A
    raw_sig = chip.sign(digest)

    # Build SSH signature blob
    sig_blob = build_ssh_signature_blob(raw_sig)

    # Response: string(signature)
    response = struct.pack(">I", len(sig_blob)) + sig_blob
    return response


def handle_client(conn, chip, key_blob):
    """Handle one client connection."""
    try:
        while True:
            msg_type, payload = read_message(conn)

            if msg_type is None:
                break

            if msg_type == SSH2_AGENTC_REQUEST_IDENTITIES:
                logger.debug("REQUEST_IDENTITIES")
                resp = handle_identities(chip, key_blob)
                send_message(conn, SSH2_AGENT_IDENTITIES_ANSWER, resp)

            elif msg_type == SSH2_AGENTC_SIGN_REQUEST:
                logger.debug("SIGN_REQUEST")
                resp = handle_sign(chip, key_blob, payload)
                if resp:
                    send_message(conn, SSH2_AGENT_SIGN_RESPONSE, resp)
                else:
                    send_message(conn, SSH_AGENT_FAILURE)

            else:
                logger.debug(f"Unknown message type: {msg_type}")
                send_message(conn, SSH_AGENT_FAILURE)

    except Exception as e:
        logger.error(f"Client error: {e}")
    finally:
        conn.close()


def run_agent(socket_path, chip, debug=False):
    """Main agent loop."""
    # Get public key and build blob
    raw_pub = chip.get_public_key()
    key_blob = build_ssh_public_key_blob(raw_pub)
    logger.info(f"Serving public key for slot {chip.slot}")

    # Clean up old socket
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    # Create Unix socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(socket_path)
    os.chmod(socket_path, 0o600)  # Only owner can access
    sock.listen(5)

    logger.info(f"Listening on {socket_path}")
    print(f"\nTo use this agent:")
    print(f"  export SSH_AUTH_SOCK={socket_path}")
    print(f"  ssh-add -l    # should show atecc608a key")
    print(f"  ssh user@host")

    def cleanup(signum=None, frame=None):
        logger.info("Shutting down...")
        sock.close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        chip.release()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        while True:
            conn, _ = sock.accept()
            logger.debug("Client connected")
            t = threading.Thread(target=handle_client, args=(conn, chip, key_blob))
            t.daemon = True
            t.start()
    except Exception as e:
        logger.error(f"Agent error: {e}")
    finally:
        cleanup()


def main():
    parser = argparse.ArgumentParser(description="ATECC608A SSH Agent")
    parser.add_argument("--socket", default=None,
                        help="Socket path (default: /run/user/$UID/atecc-ssh-agent.sock)")
    parser.add_argument("--bus", type=int, default=1, help="I2C bus (default: 1)")
    parser.add_argument("--address", type=lambda x: int(x, 0), default=0xC0,
                        help="I2C address (default: 0xC0)")
    parser.add_argument("--slot", type=int, default=0, help="Key slot (default: 0)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # Socket path
    if args.socket:
        socket_path = args.socket
    else:
        uid = os.getuid()
        runtime_dir = f"/run/user/{uid}"
        if not os.path.exists(runtime_dir):
            runtime_dir = "/tmp"
        socket_path = os.path.join(runtime_dir, "atecc-ssh-agent.sock")

    # Init chip
    chip = ATECC608A(bus=args.bus, address=args.address, slot=args.slot)
    try:
        chip.init()
    except Exception as e:
        logger.error(f"Chip init failed: {e}")
        sys.exit(1)

    run_agent(socket_path, chip, debug=args.debug)


if __name__ == "__main__":
    main()
