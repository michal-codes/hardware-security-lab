# test_atecc.py
from cryptoauthlib import *

# Konfiguracja I2C dla ATECC608A
cfg = cfg_ateccx08a_i2c_default()
cfg.cfg.atcai2c.bus = 1
cfg.cfg.atcai2c.address = 0xC0  # 8-bit adres (0x60 << 1)
cfg.devtype = 3                  # ATECC608A

# Połącz z chipem
status = atcab_init(cfg)
print(f"Init: {'OK' if status == 0 else f'BŁĄD {status}'}")

if status != 0:
    print("Nie udało się połączyć z chipem")
    exit(1)

# Numer seryjny (9 bajtów, unikalny)
serial = bytearray(9)
status = atcab_read_serial_number(serial)
print(f"Serial:  {serial.hex()}")

# Info o chipie
info = bytearray(4)
status = atcab_info(info)
print(f"Info:    {info.hex()}")

# Sprzętowy RNG
random = bytearray(32)
status = atcab_random(random)
print(f"Random:  {random.hex()}")

# SHA-256 sprzętowy
message = b"Hello from ATECC608A!"
digest = bytearray(32)
atcab_sha(len(message), message, digest)
print(f"SHA256:  {digest.hex()}")

atcab_release()
