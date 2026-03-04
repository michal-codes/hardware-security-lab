# OPTIGA Trust M — Provisioning

> Dokument powstał na podstawie konfiguracji chipa Adafruit OPTIGA Trust M SLS32AIA (breakout board).
> Platforma: Raspberry Pi 3 (BCM2837, aarch64, 64-bit OS), `optigatrust` v1.5.1.

---

## Sprzęt i okablowanie

### Podłączenie (Qwiic JST-SH 4-pin)

| Pin OPTIGA breakout | Podłączony do RPi        | Uwaga                          |
|---------------------|--------------------------|--------------------------------|
| VCC                 | Pin 17 (3.3V fizyczny)   | stałe zasilanie                |
| GND                 | Pin 9 (GND)              | przez kabel Qwiic              |
| SDA                 | GPIO 17 (Pin 11)         | software I2C                   |
| SCL                 | GPIO 27 (Pin 13)         | software I2C                   |
| RST                 | **niepodłączony**        | pull-up na breakout Adafruit — działa |

**Dlaczego software I2C (bus 3)?**
BCM2837 (RPi 3) ma hardware bug — błędna implementacja clock stretchingu w I2C hardware.
OPTIGA Trust M intensywnie używa clock stretchingu → komunikacja przez hardware I2C jest niestabilna.
Rozwiązanie: overlay `i2c-gpio` tworzy software I2C na dedykowanych pinach.

**Dlaczego RST floating działa?**
Adafruit breakout ma wbudowany pull-up rezystor na pinie RST. Chip startuje z RST HIGH — normalny tryb pracy.
Nie trzeba lutować dodatkowego drutu.

### `/boot/firmware/config.txt`

```
# Software I2C (bus 3) - OPTIGA Trust M
# delay_us=50 kompensuje wolniejszą odpowiedź secure element
dtoverlay=i2c-gpio,bus=3,i2c_gpio_sda=17,i2c_gpio_scl=27,i2c_gpio_delay_us=50
```

---

## Różnice względem ATECC608A

| Aspekt               | ATECC608A                        | OPTIGA Trust M                          |
|----------------------|----------------------------------|-----------------------------------------|
| Model pamięci        | 16 slotów (0–15)                 | OID-based (obiekty `0xE0xx`–`0xF1xx`)  |
| Pre-provisioning     | czysta konfiguracja fabryczna    | certyfikat X.509 + klucz od Infineon    |
| Interfejs Python     | `cryptoauthlib`                  | `optigatrust` v1.5.1                    |
| Runtime interface    | brak PKCS#11 out-of-box          | natywny PKCS#11 przez Infineon .so      |
| Algorytmy ECC        | P-256 only                       | P-256, P-384, P-521, BrainpoolP256/384/512 |
| RSA                  | brak                             | RSA 1024/2048                           |
| Lock mechanizm       | nieodwracalny lock Config/Data   | lifecycle states (Creation→Init→Op→Term)|
| SSH/GPG integracja   | wymaga własnego shima            | natywnie przez PKCS#11                  |

---

## Zależności i instalacja

```bash
python3 -m venv ~/crypto-env
source ~/crypto-env/bin/activate
pip install optigatrust cryptography asn1crypto

# Weryfikacja
python3 -c "import optigatrust; print(optigatrust.__version__)"
# Oczekiwany wynik: 1.5.1

# Alias
alias crypto="source ~/crypto-env/bin/activate"
alias p='python3'
```

---

## Problem 1: BCM2837 + software I2C

Chip jest widoczny na bus 3:

```bash
i2cdetect -y 3
# Oczekiwany wynik:
#      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
# 30: 30 -- -- ...
# OPTIGA Trust M domyślny adres I2C: 0x30 (7-bit)
```

---

## Problem 2: PAL hardcodes `/dev/i2c-1`

PAL (Platform Abstraction Layer) to warstwa w `.so` bibliotece Infineon która tłumaczy API na konkretny hardware.
W przypadku `liboptigatrust-i2c-linux-aarch64.so` PAL ma hardcoded dwie rzeczy:

1. Otwiera `/dev/i2c-1` (nie `/dev/i2c-3` gdzie siedzi OPTIGA)
2. Próbuje sterować GPIO 17 i GPIO 27 przez `/sys/class/gpio/` jako RST i PWR

Diagnoza przez `strace`:

```
openat /sys/class/gpio/export → eksportuje GPIO 17
openat /sys/class/gpio/gpio17/direction → ENOENT (pin zajęty przez i2c-gpio overlay!)
openat /sys/class/gpio/gpio27/direction → ENOENT (tak samo)
openat /dev/i2c-1 → otwiera bus 1, nie bus 3
→ FAIL: chip nie odpowiada na i2c-1
```

**GPIO conflict**: piny 17/27 są zajęte przez i2c-gpio overlay jako SDA/SCL — PAL nie może ich użyć jako GPIO.
**Bus conflict**: OPTIGA jest na bus 3, PAL szuka na bus 1.

### Rozwiązanie: LD_PRELOAD shim

LD_PRELOAD to mechanizm Linuxa który ładuje bibliotekę przed wszystkimi pozostałymi (w tym `libc`).
Shim przechwytuje wywołanie `open()` i podmienia ścieżkę `/dev/i2c-1` → `/dev/i2c-3` transparentnie dla `.so`.

```c
// i2c_redirect.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>

static int (*real_open)(const char*, int, ...) = NULL;

int open(const char* path, int flags, ...) {
    if (!real_open)
        real_open = dlsym(RTLD_NEXT, "open");

    const char* target = path;
    if (strcmp(path, "/dev/i2c-1") == 0)
        target = "/dev/i2c-3";

    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        return real_open(target, flags, mode);
    }
    return real_open(target, flags);
}
```

```bash
gcc -shared -fPIC -o i2c_redirect.so i2c_redirect.c -ldl
# Umieść w katalogu projektu, np. ~/OPTIGA-Trust-M/
```

Użycie:

```bash
LD_PRELOAD=~/OPTIGA-Trust-M/i2c_redirect.so python3 skrypt.py
```

**Uwaga na błędy GPIO**: PAL wciąż wypisuje `Failed to open gpio direction for writing!` — to ostrzeżenie, nie błąd krytyczny.
RST i PWR nie są potrzebne: RST ma pull-up na breakout, VCC podłączone na stałe do 3.3V.
Chip komunikuje się poprawnie mimo tych ostrzeżeń.

---

## Problem 3: architektura aarch64

RPi 3 działa pod 64-bit OS (`aarch64`). Dostępne biblioteki:

```
liboptigatrust-i2c-linux-aarch64.so       ← używana przy interface="i2c"
liboptigatrust-i2c-gpiod-linux-aarch64.so ← używana przy interface="i2c-gpiod"
```

Obie działają z shimem. `i2c-gpiod` przechwytuje też `openat` dla GPIO przez libgpiod,
ale z shimem który łapie `open()` bus redirect działa dla obu.

---

## Faza 0: Połączenie i identyfikacja chipa

### Szablon inicjalizacji (wymagany dla wszystkich skryptów)

```python
import os, sys

# KRYTYCZNE: shim musi być załadowany przez LD_PRELOAD przed uruchomieniem
# Uruchamiać jako: LD_PRELOAD=~/OPTIGA-Trust-M/i2c_redirect.so python3 skrypt.py
# NIE używać subprocess z LD_PRELOAD wewnątrz — nie zadziała po inicjalizacji biblioteki

import optigatrust as optiga
from optigatrust import objects, crypto

# Singleton — Chip() zwraca tę samą instancję przy każdym wywołaniu
# Pierwszy Chip() inicjalizuje połączenie I2C przez .so
chip = optiga.Chip(interface="i2c")
```

### Skrypt diagnostyczny

```python
import optigatrust as optiga
from optigatrust import objects
import json

chip = optiga.Chip(interface="i2c")

# UID chipa — 27 bajtów, unikalny identyfikator
uid = chip.uid
print("=== OPTIGA Trust M UID ===")
print(f"  Chip model:  {chip.name}")
print(f"  CIM ID:      {uid.cim_id}")
print(f"  Platform:    {uid.platform_id}")
print(f"  Model ID:    {uid.model_id}")
print(f"  ROM mask:    {uid.rommask_id}")
print(f"  Chip type:   {uid.chip_type}")
print(f"  Batch:       {uid.batch_num}")
print(f"  Coords:      ({uid.x_coord}, {uid.y_coord})")
print(f"  FW ID:       {uid.fw_id}")
print(f"  FW build:    {uid.fw_build}")
```

Rzeczywisty wynik (SLS32AIA010MH/S, Adafruit breakout):

```
=== OPTIGA Trust M UID ===
  Chip model:  OPTIGA™ Trust M V1 (SLS32AIA010MH/S)
  CIM ID:      cd
  Platform:    16
  Model ID:    33
  ROM mask:    8401
  Chip type:   001c00010000
  Batch:       0a091b5c000b
  Coords:      (003a, 007c)
  FW ID:       80101071
  FW build:    0809
```

`chip_id` używany jako prefix nazw plików: `{chip_type}_{batch_num}` → `001c00010000_0a091b5c000b`

---

## Faza 1: Odczyt stanu fabrycznego

### Mapa OID-ów OPTIGA Trust M V1

| OID      | Nazwa                | Zawartość fabryczna                   | Przeznaczenie                |
|----------|----------------------|---------------------------------------|------------------------------|
| `0xE0E0` | IFX_CERT             | Certyfikat X.509 od Infineon CA       | pre-provisioned device cert  |
| `0xE0E1` | USER_CERT_1          | pusty                                 | SSH key cert                 |
| `0xE0E2` | USER_CERT_2          | pusty                                 | GPG Sign cert                |
| `0xE0E3` | USER_CERT_3          | pusty                                 | GPG Encrypt cert             |
| `0xE0F0` | ECC_KEY_E0F0         | klucz prywatny ECC od Infineon        | pre-provisioned (nie dotykać)|
| `0xE0F1` | ECC_KEY_E0F1         | pusty                                 | **SSH Auth key**             |
| `0xE0F2` | ECC_KEY_E0F2         | pusty                                 | **GPG Sign key**             |
| `0xE0F3` | ECC_KEY_E0F3         | pusty                                 | **GPG Encrypt key (ECDH)**   |
| `0xE0FC` | RSA_KEY_E0FC         | pusty                                 | RSA key (opcjonalnie)        |
| `0xE0C2` | UID                  | 27 bajtów unikalnego ID               | identyfikacja chipa          |
| `0xE0C4` | current limit        | 6–15 mA                               | konfiguracja zasilania       |

### Rzeczywisty output phase1_dump.py (stan fabryczny)

```
=== Certyfikat Infineon (0xE0E0) ===
  Issuer:   Common Name: Infineon OPTIGA(TM) Trust M CA 101,
            Organizational Unit: OPTIGA(TM),
            Organization: Infineon Technologies AG, Country: DE
  Subject:  Common Name: Infineon IoT Node
  Valid:    2019-07-01 15:04:16+00:00 → 2039-07-01 15:04:16+00:00
  PubKey:   04c4239d5ee9f6e0a2e8317e1cc4ec308780bbf3...

=== Metadane slotów ECC (przed keygen) ===
  [0xe0f0] pre-provisioned
    lcso       = creation
    change     = never          ← zablokowany przez Infineon, nie do ruszenia
    execute    = always
    algorithm  = secp256r1
    key_usage  = ['authentication']   ← tylko auth, NIE signature → nie nadaje się do SSH/GPG

  [0xe0f1] SSH
    lcso       = creation
    change     = ['lcso', '<', 'operational']   ← można zmieniać dopóki < operational
    execute    = always
    (brak algorithm i key_usage — klucz jeszcze nie wygenerowany)

  [0xe0f2] GPG_Sign     (analogicznie — pusty)
  [0xe0f3] GPG_Encrypt  (analogicznie — pusty)
```

### Odczyt pre-provisioned certyfikatu Infineon

```python
import optigatrust as optiga
from optigatrust import objects
from asn1crypto import x509 as asn1_x509

chip = optiga.Chip(interface="i2c")

print("=== Pre-provisioned Infineon Certificate (0xE0E0) ===")
try:
    cert = objects.X509(0xE0E0)
    print(cert)  # __str__ wypisuje pełne info: issuer, subject, public key, signature
except Exception as e:
    print(f"  FAIL: {e}")

# Odczyt metadanych obiektu (lifecycle state, rozmiar, access conditions)
print("\n=== Metadata kluczowych OID-ów ===")
key_oids = {
    0xE0F0: "ECC_KEY_E0F0 (pre-provisioned)",
    0xE0F1: "ECC_KEY_E0F1 (SSH slot)",
    0xE0F2: "ECC_KEY_E0F2 (GPG Sign slot)",
    0xE0F3: "ECC_KEY_E0F3 (GPG Encrypt slot)",
}

for oid, name in key_oids.items():
    try:
        obj = optiga.Object(oid)
        meta = obj.meta
        print(f"\n  [{hex(oid)}] {name}")
        for k, v in meta.items():
            print(f"    {k:<20} = {v}")
    except Exception as e:
        print(f"  [{hex(oid)}] {name}: {e}")
```

### Odczyt losowości (TRNG test)

```python
import optigatrust as optiga
from optigatrust import crypto

chip = optiga.Chip(interface="i2c")

# Test TRNG — 32 bajty prawdziwej losowości z chipa
rng = crypto.random(32, trng=True)
print(f"TRNG (32B): {rng.hex()}")

# Test DRNG
drng = crypto.random(32, trng=False)
print(f"DRNG (32B): {drng.hex()}")
```

---

## Faza 2: Generowanie kluczy ECC

### Konfiguracja slotów

```python
from optigatrust import objects, crypto

# Key usage dla każdego slotu
SLOTS = {
    0xE0F1: {
        "name":      "SSH_Auth",
        "curve":     "secp256r1",
        "key_usage": ["authentication", "signature"],
    },
    0xE0F2: {
        "name":      "GPG_Sign",
        "curve":     "secp256r1",
        "key_usage": ["signature"],
    },
    0xE0F3: {
        "name":      "GPG_Encrypt",
        "curve":     "secp256r1",
        "key_usage": ["key_agreement"],
        # ECDH wymaga key_agreement, NIE signature
    },
}
```

### Skrypt generowania kluczy

```python
import optigatrust as optiga
from optigatrust import objects, crypto
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64
import struct
import json
import hashlib

chip = optiga.Chip(interface="i2c")

SLOTS = {
    0xE0F1: {"name": "SSH_Auth",     "curve": "secp256r1", "key_usage": ["authentication", "signature"]},
    0xE0F2: {"name": "GPG_Sign",     "curve": "secp256r1", "key_usage": ["signature"]},
    0xE0F3: {"name": "GPG_Encrypt",  "curve": "secp256r1", "key_usage": ["key_agreement"]},
}

print("=" * 60)
print("GENEROWANIE KLUCZY ECC P-256")
print("=" * 60)

public_keys_raw = {}  # {oid: bytes}

for oid, cfg in SLOTS.items():
    key_obj = objects.ECCKey(oid)
    pub_pkcs, _ = crypto.generate_pair(
        key_object=key_obj,
        curve=cfg["curve"],
        key_usage=cfg["key_usage"],
        export=False,       # klucz prywatny NIE opuszcza chipa
    )
    public_keys_raw[oid] = bytes(pub_pkcs)
    print(f"  [{hex(oid)}] {cfg['name']}: {pub_pkcs.hex()[:48]}...")

# ============================================
# WERYFIKACJA: Sign + Verify na każdym slocie
# (GPG_Encrypt używa ECDH, nie Sign — pomijamy 0xE0F3 w sign teście)
# ============================================
print("\n" + "=" * 60)
print("WERYFIKACJA SIGN + VERIFY")
print("=" * 60)

test_msg = b"OPTIGA Trust M provisioning verification"
sign_slots = {oid: cfg for oid, cfg in SLOTS.items() if "signature" in cfg["key_usage"]}

for oid, cfg in sign_slots.items():
    key_obj = objects.ECCKey(oid)

    # Sign przez chip
    sig_result = crypto.ecdsa_sign(key_obj, test_msg)
    sig_bytes = sig_result.signature  # DER encoded ASN.1

    # Verify po stronie software (cryptography library)
    pub_pkcs = public_keys_raw[oid]
    # optigatrust zwraca klucz publiczny jako DER SubjectPublicKeyInfo
    pub_key = serialization.load_der_public_key(pub_pkcs)
    pub_key.verify(sig_bytes, test_msg, ec.ECDSA(hashes.SHA256()))
    print(f"  [{hex(oid)}] {cfg['name']}: Sign + Verify OK")

# ============================================
# WERYFIKACJA: ECDH na slocie 0xE0F3
# ============================================
print(f"\n  [{hex(0xE0F3)}] GPG_Encrypt: ECDH test")
enc_key_obj = objects.ECCKey(0xE0F3)
# Generuj efemeryczny klucz po stronie hosta do testu
ephemeral_key = ec.generate_private_key(ec.SECP256R1())
ephemeral_pub_der = ephemeral_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

# ECDH — shared secret pozostaje na chipie (export=False)
session = crypto.ecdh(enc_key_obj, ephemeral_pub_der, export=False)
print(f"  [{hex(0xE0F3)}] GPG_Encrypt: ECDH → AcquiredSession OK (shared secret na chipie)")

# ============================================
# ZAPIS KLUCZY PUBLICZNYCH
# ============================================
print("\n" + "=" * 60)
print("ZAPIS KLUCZY PUBLICZNYCH")
print("=" * 60)

uid = chip.uid
chip_id = f"{uid.chip_type}_{uid.batch_num}"

# JSON backup
backup = {
    "chip":      chip.name,
    "chip_id":   chip_id,
    "fw_id":     uid.fw_id,
    "slots":     {}
}
for oid, cfg in SLOTS.items():
    pub_der = public_keys_raw[oid]
    backup["slots"][hex(oid)] = {
        "name":           cfg["name"],
        "curve":          cfg["curve"],
        "key_usage":      cfg["key_usage"],
        "public_key_der": pub_der.hex(),
    }

json_filename = f"optiga_{chip_id}_pubkeys.json"
with open(json_filename, "w") as f:
    json.dump(backup, f, indent=2)
print(f"  JSON: {json_filename}")

# SSH public key (slot 0xE0F1)
def der_pubkey_to_ssh(der_bytes, comment=""):
    pub_key = serialization.load_der_public_key(der_bytes)
    ssh_pub = pub_key.public_bytes(Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return ssh_pub.decode() + (f" {comment}" if comment else "")

ssh_filename = f"optiga_{chip_id}_ssh.pub"
ssh_line = der_pubkey_to_ssh(public_keys_raw[0xE0F1], f"optiga-{chip_id}-E0F1-ssh")
with open(ssh_filename, "w") as f:
    f.write(ssh_line + "\n")
print(f"  SSH:  {ssh_filename}")

# PEM dla każdego slotu
for oid, cfg in SLOTS.items():
    pub_key = serialization.load_der_public_key(public_keys_raw[oid])
    pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    pem_filename = f"optiga_{chip_id}_{cfg['name']}.pem"
    with open(pem_filename, "w") as f:
        f.write(pem.decode())
    print(f"  PEM:  {pem_filename}")

print("\n" + "=" * 60)
print("GOTOWE")
print("=" * 60)
```

### Rzeczywisty output phase2_keygen.py

```
============================================================
GENEROWANIE KLUCZY ECC P-256
============================================================
  [0xe0f1] SSH_Auth:    3059301306072a8648ce3d020106082a8648ce3d030107...
  [0xe0f2] GPG_Sign:    3059301306072a8648ce3d020106082a8648ce3d030107...
  [0xe0f3] GPG_Encrypt: 3059301306072a8648ce3d020106082a8648ce3d030107...
============================================================
WERYFIKACJA SIGN + VERIFY
============================================================
  [0xe0f1] SSH_Auth:    Sign + Verify OK
  [0xe0f2] GPG_Sign:    Sign + Verify OK
  [0xe0f3] GPG_Encrypt: ECDH → AcquiredSession OK (shared secret na chipie)
============================================================
ZAPIS KLUCZY PUBLICZNYCH
============================================================
  JSON: optiga_001c00010000_0a091b5c000b_pubkeys.json
  SSH:  optiga_001c00010000_0a091b5c000b_ssh.pub
  PEM:  optiga_001c00010000_0a091b5c000b_SSH_Auth.pem
  PEM:  optiga_001c00010000_0a091b5c000b_GPG_Sign.pem
  PEM:  optiga_001c00010000_0a091b5c000b_GPG_Encrypt.pem
```

### Metadane slotów po keygen

```
  [0xe0f1] SSH_Auth
    lcso       = creation          ← NIE zmienia się automatycznie po generate_pair!
    change     = ['lcso', '<', 'operational']
    execute    = always
    algorithm  = secp256r1         ← pojawia się po keygen (wcześniej brak)
    key_usage  = ['authentication', 'signature']

  [0xe0f2] GPG_Sign
    algorithm  = secp256r1
    key_usage  = ['signature']

  [0xe0f3] GPG_Encrypt
    algorithm  = secp256r1
    key_usage  = ['key_agreement']
```

**Kluczowa różnica względem ATECC608A**: `lcso` NIE zmienia się automatycznie po `generate_pair()`.
Klucz prywatny jest w chipie i działa, ale można go nadpisać przez kolejne `generate_pair()`.
Aby zamrozić — trzeba ręcznie przestawić `lcso=operational` przez `lock_lcso.py` (nieodwracalne).

### Bug optigatrust v1.5.1: obj.read() dla key slotów

```python
obj = optiga.Object(0xE0F1)
raw = obj.read()
# TypeError: 'EnumType' object cannot be interpreted as an integer
```

`obj.read()` rzuca `TypeError` dla OID-ów kluczy ECC (`0xE0F1–E0F3`).
Klucz publiczny dostępny tylko przez plik PEM wygenerowany podczas `phase2_keygen.py`.
Workaround: czytać klucz publiczny z pliku `*_SSH_Auth.pem` (patrz `optiga_ssh_agent.py`).

---

## Faza 4: SSH Agent

Analogia do `atecc_ssh_agent.py` — własny SSH agent rozmawiający z chipem przez `optigatrust`.
Nie wymaga Infineon PKCS#11 `.so` (osobny download) — działa bezpośrednio na `crypto.ecdsa_sign()`.

### Różnice implementacyjne względem ATECC608A

| | ATECC608A | OPTIGA Trust M |
|---|---|---|
| Inicjalizacja | `atcab_init()` | `Chip(interface="i2c")` + LD_PRELOAD |
| Klucz publiczny | `atcab_get_pubkey()` → raw 64B X\|\|Y | PEM file → X962 → X\|\|Y (obj.read() ma buga) |
| Podpis | `atcab_sign()` → raw 64B R\|\|S | `ecdsa_sign()` → DER ASN.1 → `decode_dss_signature()` → R\|\|S |
| Lock check | `config[86/87] == 0x00` | `obj.meta['algorithm'] == 'secp256r1'` |

### Uruchomienie

```bash
# Agent auto-detect znajdzie *_SSH_Auth.pem w tym samym katalogu
optiga optiga_ssh_agent.py --debug

# W osobnym terminalu
export SSH_AUTH_SOCK=/run/user/$(id -u)/optiga-ssh-agent.sock
ssh-add -l          # powinno pokazać klucz ecdsa-sha2-nistp256
ssh user@serwer     # logowanie przez chip
```

### Wynik ssh-add -l (potwierdzenie działania)

```
256 SHA256:xxxx...xxxx optiga-trust-m-E0F1 (ECDSA)
```

SSH działa end-to-end — challenge podpisywany przez OPTIGA Trust M `0xE0F1`. ✓

### systemd service

```ini
# ~/.config/systemd/user/optiga-ssh-agent.service
[Unit]
Description=OPTIGA Trust M SSH Agent
After=network.target

[Service]
Type=simple
Environment=LD_PRELOAD=/home/deploy/OPTIGA-Trust-M/i2c_redirect.so
ExecStart=/home/deploy/crypto-env/bin/python3 /home/deploy/OPTIGA-Trust-M/optiga_ssh_agent.py
Restart=on-failure

[Install]
WantedBy=default.target
```

---

## Faza 3: Pre-provisioned certyfikat Infineon

OPTIGA Trust M V1 zawiera fabrycznie:
- `0xE0F0` — klucz prywatny ECC P-256 wygenerowany przez Infineon
- `0xE0E0` — certyfikat X.509 podpisany przez Infineon CA

To pozwala na **device attestation** — udowodnienie że klucz pochodzi z prawdziwego chipa Infineon
(łańcuch CA: Infineon Root CA → Infineon ECC CA → device cert na `0xE0E0`).

```python
import optigatrust as optiga
from optigatrust import objects
from asn1crypto import x509 as asn1_x509

chip = optiga.Chip(interface="i2c")
cert = objects.X509(0xE0E0)

# Eksport DER
with open("optiga_ifx_device_cert.der", "wb") as f:
    f.write(cert.der)

# Eksport PEM
with open("optiga_ifx_device_cert.pem", "wb") as f:
    f.write(cert.pem)

# Parsowanie certyfikatu
x509 = asn1_x509.Certificate.load(cert.der)
tbs = x509["tbs_certificate"]
print(f"Issuer:  {tbs['issuer'].human_friendly}")
print(f"Subject: {tbs['subject'].human_friendly}")
print(f"Valid:   {tbs['validity']['not_before'].native} → {tbs['validity']['not_after'].native}")
print(f"PubKey:  {cert.pkey}")
```

---

## Skrypt pomocniczy: wrapper z LD_PRELOAD

Aby nie pamiętać o `LD_PRELOAD` przy każdym uruchomieniu, stwórz wrapper:

```bash
#!/bin/bash
# ~/OPTIGA-Trust-M/optiga_run.sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LD_PRELOAD="${SCRIPT_DIR}/i2c_redirect.so" python3 "$@"
```

```bash
chmod +x ~/OPTIGA-Trust-M/optiga_run.sh

# Użycie
~/OPTIGA-Trust-M/optiga_run.sh provisioning.py
~/OPTIGA-Trust-M/optiga_run.sh diagnostics.py
```

---

## Konfiguracja systemd service (SSH agent)

Analogicznie do ATECC608A — docelowo service który ładuje klucz SSH z `0xE0F1` przez PKCS#11.

```ini
# ~/.config/systemd/user/optiga-ssh-agent.service
[Unit]
Description=OPTIGA Trust M SSH Agent
After=network.target

[Service]
Type=simple
Environment=LD_PRELOAD=/home/deploy/OPTIGA-Trust-M/i2c_redirect.so
ExecStart=/home/deploy/crypto-env/bin/python3 /home/deploy/OPTIGA-Trust-M/optiga_ssh_agent.py
Restart=on-failure

[Install]
WantedBy=default.target
```

---

## Znane problemy i rozwiązania

| Problem | Objaw | Rozwiązanie |
|---------|-------|-------------|
| BCM2837 clock stretching | chip nie odpowiada na hardware I2C | software I2C: `i2c-gpio` overlay na bus 3 |
| PAL hardcoded `/dev/i2c-1` | `Failed to connect` | LD_PRELOAD shim (`i2c_redirect.so`) |
| PAL GPIO conflict | `Failed to open gpio direction for writing!` | ostrzeżenie — ignorować, nie błąd krytyczny |
| RST floating | chip nie startuje (jeśli brak pull-up) | Adafruit breakout ma pull-up — OK bez lutowania |
| `interface=None` auto-probe | próbuje `libusb` → fail zanim dotrze do `i2c` | zawsze podawać `interface="i2c"` jawnie |
| aarch64 OS | zły `.so` by default w starszych wersjach | v1.5.1 ma `aarch64.so` — OK |
| `obj.read()` na key slocie | `TypeError: 'EnumType' object cannot be interpreted as an integer` | czytać klucz publiczny z PEM file, nie przez `obj.read()` |
| `lcso` nie zmienia się po keygen | `lcso=creation` mimo wygenerowanego klucza | normalnie — trzeba ręcznie uruchomić `lock_lcso.py` |

---

## Weryfikacja końcowa stanu chipa

```bash
# Chip widoczny na bus 3
i2cdetect -y 3
# Oczekiwany wynik: 0x30

# Połączenie Python z shimem
LD_PRELOAD=~/OPTIGA-Trust-M/i2c_redirect.so python3 -c "
import optigatrust as optiga
chip = optiga.Chip(interface='i2c')
print(chip.name)
print(chip.uid)
"
# Oczekiwany wynik:
# OPTIGA™ Trust M V1 (SLS32AIA010MH/S)
# UID(cim_id='cd', platform_id='16', ...)
```

---

## Następne kroki

| Krok | Co | Status |
|------|----|--------|
| SSH hardware key | `0xE0F1` → `optiga_ssh_agent.py` | ✅ działa |
| GPG Sign + Encrypt | `0xE0F2` / `0xE0F3` → GPG agent | 🔄 w toku |
| Lock lcso | `lock_lcso.py` → `operational` na 3 slotach | ⏳ po weryfikacji GPG |
| Attestation | podpisanie CSR kluczem `0xE0F0` | `optigatrust.csr` module |
| PKCS#11 | `pkcs11-tool --module liboptigatrust-pkcs11.so` | wymaga osobnego Infineon .so |
