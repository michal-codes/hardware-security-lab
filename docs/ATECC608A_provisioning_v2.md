# ATECC608A — Provisioning

> Dokument powstał na podstawie konfiguracji chipa Qwiic Cryptographic Co-Processor Breakout (SparkFun).
>
> **v2** — poprawki: błędne mapowanie bajtu I2C Address w Config Zone, niespójna wartość revision number, brakujące `atcab_release()`, komentarze do klucza tymczasowego i uproszczonego decode_key_config, wzmocnienie checklisty.

---

## Część 1: Checklist przed LOCK

> Chip po zablokowaniu Config Zone jest NIEODWRACALNIE skonfigurowany.
> Każdy krok poniżej wykonać **przed** wywołaniem `atcab_lock_config_zone()`.

## Zależności

```bash
python3 -m venv ~/crypto-env
source ~/crypto-env/bin/activate
pip install cryptoauthlib cryptography

python3 -c "from cryptoauthlib import ATCADeviceType; print(list(ATCADeviceType))"

# aliasy do .bashrc
alias crypto="source ~/crypto-env/bin/activate"
alias p='python3'
```

- `cryptoauthlib` — Python wrapper dla biblioteki Microchip, komunikacja z chipem przez I2C
- `cryptography` — weryfikacja podpisów ECC po stronie software (wymagane przed lockiem Data Zone, bo `atcab_verify_extern()` działa dopiero po locku)

---

## Faza 0: Połączenie i identyfikacja

```python
from cryptoauthlib import *
import time

cfg = cfg_ateccx08a_i2c_default()
cfg.cfg.atcai2c.bus = 1
cfg.cfg.atcai2c.address = 0xC0  # Qwiic domyślny (7-bit: 0x60)
cfg.devtype = 3                 # ATECC608A

status = atcab_init(cfg)
assert status == 0, f"Init failed: {status}"
time.sleep(0.1)
```

### Revision chipa

```python
rev = bytearray(4)
atcab_info(rev)
print(f"Revision: {rev.hex()}")
# ATECC608A: 00 00 60 02  → .hex() = "00006002"
# ATECC608B: 00 00 60 03  → .hex() = "00006003"
```

Oczekiwany wynik: `0000600x` gdzie x to `2` (608A) lub `3` (608B).

### Numer seryjny

```python
# Dedykowana funkcja — składa serial z dwóch bloków Config Zone
# (bajty 0-3 i 8-12, bo Microchip rozbija serial na dwa fragmenty)
# NIE używać config[0:9] — złapie bajty revision zamiast seriala
serial = bytearray(9)
atcab_read_serial_number(serial)
print(f"Serial: {serial.hex()}")
# Seriale ATECC zaczynają się od 01 23 (Microchip prefix)
```

Oczekiwany wynik: 9 bajtów, prefix `0123`. Zapisać serial — to jedyny identyfikator chipa po locku.

### Stan blokady

```python
# atcab_is_locked() w niektórych wersjach cryptoauthlib zwraca ATCA_BAD_PARAM
# Bezpieczna metoda — odczyt bajtów bezpośrednio z Config Zone:
# Bajt 87 = LockConfig (0x00 = LOCKED, 0x55 = UNLOCKED)
# Bajt 86 = LockValue / Data Zone (0x00 = LOCKED, 0x55 = UNLOCKED)

config = bytearray(128)
atcab_read_config_zone(config)

lock_config = config[87]
lock_data = config[86]
print(f"Config Zone: {'LOCKED' if lock_config == 0x00 else 'UNLOCKED'}")
print(f"Data Zone:   {'LOCKED' if lock_data == 0x00 else 'UNLOCKED'}")

atcab_release()
```

Oczekiwany wynik: obie zone UNLOCKED. Jeśli Config jest LOCKED — chip był już konfigurowany i dalsze kroki nie zadziałają.

---

## Faza 1: Odczyt i analiza fabrycznej konfiguracji

### Pełny dump Config Zone (128 bajtów)

```python
config = bytearray(128)
atcab_read_config_zone(config)

for i in range(0, 128, 16):
    hex_str = ' '.join(f'{b:02X}' for b in config[i:i+16])
    print(f"  [{i:3d}] {hex_str}")
```

Zapisać ten dump — to jedyna szansa na porównanie stanu "przed" i "po".

### Dekodowanie kluczowych sekcji

```python
# Numer seryjny jest rozbity na 2 bloki w Config Zone
sn_part1 = config[0:4]     # SN[0:3]
rev_num  = config[4:8]     # Revision (NIE serial!)
sn_part2 = config[8:13]    # SN[4:8]

print(f"SN part1:  {sn_part1.hex()}")
print(f"RevNum:    {rev_num.hex()}")
print(f"SN part2:  {sn_part2.hex()}")

# Adres I2C — bajt 16 (nie bajt 6!)
# Bajt 6 to wyższy bajt RevNum — przypadkowa koincydencja z wartością 0x60
i2c_addr = config[16]
print(f"I2C addr:  0x{i2c_addr:02X} (7-bit: 0x{i2c_addr >> 1:02X})")

# SlotConfig (bajty 20-51, po 2 bajty na slot, 16 slotów)
print("\nSlotConfig:")
for slot in range(16):
    offset = 20 + slot * 2
    val = config[offset] | (config[offset + 1] << 8)
    print(f"  Slot {slot:2d}: 0x{val:04X}")

# KeyConfig (bajty 96-127, po 2 bajty na slot, 16 slotów)
print("\nKeyConfig:")
for slot in range(16):
    offset = 96 + slot * 2
    val = config[offset] | (config[offset + 1] << 8)
    print(f"  Slot {slot:2d}: 0x{val:04X}")
```

---

## Faza 2: Weryfikacja konfiguracji slotów

### Wymagania dla SSH + GnuPG

| Slot | Przeznaczenie    | Wymagane możliwości                                |
|------|------------------|----------------------------------------------------|
| 0    | SSH Auth         | GenKey, Sign, klucz prywatny ECC P-256             |
| 1    | GnuPG Signing    | GenKey, Sign, klucz prywatny ECC P-256             |
| 2    | GnuPG Encryption | GenKey, ECDH (key agreement), klucz prywatny P-256 |
| 3    | Attestation      | GenKey, Sign, klucz prywatny ECC P-256             |

### Dekodowanie bitów SlotConfig

```python
def decode_slot_config(val):
    return {
        "ReadKey":       (val >> 0) & 0x0F,
        "NoMac":         (val >> 4) & 0x01,
        "LimitedUse":    (val >> 5) & 0x01,
        "EncryptRead":   (val >> 6) & 0x01,
        "IsSecret":      (val >> 7) & 0x01,
        "WriteKey":      (val >> 8) & 0x0F,
        "WriteConfig":   (val >> 12) & 0x0F,
    }

for slot in range(4):
    offset = 20 + slot * 2
    val = config[offset] | (config[offset + 1] << 8)
    decoded = decode_slot_config(val)
    print(f"\nSlot {slot} SlotConfig = 0x{val:04X}:")
    for k, v in decoded.items():
        print(f"  {k:15s} = {v}")
```

Warunki dla slotów 0-3:
- `IsSecret = 1` (klucz prywatny musi być tajny)
- `WriteConfig` pozwala na GenKey

### Dekodowanie bitów KeyConfig

```python
def decode_key_config(val):
    return {
        "Private":          (val >> 0) & 0x01,
        "PubInfo":          (val >> 1) & 0x01,
        "KeyType":          (val >> 2) & 0x07,  # 4 = P-256
        "Lockable":         (val >> 5) & 0x01,
        "ReqRandom":        (val >> 6) & 0x01,
        "ReqAuth":          (val >> 7) & 0x01,
        "AuthKey":          (val >> 8) & 0x0F,
        "IntrusionDisable": (val >> 12) & 0x01,
        "X509id":           (val >> 14) & 0x03,
    }

for slot in range(4):
    offset = 96 + slot * 2
    val = config[offset] | (config[offset + 1] << 8)
    decoded = decode_key_config(val)
    print(f"\nSlot {slot} KeyConfig = 0x{val:04X}:")
    for k, v in decoded.items():
        print(f"  {k:15s} = {v}")
```

Warunki dla slotów 0-3:
- `Private = 1` (slot przechowuje klucz prywatny)
- `PubInfo = 1` (można odczytać klucz publiczny)
- `KeyType = 4` (ECC P-256 NIST)
- `Lockable = 1` (slot może być zablokowany)

### Porównanie z oczekiwanymi wartościami

```python
# Fabryczne wartości ATECC608A Qwiic (SparkFun) dla slotów ECC P-256:
# KeyConfig = 0x0033 (Private=1, PubInfo=1, KeyType=P256, Lockable=1)
# SlotConfig = 0x2083 (slot 0), 0x2087 (slot 1), 0x208F (slot 2)
#
# UWAGA na endianness — cryptoauthlib przechowuje bajty w little-endian
# Wartość 0x0033 w Config Zone to bajty: 0x33, 0x00
# NIE mylić z 0x3300 — to inna konfiguracja!

EXPECTED_KEY_CONFIG = 0x0033

for slot in range(4):
    sc = config[20 + slot * 2] | (config[21 + slot * 2] << 8)
    kc = config[96 + slot * 2] | (config[97 + slot * 2] << 8)
    d = decode_key_config(kc)

    issues = []
    if d["Private"] != 1: issues.append("Private!=1")
    if d["PubInfo"] != 1: issues.append("PubInfo!=1")
    if d["KeyType"] != 4: issues.append("KeyType!=P256")

    status = "OK" if not issues else ', '.join(issues)
    print(f"Slot {slot}: SlotConfig=0x{sc:04X}  KeyConfig=0x{kc:04X}  {status}")
```

Typowy wynik fabrycznego chipa Qwiic:
```
Slot 0: SlotConfig=0x2083  KeyConfig=0x0033  OK
Slot 1: SlotConfig=0x2087  KeyConfig=0x0033  OK
Slot 2: SlotConfig=0x208F  KeyConfig=0x0033  OK
Slot 3: SlotConfig=0x8FC4  KeyConfig=0x001C  KeyType!=P256
```

Sloty 0-2 mają prawidłową konfigurację fabrycznie. Slot 3 wymaga zmiany jeśli ma służyć jako klucz ECC.

---

## Faza 3: Modyfikacja konfiguracji (tylko jeśli potrzebna)

### Zapis pojedynczych slotów

```python
# atcab_write_config_zone() w niektórych przypadkach zwraca sukces
# ale bajty się nie zapisują. Bezpieczniejsza metoda — zapis po wordach
# (4 bajty naraz) przez atcab_write_zone().
#
# Config Zone = zone 0
# Word = 4 bajty, Block = 32 bajty (8 wordów)
# Adresowanie: block, word offset wewnątrz bloku

# Przykład: zmiana SlotConfig i KeyConfig dla slotu 3
# SlotConfig slot 3 = bajty 26-27 (block=0, word=6)
# KeyConfig  slot 3 = bajty 102-103 (block=3, word=1)

# --- SlotConfig slot 3 ---
block = 0
offset = 6
word = bytearray(4)
atcab_read_zone(0, 0, block, offset, word, 4)
print(f"Bajty 24-27 PRZED: {word.hex()}")

# Zmiana tylko bajtów 26-27 (slot 3), bajty 24-25 (slot 2) bez zmian
word[2] = 0x83  # SlotConfig low byte (taki jak slot 0)
word[3] = 0x20  # SlotConfig high byte
status = atcab_write_zone(0, 0, block, offset, word, 4)
print(f"Write SlotConfig status: {status}")

# --- KeyConfig slot 3 ---
block = 3
offset = 1
word2 = bytearray(4)
atcab_read_zone(0, 0, block, offset, word2, 4)
print(f"Bajty 100-103 PRZED: {word2.hex()}")

# Zmiana tylko bajtów 102-103 (slot 3), bajty 100-101 (slot 2) bez zmian
word2[2] = 0x33  # KeyConfig low byte (P-256, Private, PubInfo)
word2[3] = 0x00  # KeyConfig high byte
status = atcab_write_zone(0, 0, block, offset, word2, 4)
print(f"Write KeyConfig status: {status}")

atcab_release()
```

Zapis do Config Zone można powtarzać wielokrotnie dopóki zone jest UNLOCKED. Lock jest nieodwracalny, zapis — nie.

### Weryfikacja zapisu (read-back)

```python
verify1 = bytearray(4)
atcab_read_zone(0, 0, 0, 6, verify1, 4)
print(f"SlotConfig read-back: {verify1.hex()}")
print(f"Bajty 26-27: 0x{verify1[3]:02X}{verify1[2]:02X} (oczekiwane: 0x2083)")

verify2 = bytearray(4)
atcab_read_zone(0, 0, 3, 1, verify2, 4)
print(f"KeyConfig read-back:  {verify2.hex()}")
print(f"Bajty 102-103: 0x{verify2[3]:02X}{verify2[2]:02X} (oczekiwane: 0x0033)")
```

Jeśli read-back się nie zgadza — ZATRZYMAJ SIĘ. Nie blokować chipa z błędną konfiguracją.

---

## Faza 4: Testy funkcjonalne (przed lock)

### Test RNG

```python
random = bytearray(32)
atcab_random(random)
print(f"Random (pre-lock): {random.hex()}")
# Przed lockiem Config Zone RNG zwraca wzorzec
# np. ffff0000ffff0000... — to NORMALNE
# Prawdziwy RNG zaczyna działać dopiero po lock Config Zone
```

### Test zapisu/odczytu danych

```python
# Test na slocie 8 (typowo dane, nie klucze)
test_data = bytearray(32)
for i in range(32):
    test_data[i] = i & 0xFF

status = atcab_write_zone(2, 8, 0, 0, test_data, 32)  # zone=2 (data)
if status == 0:
    read_back = bytearray(32)
    status = atcab_read_zone(2, 8, 0, 0, read_back, 32)
    if status == 0 and read_back == test_data:
        print("Data write/read test passed")
    else:
        print(f"Data read-back mismatch or read failed: {status}")
else:
    print(f"Data write test: status {status} (może być OK zależnie od konfiguracji slotu)")
```

---

## Faza 5: Podsumowanie przed decyzją

```python
from cryptoauthlib import *
import time

cfg = cfg_ateccx08a_i2c_default()
cfg.cfg.atcai2c.bus = 1
cfg.cfg.atcai2c.address = 0xC0
cfg.devtype = 3

status = atcab_init(cfg)
assert status == 0, f"Init failed: {status}"
time.sleep(0.1)

# Uproszczona wersja decode_key_config — sprawdza tylko warunki wymagane przed lock.
# Pełna wersja z wszystkimi polami (ReqRandom, ReqAuth, AuthKey, X509id itd.) — patrz Faza 2.
def decode_key_config(val):
    return {
        "Private":   (val >> 0) & 0x01,
        "PubInfo":   (val >> 1) & 0x01,
        "KeyType":   (val >> 2) & 0x07,
        "Lockable":  (val >> 5) & 0x01,
    }

config = bytearray(128)
atcab_read_config_zone(config)

serial = bytearray(9)
atcab_read_serial_number(serial)
print(f"Serial: {serial.hex()}")

rev = bytearray(4)
atcab_info(rev)
print(f"Revision: {rev.hex()}")

print(f"Config: {'LOCKED' if config[87] == 0x00 else 'UNLOCKED'}")
print(f"Data:   {'LOCKED' if config[86] == 0x00 else 'UNLOCKED'}")

print(f"\n{'Slot':<6} {'Nazwa':<20} {'SlotConfig':<14} {'KeyConfig':<14} {'Status'}")
print("-" * 60)

names = {0: "SSH Auth", 1: "GPG Sign", 2: "GPG Encrypt", 3: "Attestation"}
all_ok = True

for slot in range(4):
    sc = config[20 + slot * 2] | (config[21 + slot * 2] << 8)
    kc = config[96 + slot * 2] | (config[97 + slot * 2] << 8)
    d = decode_key_config(kc)
    issues = []
    if d["Private"] != 1: issues.append("Private!=1")
    if d["PubInfo"] != 1: issues.append("PubInfo!=1")
    if d["KeyType"] != 4: issues.append("KeyType!=P256")
    if issues: all_ok = False
    s = "OK" if not issues else ', '.join(issues)
    print(f"{slot:<6} {names[slot]:<20} 0x{sc:04X}        0x{kc:04X}        {s}")

print()
if all_ok:
    print("KONFIGURACJA OK")
else:
    print("KONFIGURACJA MA PROBLEMY — NIE BLOKOWAC")

atcab_release()
```

---

## Lista kontrolna

Przed wywołaniem `atcab_lock_config_zone()`:

1. ☐ Serial chipa zapisany
2. ☐ Revision odpowiada ATECC608A (`00006002`) lub 608B (`00006003`)
3. ☐ Config Zone jest UNLOCKED
4. ☐ SlotConfig dla slotów 0-3 pozwala na GenKey + Sign
5. ☐ KeyConfig dla slotów 0-3: Private=1, PubInfo=1, KeyType=P256
6. ☐ Read-back konfiguracji zgadza się z zamierzoną
7. ☐ Backup hex dump Config Zone zapisany
8. ☐ **[BLOKER]** Chip testowy (nie jedyny egzemplarz) — bez tego punktu nie kontynuować

Wszystkie odpowiedzi muszą być TAK.

---

## Po locku Config Zone: natychmiastowa weryfikacja

```python
from cryptoauthlib import *
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
import hashlib
import time

cfg = cfg_ateccx08a_i2c_default()
cfg.cfg.atcai2c.bus = 1
cfg.cfg.atcai2c.address = 0xC0
cfg.devtype = 3

status = atcab_init(cfg)
assert status == 0, f"Init failed: {status}"
time.sleep(0.1)

# 1. Potwierdzenie locka
config = bytearray(128)
atcab_read_config_zone(config)
assert config[87] == 0x00, "Config Zone should be locked!"
print("Config Zone: LOCKED")

# 2. Test RNG (po locku powinien zwracać losowe dane)
random = bytearray(32)
atcab_random(random)
print(f"RNG: {random.hex()}")
assert len(set(random)) > 4, "Podejrzanie niska entropia"

# 3. GenKey + Sign — UWAGA: to klucz TYMCZASOWY tylko do weryfikacji komunikacji z chipem.
#    Finalnych kluczy nie generować tutaj — patrz Skrypt 2.
#    Każde wywołanie atcab_genkey() nadpisuje poprzedni klucz w slocie.
pub = bytearray(64)
atcab_genkey(0, pub)
print(f"Public key slot 0 (tymczasowy): {pub.hex()[:32]}...")

digest = hashlib.sha256(b"test").digest()
sig = bytearray(64)
atcab_sign(0, bytearray(digest), sig)
print(f"Signature: {sig.hex()[:32]}...")

# 4. Weryfikacja programowa (atcab_verify_extern wymaga locked Data Zone)
x = int.from_bytes(pub[0:32], 'big')
y = int.from_bytes(pub[32:64], 'big')
pub_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

r = int.from_bytes(sig[0:32], 'big')
s = int.from_bytes(sig[32:64], 'big')
der_sig = utils.encode_dss_signature(r, s)

pub_key.verify(der_sig, b"test", ec.ECDSA(hashes.SHA256()))
print("GenKey + Sign + Verify OK")

atcab_release()
```

---

## Uwagi

- **Jeden chip = jedna szansa.** Fabryczny ATECC608A kosztuje kilka dolarów. Mieć zapasowy na testy.
- **Dokumentacja Microchip** to jedyne źródło prawdy o bitach SlotConfig/KeyConfig.
- **`atcab_sign()` przyjmuje 32-bajtowy digest** (SHA-256), nie surową wiadomość. Zawsze hashować przed podpisaniem.
- **Po locku Config Zone, przed lockiem Data Zone** — to jedyny moment na generowanie kluczy (`atcab_genkey()`). Każde wywołanie GenKey nadpisuje poprzedni klucz w slocie nowym losowym. Po locku Data Zone klucze prywatne zamrożone na zawsze.
- **`atcab_verify_extern` wymaga locked Data Zone.** Do weryfikacji podpisów przed lockiem Data Zone używać biblioteki `cryptography` (weryfikacja programowa poza chipem).
- **`atcab_is_locked()` może zwracać ATCA_BAD_PARAM** w niektórych wersjach cryptoauthlib. Bezpieczna alternatywa — odczyt bajtów 86-87 z Config Zone.
- **`atcab_write_config_zone()` może nie zapisać wszystkich bajtów** mimo zwrócenia sukcesu. Bezpieczniejsza metoda — `atcab_write_zone()` po 4 bajty z read-back po każdym zapisie.
- **Endianness** — wartości w Config Zone są little-endian. KeyConfig `0x0033` w pamięci to bajty `0x33, 0x00`. Nie mylić z `0x3300`.
- **Qwiic I2C** — przy kablach dłuższych niż ~20 cm dodać pull-upy 4.7kΩ na SDA/SCL.
- **Sloty ECC P-256** — ATECC608A ma maksymalnie 6 slotów na klucze prywatne ECC (0-4 i 7). Sloty 8-15 to dane/klucze symetryczne.

---

# Część 2: Analiza Config Zone i generowanie kluczy

> Wykonywać po `atcab_lock_config_zone()`. Dokumentacja zmian, generowanie finalnych kluczy, lock Data Zone.

---

## Skrypt 1: Init + Info + Config Zone dump

```python
from cryptoauthlib import *
import time

cfg = cfg_ateccx08a_i2c_default()
cfg.cfg.atcai2c.bus = 1
cfg.cfg.atcai2c.address = 0xC0  # Qwiic domyślny (7-bit: 0x60)
cfg.devtype = 3                 # ATECC608A

status = atcab_init(cfg)
assert status == 0, f"Init failed: {status}"
time.sleep(0.1)

rev = bytearray(4)
atcab_info(rev)
print(f"Revision: {rev.hex()}")
# ATECC608A: 00 00 60 02  → .hex() = "00006002"
# ATECC608B: 00 00 60 03  → .hex() = "00006003"

config = bytearray(128)
atcab_read_config_zone(config)

for i in range(0, 128, 16):
    hex_str = ' '.join(f'{b:02X}' for b in config[i:i+16])
    print(f"  [{i:3d}] {hex_str}")

atcab_release()
```

### Uwagi
- `address = 0xC0` — 8-bit zapis adresu; 7-bit to `0x60` (widoczny w `i2cdetect`)
- `devtype = 3` — enum dla ATECC608A
- `time.sleep(0.1)` po `atcab_init()` — wymagane dla stabilności komunikacji
- Revision `00006002` = ATECC608A, `00006003` = ATECC608B

---

## `atcab_info()` — identyfikacja chipa

Komenda `INFO` wysyłana przez I2C. Zwraca 4 bajty z **revision number** układu.
Typowy output dla ATECC608A: `.hex()` → `"00006002"` (bajty: `00 00 60 02`)

Zastosowanie:
- Sprawdzenie czy chip odpowiada (I2C działa)
- Identyfikacja wersji krzemu

---

## Config Zone — mapa 128 bajtów

```
Bytes [0-3]    — Serial Number część 1: SN[0:3]    (read-only, fabryczne)
Bytes [4-7]    — Revision Number                   (read-only, fabryczne)
Bytes [8-12]   — Serial Number część 2: SN[4:8]    (read-only, fabryczne)
Bytes [13-15]  — I2C Enable, reserved
Byte  [16]     — I2C Address (domyślnie 0xC0 = 8-bit; 7-bit: 0x60)
Bytes [17-19]  — Count Match, Chip Mode
Bytes [20-51]  — SlotConfig     (16 slotów × 2 bajty)
Bytes [52-53]  — Counter[0]
Bytes [54-55]  — Counter[1]
Bytes [56-57]  — UseLock, VolatileKey
Bytes [58-83]  — SecureBoot, KDF, reserved
Bytes [84-85]  — UserExtra, Selector
Bytes [86-87]  — LockValue, LockConfig
Bytes [88-89]  — SlotLocked     (bitmapa 16 slotów)
Bytes [90-91]  — ChipOptions
Bytes [92-95]  — reserved
Bytes [96-127] — KeyConfig      (16 slotów × 2 bajty)
```

Realnie konfigurowalne przez użytkownika: **SlotConfig + KeyConfig = 64 bajty**.
Reszta to metadane, adresy i locki.

---

## I2C Address w Config Zone

```
i2cdetect -y 1
...
60: 60
...
```

Chip widoczny pod adresem 7-bit `0x60`. Adres pochodzi z bajtu `[16]` Config Zone = `0xC0` (format 8-bit używany przez cryptoauthlib).

```
[  0] 01 23 FE 1E 00 00 60 02 CB C3 C0 8F EE C1 39 00
       ^^^^^^^^^^^^ ^^^^^^^^^^^^                       
       SN[0:3]      RevNum (bajty 4-7)
                             ^^
                             To bajt 6 = wyższy bajt RevNum (0x60)
                             Przypadkowa koincydencja z adresem I2C — NIE mylić!

[ 16] C0 00 00 00 83 20 87 20 ...
       ^^
       I2C Address = 0xC0 (8-bit) → 7-bit: 0x60
```

**Pułapka:** bajt `[6]` dumpa ma wartość `0x60` (wyższy bajt Revision Number `0x00006002`), co wygląda identycznie jak adres I2C. Adres I2C to zawsze `config[16]`.

Po locku adres jest niezmienny. Gdyby przed lockiem `config[16]` ustawiono na np. `0x6A` — chip odpowiadałby pod `0x35` (7-bit).

---

## Analiza zmian: przed → po lock zones

### Dump przed lockiem
```
[  0] 01 23 FE 1E 00 00 60 02 CB C3 C0 8F EE C1 39 00
[ 16] C0 00 00 00 83 20 87 20 8F 20 C4 8F 8F 8F 8F 8F
[ 32] 9F 8F AF 8F 00 00 00 00 00 00 00 00 00 00 00 00
[ 48] 00 00 AF 8F FF FF FF FF 00 00 00 00 FF FF FF FF
[ 64] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[ 80] 00 00 00 00 00 00 55 55 FF FF 00 00 00 00 00 00
[ 96] 33 00 33 00 33 00 1C 00 1C 00 1C 00 1C 00 1C 00
[112] 3C 00 3C 00 3C 00 3C 00 3C 00 3C 00 3C 00 1C 00
```

### Dump po lock zones
```
[  0] 01 23 FE 1E 00 00 60 02 CB C3 C0 8F EE C1 39 00
[ 16] C0 00 00 00 83 20 87 20 8F 20 83 20 8F 8F 8F 8F
[ 32] 9F 8F AF 8F 00 00 00 00 00 00 00 00 00 00 00 00
[ 48] 00 00 AF 8F FF FF FF FF 00 00 00 00 FF FF FF FF
[ 64] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[ 80] 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00
[ 96] 33 00 33 00 33 00 33 00 1C 00 1C 00 1C 00 1C 00
[112] 3C 00 3C 00 3C 00 3C 00 3C 00 3C 00 3C 00 1C 00
```

### Różnice (3 zmiany)

| Bytes | Przed | Po | Znaczenie |
|-------|-------|----|-----------|
| [26-27] | `C4 8F` | `83 20` | SlotConfig slot 3 — zmieniony na ECC P256 |
| [86-87] | `55 55` | `00 00` | **Lock bytes** — `55`=unlocked → `00`=locked |
| [102-103] | `1C 00` | `33 00` | KeyConfig slot 3 — `Private=1`, `Lockable=1` |

**Sekwencja:** skrypt najpierw zmodyfikował slot 3, potem wykonał `atcab_lock_config_zone()` + `atcab_lock_data_zone()`.

### Lock bytes — co się zmienia po lock_config_zone()

`0x55` = `01010101` binarnie — domyślna wartość "nieskonfigurowane" w EEPROM Microchip (nie `0xFF` jak typowa flash).
`0x00` = locked. Chip sprawdza te bajty przy każdej operacji write — jeśli nie są `0x55`, odrzuca żądanie.

**Po locku Config Zone:**
- Config Zone staje się read-only na poziomie hardware — nieodwracalne
- `atcab_genkey()` staje się możliwy (chip blokuje generowanie kluczy dopóki config nie jest finalny)
- SlotConfig/KeyConfig zaczyna być egzekwowane: `IsSecret`, `RequireAuth`, `EncryptRead` wchodzą w życie
- `atcab_lock_data_zone()` staje się możliwy (chip wymaga tej kolejności)

---

## Do czego służy dump zablokowanego chipa

**Dokumentacja i audyt**
- Dowód konfiguracji produkcyjnej zarchiwizowany w git
- Podstawa do audytu bezpieczeństwa bez fizycznego dostępu do chipa

**Weryfikacja w field**
- Porównanie z nieznanym chipem: `assert dump == expected_dump`
- Automatyzacja w testach produkcyjnych

**Debugging**
- Weryfikacja że SlotConfig/KeyConfig faktycznie zawiera to co zakładamy
- Diagnoza błędów `ATCA_EXECUTION_ERROR`

**Klonowanie konfiguracji**
- Wzorzec do programowania kolejnych partii chipów
- Historia `przed`/`po` pozwala odtworzyć dokładną sekwencję operacji

---

## Skrypt 2: Generowanie kluczy + Lock Data Zone

Wykonywany **po** `lock_config_zone()`, **przed** `lock_data_zone()`.
To jedyny moment na `atcab_genkey()` — po locku Data Zone klucze prywatne zamrożone na zawsze.

```python
from cryptoauthlib import *
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
import hashlib
import time
import struct
import base64
import json

cfg = cfg_ateccx08a_i2c_default()
cfg.cfg.atcai2c.bus = 1
cfg.cfg.atcai2c.address = 0xC0
cfg.devtype = 3

status = atcab_init(cfg)
assert status == 0, f"Init failed: {status}"
time.sleep(0.1)

# Sprawdź stan
config = bytearray(128)
atcab_read_config_zone(config)
assert config[87] == 0x00, "Config Zone must be LOCKED first!"
print(f"Config Zone: LOCKED")
print(f"Data Zone:   {'LOCKED' if config[86] == 0x00 else 'UNLOCKED'}")

if config[86] == 0x00:
    print("Data Zone juz zablokowana — klucze sa zamrozone.")
    print("Nie mozna generowac nowych kluczy.")
    atcab_release()
    exit()

serial = bytearray(9)
atcab_read_serial_number(serial)
serial_hex = serial.hex()
print(f"Serial: {serial_hex}")

# ============================================
# KROK 1: Generowanie finalnych kluczy
# ============================================
print("\n" + "=" * 50)
print("GENEROWANIE FINALNYCH KLUCZY ECC P-256")
print("=" * 50)

slots = {
    0: "SSH_Auth",
    1: "GPG_Sign",
    2: "GPG_Encrypt",
    3: "Attestation",
}

public_keys = {}

for slot, name in slots.items():
    pub = bytearray(64)
    status = atcab_genkey(slot, pub)
    assert status == 0, f"GenKey slot {slot} failed: {status}"
    public_keys[slot] = bytes(pub)
    print(f"  Slot {slot} ({name}): {pub.hex()[:40]}...")

# ============================================
# KROK 2: Weryfikacja — Sign + Verify na kazdym slocie
# ============================================
print("\n" + "=" * 50)
print("WERYFIKACJA SIGN + VERIFY")
print("=" * 50)

test_msg = b"ATECC608A final key verification"
digest = hashlib.sha256(test_msg).digest()

for slot, name in slots.items():
    sig = bytearray(64)
    status = atcab_sign(slot, bytearray(digest), sig)
    assert status == 0, f"Sign slot {slot} failed: {status}"

    pub = public_keys[slot]
    x = int.from_bytes(pub[0:32], 'big')
    y = int.from_bytes(pub[32:64], 'big')
    pub_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

    r = int.from_bytes(sig[0:32], 'big')
    s = int.from_bytes(sig[32:64], 'big')
    der_sig = utils.encode_dss_signature(r, s)

    pub_key.verify(der_sig, test_msg, ec.ECDSA(hashes.SHA256()))
    print(f"  Slot {slot} ({name}): Sign + Verify OK")

# ============================================
# KROK 3: Zapis kluczy publicznych
# ============================================
print("\n" + "=" * 50)
print("ZAPIS KLUCZY PUBLICZNYCH")
print("=" * 50)

with open(f"atecc_{serial_hex}_pubkeys.json", "w") as f:
    data = {
        "serial": serial_hex,
        "chip": "ATECC608A",
        "slots": {}
    }
    for slot, name in slots.items():
        pub = public_keys[slot]
        data["slots"][str(slot)] = {
            "name": name,
            "public_key_hex": pub.hex(),
            "x": pub[0:32].hex(),
            "y": pub[32:64].hex(),
        }
    json.dump(data, f, indent=2)
    print(f"  JSON: atecc_{serial_hex}_pubkeys.json")

# Format SSH (slot 0)
def pubkey_to_ssh(raw_pub, comment=""):
    curve = b"nistp256"
    point = b'\x04' + raw_pub
    key_data = (
        struct.pack(">I", 19) + b"ecdsa-sha2-nistp256" +
        struct.pack(">I", 8) + curve +
        struct.pack(">I", len(point)) + point
    )
    b64 = base64.b64encode(key_data).decode()
    return f"ecdsa-sha2-nistp256 {b64} {comment}"

ssh_key = pubkey_to_ssh(public_keys[0], f"atecc608a-{serial_hex}-slot0")
with open(f"atecc_{serial_hex}_ssh.pub", "w") as f:
    f.write(ssh_key + "\n")
    print(f"  SSH:  atecc_{serial_hex}_ssh.pub")

# PEM (wszystkie sloty)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

for slot, name in slots.items():
    pub = public_keys[slot]
    x = int.from_bytes(pub[0:32], 'big')
    y = int.from_bytes(pub[32:64], 'big')
    pub_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    filename = f"atecc_{serial_hex}_slot{slot}_{name}.pem"
    with open(filename, "w") as f:
        f.write(pem.decode())
    print(f"  PEM:  {filename}")

# ============================================
# KROK 4: Lock Data Zone
# ============================================
print("\n" + "=" * 50)
print("LOCK DATA ZONE")
print("=" * 50)
print("Po zablokowaniu klucze prywatne sa zamrozone NA ZAWSZE.")
print()
response = input("Zablokowac Data Zone? (wpisz 'TAK'): ")

if response == "TAK":
    status = atcab_lock_data_zone()
    assert status == 0, f"Lock data failed: {status}"
    print("Data Zone: LOCKED")

    config2 = bytearray(128)
    atcab_read_config_zone(config2)
    assert config2[86] == 0x00, "Data Zone lock verification failed!"
    print("Lock zweryfikowany.")

    sig = bytearray(64)
    atcab_sign(0, bytearray(digest), sig)
    pub = public_keys[0]
    x = int.from_bytes(pub[0:32], 'big')
    y = int.from_bytes(pub[32:64], 'big')
    pub_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    r = int.from_bytes(sig[0:32], 'big')
    s = int.from_bytes(sig[32:64], 'big')
    der_sig = utils.encode_dss_signature(r, s)
    pub_key.verify(der_sig, test_msg, ec.ECDSA(hashes.SHA256()))
    print("Sign + Verify po locku: OK")
else:
    print("Data Zone NIE zablokowana.")
    print("Mozesz jeszcze generowac nowe klucze.")

print("\n" + "=" * 50)
print("GOTOWE")
print("=" * 50)

atcab_release()
```

### Co robi skrypt krok po kroku

1. Sprawdza że Config jest LOCKED, Data jest UNLOCKED — jedyne poprawne okno
2. Dla slotów 0-3 wywołuje `atcab_genkey()` — generuje losowe klucze ECC P-256
3. Na każdym slocie robi Sign + software Verify — potwierdza że klucz działa przed lockiem
4. Zapisuje klucze publiczne w 3 formatach: JSON (backup), `.pub` (SSH dla slot 0), `.pem` (każdy slot)
5. Pyta o potwierdzenie przed `atcab_lock_data_zone()` — guard przed przypadkowym lockiem
6. Po locku robi jeszcze jeden Sign + Verify jako dowód że chip działa finalnie

### Uwagi
- Software verify przez `cryptography` — `atcab_verify_extern()` wymaga locked Data Zone, więc przed lockiem trzeba weryfikować poza chipem
- `atcab_sign()` przyjmuje 32-bajtowy SHA-256 digest, nie surową wiadomość
- Każde wywołanie `atcab_genkey()` nadpisuje poprzedni klucz — wywoływać tylko raz na slot finalnie
