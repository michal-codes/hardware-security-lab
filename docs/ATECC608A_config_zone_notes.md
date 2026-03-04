# ATECC608A — Config Zone: Analiza i Notatki

## `atcab_info()` — identyfikacja chipa

```python
info = bytearray(4)
status = atcab_info(info)
print(f"Info: {info.hex()}")
```

Komenda `INFO` wysyłana przez I2C. Zwraca 4 bajty z **revision number** układu.  
Typowy output dla ATECC608A: `00600200`

Zastosowanie:
- Sprawdzenie czy chip odpowiada (I2C działa)
- Identyfikacja wersji krzemu

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
# ATECC608A: 00 00 60 02
# ATECC608B: 00 00 60 03


config = bytearray(128)
atcab_read_config_zone(config)

for i in range(0, 128, 16):
    hex_str = ' '.join(f'{b:02X}' for b in config[i:i+16])
    print(f"  [{i:3d}] {hex_str}")
```

---

## Config Zone — mapa 128 bajtów

```
Bytes [0-12]   — Serial Number + Revision    (read-only, fabryczne)
Bytes [13-15]  — I2C Enable, reserved
Byte  [16]     — I2C Address (domyślnie 0x60)
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

---

## I2C Address w Config Zone

```
i2cdetect -y 1
...
60: 60
...
```

Byte `[6]` dumpa = `0x60` — bezpośrednia korelacja z adresem widocznym w `i2cdetect`.

```
[  0] 01 23 FE 1E 00 00 [60] 02 ...
```

- Bytes `[0-3]` + `[8-12]` + `[13]` — numer seryjny (rozrzucony)
- Bytes `[4-5]` — reserved
- Byte `[6]` = `0x60` — adres I2C
- Byte `[7]` = `0x02` — OTP mode

Po locku adres jest niezmienny. Gdyby przed lockiem byte `[6]` ustawiono na np. `0x35` — chip odpowiadałby pod `0x35`.

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
