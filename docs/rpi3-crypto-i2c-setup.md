# Raspberry Pi 3 - Dual Crypto Chip I2C Setup

## Sprzęt

| Moduł | Chip | Adres I2C | Bus | Typ I2C |
|-------|------|-----------|-----|---------|
| SparkFun Qwiic Cryptographic Co-Processor | ATECC608A | 0x60 | Bus 1 | Hardware |
| Adafruit STEMMA QT Infineon Trust M | OPTIGA Trust M SLS32AIA | 0x30 | Bus 3 | Software (bit-bang) |

## Podłączenie

### ATECC608A → Hardware I2C (Bus 1)

| STEMMA QT | Kolor | RPi Pin | GPIO |
|-----------|-------|---------|------|
| VCC | czerwony | Pin 1 | 3.3V |
| GND | czarny | Pin 6 | GND |
| SDA | niebieski | Pin 3 | GPIO2 (SDA1) |
| SCL | żółty | Pin 5 | GPIO3 (SCL1) |

### OPTIGA Trust M → Software I2C (Bus 3)

| STEMMA QT | Kolor | RPi Pin | GPIO |
|-----------|-------|---------|------|
| VCC | czerwony | Pin 17 | 3.3V |
| GND | czarny | Pin 14 | GND |
| SDA | niebieski | Pin 11 | GPIO17 |
| SCL | żółty | Pin 13 | GPIO27 |

## Konfiguracja /boot/firmware/config.txt

```ini
# Hardware I2C (bus 1) - ATECC608A
dtparam=i2c_arm=on
dtparam=i2c_arm_baudrate=100000

# Software I2C (bus 3) - OPTIGA Trust M
dtoverlay=i2c-gpio,bus=3,i2c_gpio_sda=17,i2c_gpio_scl=27,i2c_gpio_delay_us=50
```

Po zmianie zawsze `sudo reboot`.

## Weryfikacja

```bash
# ATECC608A na bus 1 (hardware I2C)
i2cdetect -y 1
# Oczekiwany wynik: 0x60

# OPTIGA Trust M na bus 3 (software I2C)
i2cdetect -y -r 3
# Oczekiwany wynik: 0x30
```

## Bug BCM2837 - Clock Stretching

Raspberry Pi 3 używa SoC Broadcom BCM2837, który ma znany bug z I2C clock stretching. Kiedy urządzenie slave potrzebuje więcej czasu na przetworzenie danych, trzyma linię SCL nisko ("rozciąga" zegar). BCM2837 nie obsługuje tego poprawnie i traci synchronizację.

Chipy kryptograficzne są szczególnie podatne — operacje kryptograficzne trwają dłużej niż typowa komunikacja I2C. OPTIGA Trust M z protokołem IFX I2C intensywnie używa clock stretching i dlatego nie działał na hardware I2C.

ATECC608A ma prostszą komunikację i działa na hardware I2C mimo bugu.

### Rozwiązanie: Software I2C (bit-bang)

Overlay `i2c-gpio` tworzy software'ową magistralę I2C, która poprawnie obsługuje clock stretching — czeka na faktyczny stan linii SCL zamiast zakładać timing.

### Raspberry Pi 5 - problem nie istnieje

Na Pi 5 I2C jest obsługiwane przez chip RP1 (southbridge zaprojektowany przez Raspberry Pi Foundation), nie przez Broadcom SoC. Bug clock stretching znika.

| | BCM2837 (Pi 3) | BCM2712 (Pi 5) |
|---|---|---|
| I2C clock stretching | bug | naprawione (RP1) |
| CPU | 4x Cortex-A53 @ 1.2GHz | 4x Cortex-A76 @ 2.4GHz |
| RAM | 1GB LPDDR2 | do 8GB LPDDR4X |
| PCIe | brak | PCIe 2.0 x4 |

## Python - środowisko

```bash
# Aktywacja venv (alias "crypto" w .bashrc)
crypto
# lub pełna komenda:
source ~/crypto-env/bin/activate

# Wyjście z venv
deactivate
```

### Zainstalowane pakiety

```bash
pip install cryptoauthlib   # biblioteka Microchip do ATECC608A
pip install smbus2           # niskopoziomowy dostęp I2C
```

Wymagane zależności systemowe:

```bash
sudo apt install cmake build-essential i2c-tools libhidapi-dev libudev-dev
```

### Dostęp do I2C bez sudo

```bash
sudo usermod -aG i2c deploy
logout
# zaloguj ponownie
```

## Test ATECC608A

```python
# test_atecc.py
from cryptoauthlib import *

cfg = cfg_ateccx08a_i2c_default()
cfg.cfg.atcai2c.bus = 1
cfg.cfg.atcai2c.address = 0xC0  # 8-bit adres (0x60 << 1)
cfg.devtype = 3                  # ATECC608A

status = atcab_init(cfg)
print(f"Init: {'OK' if status == 0 else f'BŁĄD {status}'}")

if status != 0:
    print("Nie udało się połączyć z chipem")
    exit(1)

# Numer seryjny (9 bajtów, unikalny)
serial = bytearray(9)
atcab_read_serial_number(serial)
print(f"Serial:  {serial.hex()}")

# Info o chipie
info = bytearray(4)
atcab_info(info)
print(f"Info:    {info.hex()}")

# Sprzętowy RNG
random = bytearray(32)
atcab_random(random)
print(f"Random:  {random.hex()}")

# SHA-256 sprzętowy
message = b"Hello from ATECC608A!"
digest = bytearray(32)
atcab_sha(len(message), message, digest)
print(f"SHA256:  {digest.hex()}")

atcab_release()
```

## Adresowanie I2C - 7-bit vs 8-bit

`i2cdetect` pokazuje adresy 7-bitowe (0x60), ale biblioteka `cryptoauthlib` oczekuje adresu 8-bitowego (0x60 << 1 = 0xC0). To częsta pułapka.

| Kontekst | ATECC608A | OPTIGA Trust M |
|----------|-----------|----------------|
| 7-bit (i2cdetect) | 0x60 | 0x30 |
| 8-bit (cryptoauthlib) | 0xC0 | 0x60 |

## STEMMA QT / Qwiic - notatki

- Złącze JST SH 1.0mm, 4-pinowe
- Kluczowane — nie da się włożyć odwrotnie
- Obsługuje hot-plug (podłączanie na żywo)
- Dwa złącza na płytce są równoległe (daisy-chain)
- Zamiana VCC z GND **może uszkodzić** moduł (ale kluczowanie chroni)
- Kabelki JST-SH są delikatne — mogą mieć przerwę w żyle, warto sprawdzić multimetrem

## Status chipów

- **ATECC608A**: Config zone i Data zone **odblokowane** (stan fabryczny). RNG zwraca dummy data (ffff0000...). Wymaga konfiguracji i zablokowania stref żeby w pełni działać.
- **OPTIGA Trust M**: Wykrywany na bus 3, dalsza konfiguracja do zrobienia.

## TODO

- [ ] Skonfigurować i zablokować config zone ATECC608A
- [ ] Zablokować data zone ATECC608A
- [ ] Przetestować generowanie kluczy ECC P-256
- [ ] Przetestować podpisy cyfrowe
- [ ] Skonfigurować komunikację z OPTIGA Trust M przez Python
- [ ] Rozważyć migrację na Raspberry Pi 5 (brak bugu clock stretching)
