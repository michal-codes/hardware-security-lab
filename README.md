# hardware-security-lab

Hands-on experiments with hardware security modules (Secure Elements) on Raspberry Pi.

Long-term goal: build a hardware root of trust for key management — from homelab prototype to commercial product.

## Current Setup

Raspberry Pi 3 Model B running two crypto chips simultaneously on separate I2C buses:

| Chip | Module | I2C Bus | Address | Type |
|------|--------|---------|---------|------|
| ATECC608A | SparkFun Qwiic Breakout | Bus 1 (hardware) | 0x60 | Microchip Secure Element |
| OPTIGA Trust M SLS32AIA | Adafruit STEMMA QT Breakout | Bus 3 (software) | 0x30 | Infineon Secure Element |

### Why two I2C buses?

Raspberry Pi 3's BCM2837 SoC has a [known bug with I2C clock stretching](https://github.com/raspberrypi/linux/issues/254). Crypto chips — especially OPTIGA Trust M with its IFX I2C protocol — rely heavily on clock stretching during cryptographic operations. The hardware I2C controller loses synchronization.

**Solution:** OPTIGA Trust M runs on a software (bit-banged) I2C bus via `i2c-gpio` kernel overlay, which correctly waits for the SCL line state. ATECC608A has simpler I2C communication and works fine on the hardware bus.

> This bug doesn't exist on Raspberry Pi 5 — its I2C is handled by the RP1 southbridge chip, not the Broadcom SoC.

## Hardware

- Raspberry Pi 3 Model B
- SparkFun Qwiic Cryptographic Co-Processor Breakout (ATECC608A)
- Adafruit STEMMA QT Infineon Trust M (OPTIGA Trust M SLS32AIA)
- 30× ATECC608B-SSHDA-T bare chips (for future experiments)
- STEMMA QT / Qwiic cables (JST-SH 1.0mm, 4-pin)

## Quick Start

### 1. Configure I2C

Add to `/boot/firmware/config.txt`:

```ini
# Hardware I2C (bus 1) - ATECC608A
dtparam=i2c_arm=on
dtparam=i2c_arm_baudrate=100000

# Software I2C (bus 3) - OPTIGA Trust M
dtoverlay=i2c-gpio,bus=3,i2c_gpio_sda=17,i2c_gpio_scl=27,i2c_gpio_delay_us=50
```

Reboot and verify:

```bash
i2cdetect -y 1       # should show 0x60
i2cdetect -y -r 3    # should show 0x30
```

### 2. Install dependencies

```bash
sudo apt install cmake build-essential i2c-tools libhidapi-dev libudev-dev
python3 -m venv ~/crypto-env
source ~/crypto-env/bin/activate
pip install cryptoauthlib smbus2
```

### 3. Test ATECC608A

```bash
python3 scripts/test_atecc.py
```

## Wiring

### ATECC608A → Bus 1 (Pin 3/5)

| Wire | RPi Pin | Function |
|------|---------|----------|
| Red | Pin 1 | 3.3V |
| Black | Pin 6 | GND |
| Blue | Pin 3 | SDA (GPIO2) |
| Yellow | Pin 5 | SCL (GPIO3) |

### OPTIGA Trust M → Bus 3 (Pin 11/13)

| Wire | RPi Pin | Function |
|------|---------|----------|
| Red | Pin 17 | 3.3V |
| Black | Pin 9 | GND |
| Blue | Pin 11 | SDA (GPIO17) |
| Yellow | Pin 13 | SCL (GPIO27) |

## Docs

- [RPi3 Crypto I2C Setup Guide](docs/rpi3-crypto-i2c-setup.md) — detailed setup notes, debugging log, BCM2837 clock stretching explained

## Status

- [x] I2C communication with ATECC608A
- [x] I2C communication with OPTIGA Trust M (via software I2C)
- [x] Dual chip setup on separate buses
- [x] Serial number, info, SHA-256 on ATECC608A
- [ ] Lock config zone on ATECC608A (enables real RNG and key generation)
- [ ] ECC P-256 key generation and ECDSA signing
- [ ] OPTIGA Trust M Python communication
- [ ] ATECC608B bare chip soldering and testing
- [ ] Signing service prototype (Web3Signer-compatible)

## Lessons Learned

1. **I2C address format matters** — `i2cdetect` shows 7-bit addresses (0x60), but `cryptoauthlib` expects 8-bit (0xC0 = 0x60 << 1)
2. **Clock stretching is real** — if `i2cdetect` shows nothing, try software I2C before blaming the chip
3. **Always use `-r` flag** for OPTIGA Trust M scanning — default "quick write" mode doesn't wake it up
4. **ATECC608A config zone must be locked** before RNG and crypto operations work properly — unlocked chip returns dummy data (ffff0000...)
5. **STEMMA QT cables can fail silently** — check continuity with multimeter if things don't work

## License

MIT
