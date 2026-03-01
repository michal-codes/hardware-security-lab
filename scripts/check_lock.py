# check_lock.py
from cryptoauthlib import *

cfg = cfg_ateccx08a_i2c_default()
cfg.cfg.atcai2c.bus = 1
cfg.cfg.atcai2c.address = 0xC0
cfg.devtype = 3
atcab_init(cfg)

# Odczytaj config zone (128 bajtów)
config = bytearray(128)
status = atcab_read_config_zone(config)
print(f"Read config status: {status}")

if status == 0:
    # Bajt 87 = LockConfig, bajt 86 = LockValue (Data zone)
    # 0x55 = odblokowany, 0x00 = zablokowany
    print(f"Config zone locked: {config[87] != 0x55}")
    print(f"Data zone locked:   {config[86] != 0x55}")
    print(f"Raw lock bytes: config={hex(config[87])}, data={hex(config[86])}")

atcab_release()
