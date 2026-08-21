# cdbackup
![cdbackup logo](/logo.png)

Backs up/restores (or deletes) `/title/00000001/00000002/data/cdb.vff` to/from your SD card as `cdbackup.vff`. That's all.

This version is modded and lets you export Wii Message Board images and also Wii Message Board data transferred to the SD with the Wii Menu

## Controller support

Optional builds support the Wii U GamePad through [libwiidrc](https://github.com/FIX94/libwiidrc), the Wii U Pro Controller through [libwupc](https://github.com/FIX94/libwupc), and USB DualShock 3 controllers through [libsicksaxis](https://github.com/xerpi/libsicksaxis). Wii Remote, Classic Controller, GameCube controller, and USB keyboard input remain supported.

Build the pinned controller libraries and enable all controller backends with:

```sh
./scripts/build_controller_portlibs.sh
make WITH_WIIDRC=1 WITH_WUPC=1 WITH_SICKSAXIS=1
```

The GamePad backend requires the Wii U Virtual Console environment and a compatible patched `fw.img`. DualShock 3 USB input requires IOS58.
