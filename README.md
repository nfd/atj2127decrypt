ATJ2127 UPGRADE.HEX decryption
===

This extracts the files from ATJ2127 UPGRADE.HEX firmware upgrades, such as those used in the Sandisk Clip Sport.

It requires a MIPS32-little endian system and MUSL libc.

Setup
---

If you don't have a native MIPS32 system, you can use qemu, e.g.:

    qemu-system-mipsel -M malta -m 256 -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -no-reboot -nographic -redir tcp:2222::22

Once you have your system running, download musl-libc (http://www.musl-libc.org/), compile and install it. You must do this manually as Debian does not include a statically-linked version of musl.

Usage:
---

    make
    decrypt UPGRADE.HEX

The files will be written to out/.


Bugs and TODOs:
---

* Remove MIPS-specific code.
* Remove MUSL dependency.
* MBREC not correctly decoded.

