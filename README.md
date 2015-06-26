ATJ2127 UPGRADE.HEX decryption
===

This extracts the files from ATJ2127 UPGRADE.HEX firmware upgrades, such as those used in the Sandisk Clip Sport.

You can compile this version on any 32-bit little-endian system (I think). Note that the code was automatically decompiled using a (custom) tool, and is very ugly.

Installation and setup
---

    make -f Makefile.native decrypt
	./decrypt firmware.hex


Debugging with the original binary
---
You don't need to do this if everything is working, but if something goes wrong you may wish to double check against the original decryption code. To do that you will need a little-endian MIPS32r2 compatible system. QEmu supports such a system with a command line such as:


    qemu-system-mipsel -M malta -m 256 -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -no-reboot -nographic -redir tcp:2222::22

Once you have your system running, download musl-libc (http://www.musl-libc.org/), compile and install it. You must do this manually as Debian does not include a statically-linked version of musl.

Bugs and TODOs:
---

* MBREC not correctly decoded.
* Code is hideous (bug) and needs to be cleaned up from its auto-generated state (todo)

