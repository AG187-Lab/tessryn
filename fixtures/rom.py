"""Original 16-bit reset-ROM test fixtures; these are not Tessryn kernel code.

QEMU maps the 64 KiB ROM at the top of the address space. At x86 reset the
processor executes its last 16 bytes. A far jump selects segment F000, offset
0000 (the conventional low BIOS alias). No bootloader, RAM, stack, interrupt,
disk, firmware service, kernel, or GPU is involved.
"""

MARKER = b"TESSRYN_G03_FIXTURE_PASS\n"


def make_rom(*, hang: bool = False) -> bytes:
    code = bytearray(b"\xfa")  # cli: fixtures have no interrupt handlers.
    if not hang:
        for character in MARKER:
            # mov al, imm8; out 0xe9, al. QEMU isa-debugcon captures the bytes.
            code.extend((0xB0, character, 0xE6, 0xE9))
        # mov al, 0x10; out 0xf4, al. isa-debug-exit returns (0x10 << 1) | 1.
        code.extend(b"\xb0\x10\xe6\xf4")
    code.extend(b"\xf4\xeb\xfd")  # hlt; jmp back to hlt, also after exit.
    image = bytearray(b"\xff" * 65536)
    image[: len(code)] = code
    image[65520:65525] = b"\xea\x00\x00\x00\xf0"  # jmp far F000:0000.
    return bytes(image)
