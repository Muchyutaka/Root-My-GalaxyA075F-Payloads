# e3q-S928BXXS6DZI1 target profile

Galaxy S24 Ultra international (`SM-S928B`), firmware `S928BXXS6DZI1`. The supplied `boot.img.lz4` decompresses to a v4 boot image whose raw ARM64 kernel banner is:

```text
Linux version 6.1.145-android14-11-33419968-abS928BXXS6DZI1
```

The supplied BL archive contains bootloader firmware only; it does not contain AP/system metadata. Therefore the exact Android build fingerprint is not asserted. The DZI1 profile was derived from the boot kernel's recovered BTF, kallsyms and raw Image, not by relabeling the DZF2 payload. See [`docs/SM-S928B-S928BXXS6DZI1.md`](../../../docs/SM-S928B-S928BXXS6DZI1.md).

Hardware testing has not been performed. Treat this profile as experimental and use only on the exact DZI1 kernel release above.
