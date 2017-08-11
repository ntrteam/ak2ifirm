# AK2I firm generator for ntrboot
## Requirements
- boot11.bin
- ak2i_flash.bin
- boot9strap_ntr.firm

## Steps
```bash
python tool.py e boot11.bin extract_b498.bin
python tool.py d extract_b498.bin blowfish.bin
python tool.py x blowfish.bin boot9strap_ntr.firm ak2i_flash.bin ak2i_patch.bin
```

## References
- [Decrypt9WIP][d9wip] by d0k3
- [3dbrew FIRM][firm]
- [3dbrew bootloader][bootloader]
- [GBATEK][gbatek]

[d9wip]: https://github.com/d0k3/Decrypt9WIP
[firm]: https://www.3dbrew.org/wiki/FIRM
[bootloader]: https://www.3dbrew.org/wiki/Bootloader
[gbatek]: http://problemkaputt.de/gbatek.htm

## Credits
- [Normmatt][normmatt] - He knows everything and help to fix my mistake
- [TuxSH][tuxsh] - Made [firmtool][firmtool]
- [SciresM][sciresm] - He shared this flaw

[normmatt]: https://github.com/Normmatt
[sciresm]: https://github.com/SciresM/boot9strap
[tuxsh]: https://github.com/TuxSH/firmtool
[firmtool]: https://github.com/TuxSH/firmtool

