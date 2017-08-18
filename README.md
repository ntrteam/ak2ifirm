# AK2I firm generator for ntrboot

## Requirements
- boot11.bin
- ak2i_flash.bin
- boot9strap_ntr.firm
- modified decrypt9wip. require flash `0xA0000` instead `0x20000`

## Steps

```bash
pip install git+https://github.com/d3m3vilurr/ak2ifirm.git
ak2ifirm blowfish boot11.bin
ak2ifirm inject blowfish.bin boot9strap_ntr.firm ak2i_flash.bin
```

## References
- [Decrypt9WIP][d9wip]
- [3dbrew FIRM][firm]
- [3dbrew bootloader][bootloader]
- [GBATEK][gbatek]
- [33.5c3][33_5c3]

[d9wip]: https://github.com/d0k3/Decrypt9WIP
[firm]: https://www.3dbrew.org/wiki/FIRM
[bootloader]: https://www.3dbrew.org/wiki/Bootloader
[gbatek]: http://problemkaputt.de/gbatek.htm
[33_5c3]: https://sciresm.github.io/33-and-a-half-c3

## Credits
- [Normmatt][normmatt] - He knows everything and help to fix my mistake
- [d0k3][d0k3] - Made [Decrypt9WIP][d9wip] and [GodMode9][gm9]
- [TuxSH][tuxsh] - Made [firmtool][firmtool]
- [SciresM][sciresm] - Shared this flaw & implemented [boot9strap][b9s]
- And all others

[normmatt]: https://github.com/Normmatt
[sciresm]: https://github.com/SciresM/boot9strap
[tuxsh]: https://github.com/TuxSH/firmtool
[d0k3]: https://github.com/d0k3
[firmtool]: https://github.com/TuxSH/firmtool
[b9s]: https://github.com/SciresM/boot9strap
[gm9]: https://github.com/d0k3/GodMode9
