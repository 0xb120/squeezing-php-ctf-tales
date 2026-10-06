#!/bin/sh
# The lab exercises a 2012 memory-corruption bug. Two knobs make the heap
# layout reproducible so the exploit is a lab exercise and not a research
# project (both are documented in README.md / WRITEUP.md):
#   * a fixed 8 MiB stack rlimit  -> fixed mmap_base
#   * setarch -R (ADDR_NO_RANDOMIZE) -> ASLR off for apache2 and every php-cgi
#     child it spawns
ulimit -s 8192
exec setarch -R apache2ctl -D FOREGROUND
