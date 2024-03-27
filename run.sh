#!/bin/bash

# Clone the emulation repository
git clone https://github.com/th-duvanel/riscv-spdm.git

# Compiles the echo "sniffer" server
gcc -Wall -o sniffer sniffer.c

# Check if the first argument is "full"
if [ "$1" = "full" ]; then
    chmod +x *.sh

    sudo ./deps.sh
    . ./env.sh
    sudo ./newdisk.sh
fi




exit 0