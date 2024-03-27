# SPDM-WID, a Wireshark Dissector

SPDM-WID is a dissector for Wireshark, made in Lua. It's designed for SPDM (Security Protocol Data Model), a protocol made by DMTF.

## About SPDM
SPDM defines message exchanging and authentication between devices, including hardware identities. The protocol is made for being executed in the start of the computer, exchanging messages between PCI Express physical bus. It is a very low-level protocol.

So, if it's made for running in a way that we can't sniff packets with Wireshark, how can we use this dissector?

## Usage
If you're lazy, libspdm has a built-in Responder and Requester, that can emulate the packet exchange. You can use this dissector and it will work perfectly.

Besides that, there are many emulated implementations using SPDM for authenticating hardware. One of them is listed above, using QEMU. A way to intercept those packets its using a built-in QEMU functionality: a SLIRP, a manner to access the Host (our computer) with the guest (QEMU).

Then, inside the emulated hardware (in this case, we're using virtio) you can open a socket to transmit packets from the guest to the host. If your host have a sort of echo server, perfect. If it doesn't, use UDP, and then Wireshark doesn't care if the packet was received, just if it was intercepted.

For your luck, this repo comes with an already made implementation!


## Installation

### Dissector
Wireshark has two paths for plugins: personal and global plugins. I would recommend putting our dissector on the global ones, in my system, the path is this one:

```bash
sudo cp SPDM-wid.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/SPDM-wid.lua
```

You can check your path on the Help -> About Wireshark and then Folder menu, if you click twice on the path, it will appear on your file manager. Just drop it there.

### SPDM packets emulation
You can run the bash script, it will clone the repository needed for demonstration and compile our server/sniffer/echo. You'll need gcc for this.

For this, you have two options: the auto compiled demonstration (needs sudo because there are many dependencies. Maybe you're lucky to have them all) or the normal one, which just compiles the server and clones the respository.

For full compilation:

```bash
  chmod +x compile.sh
  sudo ./compile.sh full
```

For just some things:
```bash
  chmod +x compile.sh
  ./compile.sh
```

Now, run in this order:
- (1th) The sniffer (server, echo, etc.), make sure you have the 2323 TCP port on
```bash
./sniffer
```
- (2th) Wireshark, with the dissector installed and filter "tcp.port == 2323 && tcp.flags.push == 1"
```bash
sudo wireshark
```
- (3th) The emulator
```bash
./riscv-spdm/run.sh
```


## Links
[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/thiago-duvanel?original_referer=https%3A%2F%2Fgithub.com%2F)

 - [Libspdm](https://github.com/DMTF/libspdm)
 - [SPDM inside QEMU](https://github.com/offreitas/riscv-spdm)
 - [spdmfuzzer](https://github.com/th-duvanel/spdmfuzzer)
