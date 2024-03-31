# SPDM-WiD, a Wireshark Dissector

SPDM-WiD is a dissector for Wireshark, made in Lua. It's designed for SPDM (Security Protocol Data Model), a protocol made by DMTF.

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
sudo cp dissector/SPDMwid.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/SPDMwid.lua
```

You can check your path on the Help -> About Wireshark and then Folder menu, if you click twice on the path, it will appear on your file manager. Just drop it there.

### SPDM packets emulation
You can run the bash script, it will clone the repository needed for demonstration and compile our server/sniffer/echo. You'll need gcc for this.

You need to use the other repository, it is important to capture the packets. This is a copy of its README, to test it:

```bash
git clone https://github.com/th-duvanel/riscv-spdm.git
```
Inside riscv-spdm, follow the instructions:

First, you need some dependencies:

```bash
make 
gcc 
file 
g++ 
wget 
unzip 
cpio 
rsync 
bc 
bzip2 
cmake 
libglib2.0-dev 
libsdl2-dev 
libpixman-1-dev 
nettle-dev 
libgtk-3-dev 
libjemalloc-dev 
libcap-ng-dev 
libattr1-dev 
libssl-dev
parted
```

```bash
$ chmod +x *.sh
$ . ./compile.sh
```
I know, it is strange to have a Makefile in the repo and you have to use a shell script. But the Git repos have to compile themselves
individually. If not, it can cause some unexpected errors, so, use the script above.


For the qemu emulation, you need to simulate the disk, so, use this shell script.
```bash
./newdisk.sh
```
I'm sorry for the sudo newdisk.sh inside the own shell. It is because the compilation and environemnt variables aren't the same if you're running the
script with and without it. If you want it, you can run it separetely.

# Running

Now, run in this order, inside the riscv-spdm folder:
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
./run.sh
```

## Links
[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/thiago-duvanel?original_referer=https%3A%2F%2Fgithub.com%2F)

 - [Libspdm](https://github.com/DMTF/libspdm)
 - [SPDM inside QEMU (author's fork)](https://github.com/th-duvanel/riscv-spdm)
 - [SPDM inside QEMU (original)](https://github.com/offreitas/riscv-spdm)
 - [spdmfuzzer](https://github.com/th-duvanel/spdmfuzzer)
