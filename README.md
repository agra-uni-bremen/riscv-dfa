RISC-V based Data Flow Analysis (RISCV-DFA)
==============================

The RISC-V based Data Flow Analysis Tool is a fork of the original [Virtual Prototype](https://github.com/agra-uni-bremen/riscv-vp).
It extends the existing RISC-V RV32IM core and peripherals to track guest memory even in CPU and peripherals and enforce a given security policy, defined by a lattice.

The VP is designed as extensible and configurable platform with a generic bus system and implemented in standard-compliant SystemC and TLM-2.0.
For more information please visit http://www.systemc-verification.org/ or contact <riscv@systemc-verification.org>.
In the following we provide build instructions and how to compile and run software on the VP.


1) Build the RISC-V GNU Toolchain:
----------------------------------

(Cross-)Compiling the software examples, in order to run them on the VP, requires the RISC-V GNU toolchain to be available in PATH. Several standard packages are required to build the toolchain. On Ubuntu the required packages can be installed as follows:

```bash
sudo apt-get install autoconf automake autotools-dev curl libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev
```

On Fedora, following actions are required:
```bash
sudo dnf install autoconf automake curl libmpc-devel mpfr-devel gmp-devel gawk bison flex texinfo gperf libtool patchutils bc zlib-devel expat-devel cmake boost-devel
sudo dnf groupinstall "C Development Tools and Libraries"
#optional debuginfo
sudo dnf debuginfo-install boost-iostreams boost-program-options boost-regex bzip2-libs glibc libgcc libicu libstdc++ zlib
```

For more information on prerequisites for the RISC-V GNU toolchain visit https://github.com/riscv/riscv-gnu-toolchain. With the packages installed, the toolchain can be build as follows:

```bash
git clone https://github.com/riscv/riscv-gnu-toolchain.git
cd riscv-gnu-toolchain
git submodule update --init --recursive

./configure --prefix=$(pwd)/../riscv-gnu-toolchain-dist-rv32g-ilp32d --with-arch=rv32g --with-abi=ilp32d

make
```


2) Build this RISC-V Virtual Prototype:
---------------------------------------

i) in root folder, run `make`. This will download and build systemC-2.4.2 and the main executable.


3) Compile and run some Software:
---------------------------------

In *sw*:

```bash
cd simple-sensor                        # can be replaced with different example
make                                    # (requires RISC-V GNU toolchain in PATH)
../../vp/build/lib/riscv-vp main        # shows final simulation time as well as register and pc contents
```

Add the *riscv-vp* executable to PATH to simplify execution of SW examples.
