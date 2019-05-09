# RISC-V Attacks

<!-- vim-markdown-toc GFM -->

* [Introduction](#introduction)
* [Cloning the Repository](#cloning-the-repository)
* [System Deploy](#system-deploy)
    * [RI5CY GNU Toolchain Setup](#ri5cy-gnu-toolchain-setup)
    * [PULPino Setup](#pulpino-setup)
* [Executing the Attacks](#executing-the-attacks)
* [References](#references)

<!-- vim-markdown-toc -->

## Introduction

This repository includes a porting of the Wilander-Kamkar [[1]](#wilander-kamkar) suite of buffer-overflow attacks that targets RISC-V processors. The original suite targets `x86` architectures. We modified the suite to implement the attacks on RISC-V 32-bit processor cores. This repository, in addition to the code of the attacks, includes some scripts that allow you to test these attacks on the [PULPino](https://github.com/pulp-platform/pulpino) system.

## Cloning the Repository

If you are interested in only the source code of the attacks you can clone the current repository:
```
git clone git@github.com:lucapiccolboni/riscv-attacks.git
```

In addition, if you want to test the attacks on the RISC-V core provided with the [PULPino](https://github.com/pulp-platform/pulpino) system you have to initialize few submodules:
```
cd riscv-attacks
git submodule update --init --recursive
```
See the following subsection for the system-setup details.

## System Deploy

We run our experiments on a host equipped with CentOS 7.x or Ubuntu 18.x. For library and tool requirements please check:
- https://github.com/pulp-platform/ri5cy_gnu_toolchain
- https://github.com/pulp-platform/pulpino
- https://github.com/pulp-platform/pulpino/tree/master/fpga

For RTL simulation you need a relatively recent version of ModelSim. For FPGA deployment you need Vivado 2015.1.

### RI5CY GNU Toolchain Setup

You need the [PULPino port](https://github.com/pulp-platform/ri5cy_gnu_toolchain) of the RISC-V GCC toolchain, which has been modified to support the extensions of the PULPino cores.

We include it as a submodule in `deploy/ri5cy_gnu_toolchain`. You can easily compile and add it to the `PATH` system variable:

```
cd deploy/ri5cy_gnu_toolchain
make
export PATH=$PWD/install/bin:$PATH
```

### PULPino Setup

For the PULPino requirements and setup, please follow the [official documentation](https://github.com/pulp-platform/pulpino).

Our experiments require only one change with respect to the official setup instructions (see section [Running simulations](https://github.com/pulp-platform/pulpino#running-simulations)). You should use the configuration file that we provide in the folder `deploy/configs`, rather than any of the files `deploy/pulpino/sw/cmake_configure.*.gcc.sh`.

```
mkdir -p deploy/pulpino/sw/build
cp deploy/pulpino/sw/cmake_configure.riscv.gcc.sh deploy/pulpino/sw/build
```

## Executing the Attacks

We provide a script to configure and install the attacks in the software directory of PULPino. You should just run it:
```
cd scripts
./deploy_attacks_on_pulpino.sh
```

At this point you can try the attacks:
```
cd deploy/pulpino/sw/build
make vcompile
make wilander_kamkar
make wilander_kamkar.vsimc
```

Please look at the instructions on the [PULPino](https://github.com/pulp-platform/pulpino) repository for further details.

## References

- <a name="wilander-kamkar">[1]</a> _A Comparison of Publicly Available Tools for Dynamic Buffer Overflow Prevention_, John Wilander and Mariam Kamkar, Network & Distributed System Security Symposium, 2003 

