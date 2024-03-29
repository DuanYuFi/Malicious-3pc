# Malicious-3PC

**Note: The binary protocol is in the branch 'static_bincheck'**

**The arithmetic protocol is in the branch 'full_version'**

**After all the stuffs finish, they will merged into branch main**

Usage: After pull the repository, run:
```
sudo apt update
sudo apt install automake build-essential git libboost-dev libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 python3 texinfo yasm
make tldr
```

then the environment will automatically prepared. And you can build other protocols.

```
make mal3pc-ring -j 8 // our protocol
make replicated-ring-party.x -j 8 // ABY3
make sy-rep-ring-party.x -j 8 // SpdzWise ring

```

## Malicious

Our protocol with SpdzWise is in Protocols/Malicious3PCProtocol.h, Protocols/Malicious3PCProtocol.hpp. The VM file is Machines/mal3pc-ring-party.cpp. If you want to compile this protocol, please DO NOT FORGET to uncomment GC/ShareThread.hpp: line 88 `protocol->finalize_check();` and comment line 89 `protocol->check();`. The test running script is in Scripts/mal3pc-ring.sh .

## About mpir:

If any error occurs in make. According to the error log, if it's about `mpir`, try to figure out the following:
- mpir directory is not empty. If it is, you have to run `git clone https://github.com/wbhart/mpir.git`.
- make sure mpir is correctly installed. You can check the INSTALL file in mpir.
- Other errors mostly can be found in the issue of mpir project.
