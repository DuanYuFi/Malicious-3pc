# Malicious-3PC

Usage: After pull the repository, run:
```
sudo apt update
sudo apt install automake build-essential git libboost-dev libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 python3 texinfo yasm
make tldr
```

then the environment will automatically prepared. And you can build other protocols.

## Arithmetic Verify

Test files are in folder "Test/". In the Test folder, there are some c++ source codes named like "dzkp-xxx-yyy.cpp". The 'xxx' means the ring or field that the basic protocol (mul, add, sub, etc) is based on. The 'yyy' means the ring or field that the verification protocol is used. For example, "dzkp-fp-mersenne.cpp" means the protocol is based on GFp and verify on mersenne prime field.

Before run the file, you have to setup the MP-SPDZ environment (use dockerfile or command line, etc). After you got the "libSPDZ.so", you can run the script "run_test.sh" to compile and run the test file. The script will automatically compile the test file and run it. The result will be shown in the terminal.

## About mpir:

If any error occurs in make. According to the error log, if it's about `mpir`, try to figure out the following:
- mpir directory is not empty. If it is, you have to run `git clone https://github.com/wbhart/mpir.git`.
- make sure mpir is correctly installed. You can check the INSTALL file in mpir.
- Other errors mostly can be found in the issue of mpir project.
