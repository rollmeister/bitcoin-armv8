This fork of the official Bitcoin Core wallet and node software employs hardware acceleration features on ArmV8. It can be used on Cortex-a53 and higher based cpu's running Linux. Raspberry Pi 3 Model B+ (and later model) single board computers should work even if using the 32-bit Rasbpian Linux OS, though this is untested at time of writing. If you board lacks the required hardware extensions ("cat /proc/cpuinfo" check for sha1, sha2, pmull & crc32 Features), the software will either fail to compile or run.  

*Update. SHA256D64 is currently routed through sha256_armv8::TransformD64Wrapper<sha256_armv8::Transform> with about 25% performance penalty of a fully optimised TransformD64 which is currently broken.  
Below are benchmark comparisons of the original and forked repository outputted by src/bench/bench_bitcoin.
Tests that had negligible difference were removed. The most notable gain is the SHA256 tests.

Benchmark (real world significance in bold) | Percentage improvement
------------ | -------------
**AssembleBlock** | 30%
Base58CheckEncode | 9%
Bech32Decode | 14%
Bech32Encode | 7%
**CCoinsCaching** | 88%
**DeserializeAndCheckBlockTest** | 40%
**DeserializeBlockTest** | 67%
MempoolEviction | 5%
RollingBloom | 7%
SHA1 | 371%
**SHA256** | 681%
**SHA256_32b** | 338%

The following algorithms and files were updated and listed in order of significance.

Bitcoins central hashing algorithm.
SHA256 (src/crypto/sha256.cpp)

Used by leveldb library as part of block processing. Raw CRC32 computations are 5x faster.
CRC32 (port_posix_sse.cc & port_posix.cc in src/leveldb/port/)

Possibly used in Bitcoin currency transactions, or not at all.
SHA1 (src/crypto/sha1.cpp)

configure.ac has superfluous changes for CRC32 support checks, and compulsory architecture specific feature modifier compiler flags and -funroll-loops.

Compiled with Clang 6 -O2 on Ubuntu 16.04. For faster compile you could do...

git clean -xdf

./autogen.sh

./configure --disable-tests --disable-bench

make -j 1

or -j 2 if 2gb ram or compiling with Clang (i.e. add CC="clang-6.0" CXX="clang++-6.0" to configure and make)

The changes to code were tested for validity using src/test/test_bitcoin and separate run time tests where output of the new functions ran side by side with the original for several hours and compared output of both to be identical. There is no guarantee or warranty of any kind. This fork inherits the same licences and liability wavers of its parent Bitcoin Core branch. USE AT YOUR OWN RISK.

###### Other notes. 
Implementing ArmV8 SHA256 for secp256k1 was attempted during development. Due to the library being coded in the 1989 ANSI C standard and requires extra hacking to allow intrinsics to compile. Minor benefits are to be expected in doing so.
Changes are not very maintainable, that is compilation for other platforms will fail and further releases require merging into it. Lack of skill & time in changing compiling scripts for easily maintainable commits. Mostly using preprocessor conditionals to include ArmV8 specific code.

Software dependencies detailed in doc/build-unix.md still apply.

Bitcoin Core integration/staging tree
=====================================

[![Build Status](https://travis-ci.org/bitcoin/bitcoin.svg?branch=master)](https://travis-ci.org/bitcoin/bitcoin)

https://bitcoincore.org

What is Bitcoin?
----------------

Bitcoin is an experimental digital currency that enables instant payments to
anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. Bitcoin Core is the name of open source
software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Bitcoin Core software, see https://bitcoincore.org/en/download/, or read the
[original whitepaper](https://bitcoincore.org/bitcoin.pdf).

License
-------

Bitcoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/bitcoin/bitcoin/tags) are created
regularly to indicate new official, stable release versions of Bitcoin Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and macOS, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

Changes to translations as well as new translations can be submitted to
[Bitcoin Core's Transifex page](https://www.transifex.com/projects/p/bitcoin/).

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.

Translators should also subscribe to the [mailing list](https://groups.google.com/forum/#!forum/bitcoin-translators).
