# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=master)](https://travis-ci.org/carblue/acos5_64)

# acos5_64

ACS ACOS5-64/CryptoMate64/CryptoMateNano driver/SM/PKCS#15 external module for the OpenSC framework.<br>

Restricted to Non-FIPS/64K operation mode setting !<br>
If the card/token is virgin from factory (no MF), it will be switched to Non-FIPS/64K mode and initialized. Initial "CODES PINS" to be looked up in source code.<br>
For tweaking init/reinit/zeroize card/token, search for CHANGE_HERE_FOR_  in source code.<br>
FIPS mode (if at all) won't be supported before full SM implementation is done and the final Non-FIPS/64K mode will be close to FIPS mode, but e.g. not exclude 4096 bit keys.

Work in progress.

Contributions like writing docmentation/code, borrow latest PKCS#15 standard document ISO/IEC 7816-15:2016 are welcome.