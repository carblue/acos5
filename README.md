# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=master)](https://travis-ci.org/carblue/acos5_64)

# acos5_64

ACS ACOS5-64 Smart Card/CryptoMate64/CryptoMate Nano driver, external module for the OpenSC framework.

https://github.com/OpenSC/OpenSC/wiki<br>
https://www.rust-lang.org/learn/get-started

Compile - as usual with Rust and find the library in target/release -<br>
user@host:~/path/to/acos5_64$ cargo build --release

The required opensc.conf entries:<br>
...... just denotes, there is other opensc.conf content before this line<br>
Content within ... (excluded) must be adapted (/something/like/path/to/acos5_64/target/releaseORdebug/) and added, otherwise there will be no support for ACOS5-64.<br>
The line "card_drivers = acos5_64, npa, internal;" is just an example for OpenSC version 0.17.0: It means: Just prepend<br>
acos5_64,<br>
to the list of drivers specified by default and remove a leading comment character # in this line, if there is any.<br>
When using ACOS5-64 hardware versions V2.00, it's possibly also required to bypass the 'acos5' driver somehow, thus a painless start is by using
    card_drivers = acos5_64, default;

```
app default {
......
    # card_driver customcos {
    # The location of the driver library
    # module = /usr/lib/x86_64-linux-gnu/libcard_customcos.so;
    # }
...
    card_driver acos5_64 {
        # module, the (/path/to/) filename of the driver library. /path/to/ is dispensable if it's in a 'standard library search path'
        module = "/something/like/path/to/acos5_64/target/release/libacos5_64.so";
    }
...
......
    #card_drivers = npa, internal;
...
    card_drivers = acos5_64, npa, internal;
...
}
```
