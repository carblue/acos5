# acos5_pkcs15

pkcs15init shared library for ACS ACOS5 Smart Card/CryptoMate64/CryptoMate Nano, external module for the OpenSC framework.<br>
A theoretically optional, but in practice likely required library that supplements driver 'acos5' with some specific PKCS#15 related functionality, i.a. C_GenerateKeyPair will get support from this module.

https://github.com/OpenSC/OpenSC/wiki<br>
https://www.rust-lang.org/tools/install

Build as usual with Rust<br>
`user@host:~/path/to/acos5_root_downloaded$  cargo build --release`<br>
`optionally user@host:~/path/to/acos5_root_downloaded$  strip --strip-all target/release/libacos5_pkcs15.so`

The required opensc.conf entries:<br>
......... just denotes, there is other opensc.conf content before this line<br>
Content within ... (excluded) must be adapted (/something/like/path/to/acos5_pkcs15$/target/releaseORdebug/) and added, otherwise the library won't be found.<br>
```
app default {
    .........
    # PKCS #15
    framework pkcs15 {
        .........
        # emulate custom {
            # The location of the driver library
            # module = /usr/lib/x86_64-linux-gnu/libp15emu_custom.so;
        # }
        ...
        pkcs15init acos5-external {
            # The location of the pkcs15init library that supplements driver 'acos5': /path/to/libacos5_pkcs15.so/dll/dylib;
            # /path/to/ may be omitted, if it's located in a standard library search path of the OS
            module = /something/like/path/to/acos5/target/releaseORdebug/libacos5_pkcs15.so;
        }
        ...
    }
}
```

Copy `acos5-external.profile` to the directory where all the other .profile files installed by OpenSC are located, for Linux probably in /usr/share/opensc/ or /usr/local/share/opensc/, for Windows something like C:/Program Files/OpenSC Project/OpenSC/profiles.<br>
