# opensc-sys
Rust lang.: A binding to libopensc.so/dll/dylib, required for new external modules (driver/pkcs15init/sm) etc. written in Rust

https://github.com/OpenSC/OpenSC/wiki<br>
https://www.rust-lang.org/tools/install

More infos: The first 100 lines of [lib.rs](https://github.com/carblue/acos5/blob/master/opensc-sys/src/lib.rs "https://github.com/carblue/acos5/blob/master/opensc-sys/src/lib.rs")
or clone and run<br>
user@host:~/path/to/opensc-sys$  cargo doc && firefox ../target/doc/opensc_sys/index.html &
If Rust/cargo is not required anymore, uninstall with: rustup self uninstall

It's highly recommended to test the binding (with installed binary libopensc.so/dll/dylib). The test MUST pass or the binding is NOT usable with the given binary and dependants won't work!<br>
```
user@host:~/path/to/opensc-sys$ cargo test test_struct_sizeof -- --nocapture
...
Testing whether linking to the OpenSC binary works: On success, it will state the OpenSC version

### Release version of installed OpenSC binaries is  "0.19.0"  ###    <= or whatever version the installed OpenSC package is; MUST match the version reported by  opensc-tool -i

test tests::test_struct_sizeof ... ok                                 <= this is the essential success line

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 24 filtered out

```
The repo's intention is NOT to substitute/bypass writing an internal driver for OpenSC (which has undisputed long-term advantages), but from my experience it's faster and more flexible to first write/test an external version and then transform the Rust code to an internal C code driver.

Work IN Progress.<br>
Apart from the binding, this strives to evolve into a high quality API documentation of libopensc, to be tailored to particular needs of Rust.
