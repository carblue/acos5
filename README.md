# acos5_64


ACS ACOS5-64/CryptoMate64 driver and SM module (shared library/DLL) for the OpenSC framework

The library will be limited to OS Windows and POSIX (excluding Mac OSX; I've neither access to nor knowledge of Mac OSX. But if it doesn't work out of the box, it should be quite easy to support Mac OSX as well, if someone interested in will assist/test).

The module (driver) is operational now, though for no more than  opensc-tool --serial

An early tester will find the opensc.conf (i.e. a diff-file to what gets installed by opensc, working for me on linux) in directrory config. Adapt "/path/to" or place binary in OS's shared object/DLL search path.
Forcing driver acos5_64 seems to be essential at the moment, as there is another driver (acos5 internal driver), that will serve Your card/token otherwíse.
As long as DMD doesn't obey visibility of symbols declared [http://wiki.dlang.org/Access_specifiers_and_visibility], the script for the linker 'libacos5_64.map' (included in dub.json) does the job as well.
Building with DUB is a pleasure and DMD is blazingly fast ;-)  Within directory libacos5_64, execute: $ dub build
The binary will be compiled/linked/placed to sub-directory lib, if You go with DUB/my dub.json.

Soon to come: More code to be integrated, as review of existing code goes on.

This topic climbed rapidly on my priority ladder: Reinitialization of a card/token. Presumably, most cards/token out there got initialized with vendors client kit, what makes Secure Messaging (SM) with session key infeasible (SE-file NEVER update protected, but no session key usage provided).
There are some more reasons to reinitialize. Users with some knowledge in this regard and not afraid of source code, will be able to reinitialize exactly to their needs. Still my settings are compatible with ACSCMU
In turn SM working is my prerequisite for publishing operations relevant to security.
Though sadly, all pin related operations have no SM support by ACOS5-64 (at least reference manual says so, but perhaps it is wrong in this regard too?).
Pins will always be in plain text commands. I've to make my mind how to deal with that if it proves true. Then, pins are but a transient shadow.


TODO explain a lot of details/usage/version identifiers/etc.
