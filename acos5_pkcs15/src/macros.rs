
//! Both driver components (libacos5.so/dll and `libacos5_pkcs15.so/dll`) share this same file

/*
macro_rules! cstru {
    ($x:expr) => (unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked($x) })
}
*/
/*
All logging will ultimately call into C's variadic function sc_do_log
All log-related macros here are dispatchers only to some wr_do_log* functions
Purpose of both together:
 - if cfg!(log) shall appear in wrappers.rs only
 - possibly remove wrappers.rs
 -
*/

// log3if` : with explicit format-string $d and for 0-4 arguments, all possibly differing types
//    3 == SC_LOG_DEBUG_NORMAL
//     if : because it depends on cargo:rustc-cfg=log: if set, the macro will log, otherwise logging will be suppressed
macro_rules! log3if {
    ($a:expr_2021, $b:expr_2021, $c:expr_2021, $d:expr_2021)                                      => (wr_do_log     ($a, $b, $c, $d));
    ($a:expr_2021, $b:expr_2021, $c:expr_2021, $d:expr_2021,  $e:expr_2021)                            => (wr_do_log_t   ($a, $b, $c, $d, $e));
    ($a:expr_2021, $b:expr_2021, $c:expr_2021, $d:expr_2021,  $e:expr_2021, $f:expr_2021)                   => (wr_do_log_tu  ($a, $b, $c, $d, $e, $f));
    ($a:expr_2021, $b:expr_2021, $c:expr_2021, $d:expr_2021,  $e:expr_2021, $f:expr_2021, $g:expr_2021)          => (wr_do_log_tuv ($a, $b, $c, $d, $e, $f, $g));
    ($a:expr_2021, $b:expr_2021, $c:expr_2021, $d:expr_2021,  $e:expr_2021, $f:expr_2021, $g:expr_2021, $h:expr_2021) => (wr_do_log_tuvw($a, $b, $c, $d, $e, $f, $g, $h));
}

// log3ift` : with explicit format-string $d and for 2-4 arguments, all of the same type
//    3 == SC_LOG_DEBUG_NORMAL
//     if : because it depends on cargo:rustc-cfg=log: if set, the macro will log, otherwise logging will be suppressed
//       t indicates common type T for all arguments
macro_rules! log3ift {
    ($a:expr_2021, $b:expr_2021, $c:expr_2021, $d:expr_2021,  $e:expr_2021, $f:expr_2021)                   => (wr_do_log_tt  ($a, $b, $c, $d, $e, $f));
    ($a:expr_2021, $b:expr_2021, $c:expr_2021, $d:expr_2021,  $e:expr_2021, $f:expr_2021, $g:expr_2021)          => (wr_do_log_ttt ($a, $b, $c, $d, $e, $f, $g));
    ($a:expr_2021, $b:expr_2021, $c:expr_2021, $d:expr_2021,  $e:expr_2021, $f:expr_2021, $g:expr_2021, $h:expr_2021) => (wr_do_log_tttt($a, $b, $c, $d, $e, $f, $g, $h));
}

// log3ifr` : with implicit format-string and for 0-2 arguments, all possibly differing types; no individual format string, but prescribed
//    3 == SC_LOG_DEBUG_NORMAL
//     if : because it depends on cargo:rustc-cfg=log: if set, the macro will log, otherwise logging will be suppressed
//       r : specific for logging 'return' (or 'report') situations
macro_rules! log3ifr {
//  ($a:expr, $b:expr, $c:expr)                                               => (wr_do_log     ($a, $b, $c,  c"returning"));
    ($a:expr_2021, $b:expr_2021, $c:expr_2021,           $e:expr_2021)                            => (wr_do_log_rv  ($a, $b, $c,  $e));
    ($a:expr_2021, $b:expr_2021, $c:expr_2021,           $e:expr_2021, $f:expr_2021)                   => (wr_do_log_sds ($a, $b, $c,  $e, $f)); // not explicitly related to 'returning'
}

macro_rules! log3ifr_ret {
    ($a:expr_2021, $b:expr_2021, $c:expr_2021,           $e:expr_2021)                            => (wr_do_log_rv_ret  ($a, $b, $c,  $e));
    ($a:expr_2021, $b:expr_2021, $c:expr_2021,           $e:expr_2021, $f:expr_2021)                   => (wr_do_log_sds_ret ($a, $b, $c,  $e, $f)); // not explicitly related to 'returning'
}

// log3ifc` : with implicit format-string and for 0 arguments
//    3 == SC_LOG_DEBUG_NORMAL
//     if : because it depends on cargo:rustc-cfg=log: if set, the macro will log, otherwise logging will be suppressed
//       c : specific for logging 'called' situations
macro_rules! log3ifc {
    ($a:expr_2021, $b:expr_2021, $c:expr_2021)                                               => (wr_do_log     ($a, $b, $c,  c"called"));
}
