//! This crate provides tools and utilities for handling TLV data as
//! defined in [ISO7816-4][iso7816-4].
//!
//! This include BER-TLV data or SIMPLE-TLV data objects.
//!
//!
//!
//!
//! [iso7816-4]: https://www.iso.org/standard/54550.html

#![deny(missing_docs)]
//#![cfg_attr(feature = "cargo-clippy", deny(clippy::all))]
//#![cfg_attr(feature = "cargo-clippy", deny(clippy::pedantic))]

// internal organization
pub mod ber;
mod error;
pub mod simple;

// custom reexport (structs at same level for users)
pub use error::TlvError;

type Result<T> = std::result::Result<T, TlvError>;
