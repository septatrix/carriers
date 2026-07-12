//! Daemon runtime for carriers, exposed as a library so the ingress listener, delivery and
//! shared application state can be driven in-process (e.g. by `carriers-testkit`) as well as by
//! the `carriers` binary. The CLI itself lives in `main.rs`.

pub mod deliver;
pub mod smtp;
pub mod state;
