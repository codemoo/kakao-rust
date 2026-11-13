//! Message collection, authenticated APIs, text sending and history restoration.
//! Feature coverage and verification limits are documented in docs/PARITY.md.

pub mod api;
pub mod auth;
pub mod contacts;
pub mod device;
pub mod drawer;
pub mod drawer_restore;
pub mod error;
pub mod friends;
pub mod ingest;
pub mod live;
pub mod loco;
pub mod maintenance;
pub mod media;
pub mod native;
pub mod native_http;
pub mod password;
pub mod password_auth;
pub mod pilsner;
pub mod qr;
pub mod qr_auth;
pub mod runtime;
pub mod session;
pub mod store;

mod block_sync;
mod domain_sync;
mod live_store;
mod mutations;
mod outgoing;
mod room_sync;
mod send_text;

pub use error::{Error, Result};
pub use store::Store;
