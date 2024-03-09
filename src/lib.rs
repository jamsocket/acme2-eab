//! # acme2-eab
//!
//! NOTE: this is a fork of [acme2](https://crates.io/crates/acme2) which
//! adds support for [External Account Binding](https://tools.ietf.org/html/rfc8555#section-7.3.4).
//!
//! A [Tokio](https://crates.io/crates/tokio) and
//! [OpenSSL](https://crates.io/crates/openssl) based
//! [ACMEv2](https://tools.ietf.org/html/rfc8555) client.
//!
//! Features:
//!
//! - ACME v2 support, tested against Let's Encrypt and Pebble
//! - Fully async, using `reqwest` / Tokio
//! - Support for DNS01 and HTTP01 validation
//! - Fully instrumented with `tracing`
//!
//! ## Example
//!
//! This example demonstrates how to provision a certificate for the domain
//! `example.com` using `http-01` validation.
//!
//! ```no_run
//! use acme2_eab::gen_rsa_private_key;
//! use acme2_eab::AccountBuilder;
//! use acme2_eab::AuthorizationStatus;
//! use acme2_eab::ChallengeStatus;
//! use acme2_eab::DirectoryBuilder;
//! use acme2_eab::OrderBuilder;
//! use acme2_eab::OrderStatus;
//! use acme2_eab::Csr;
//! use acme2_eab::Error;
//! use std::time::Duration;
//!
//! const LETS_ENCRYPT_URL: &'static str =
//!   "https://acme-v02.api.letsencrypt.org/directory";
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!   // Create a new ACMEv2 directory for Let's Encrypt.
//!   let dir = DirectoryBuilder::new(LETS_ENCRYPT_URL.to_string())
//!     .build()
//!     .await?;
//!
//!   // Create an ACME account to use for the order. For production
//!   // purposes, you should keep the account (and private key), so
//!   // you can renew your certificate easily.
//!   let mut builder = AccountBuilder::new(dir.clone());
//!   builder.contact(vec!["mailto:hello@lcas.dev".to_string()]);
//!   builder.terms_of_service_agreed(true);
//!   let account = builder.build().await?;
//!
//!   // Create a new order for a specific domain name.
//!   let mut builder = OrderBuilder::new(account);
//!   builder.add_dns_identifier("example.com".to_string());
//!   let order = builder.build().await?;
//!
//!   // Get the list of needed authorizations for this order.
//!   let authorizations = order.authorizations().await?;
//!   for auth in authorizations {
//!     // Get an http-01 challenge for this authorization (or panic
//!     // if it doesn't exist).
//!     let challenge = auth.get_challenge("http-01").unwrap();
//!
//!     // At this point in time, you must configure your webserver to serve
//!     // a file at `https://example.com/.well-known/${challenge.token}`
//!     // with the content of `challenge.key_authorization()??`.
//!
//!     // Start the validation of the challenge.
//!     let challenge = challenge.validate().await?;
//!
//!     // Poll the challenge every 5 seconds until it is in either the
//!     // `valid` or `invalid` state.
//!     let challenge = challenge.wait_done(Duration::from_secs(5), 3).await?;
//!
//!     assert_eq!(challenge.status, ChallengeStatus::Valid);
//!
//!     // You can now remove the challenge file hosted on your webserver.
//!
//!     // Poll the authorization every 5 seconds until it is in either the
//!     // `valid` or `invalid` state.
//!     let authorization = auth.wait_done(Duration::from_secs(5), 3).await?;
//!     assert_eq!(authorization.status, AuthorizationStatus::Valid)
//!   }
//!
//!   // Poll the order every 5 seconds until it is in either the
//!   // `ready` or `invalid` state. Ready means that it is now ready
//!   // for finalization (certificate creation).
//!   let order = order.wait_ready(Duration::from_secs(5), 3).await?;
//!
//!   assert_eq!(order.status, OrderStatus::Ready);
//!
//!   // Generate an RSA private key for the certificate.
//!   let pkey = gen_rsa_private_key(4096)?;
//!
//!   // Create a certificate signing request for the order, and request
//!   // the certificate.
//!   let order = order.finalize(Csr::Automatic(pkey)).await?;
//!
//!   // Poll the order every 5 seconds until it is in either the
//!   // `valid` or `invalid` state. Valid means that the certificate
//!   // has been provisioned, and is now ready for download.
//!   let order = order.wait_done(Duration::from_secs(5), 3).await?;
//!
//!   assert_eq!(order.status, OrderStatus::Valid);
//!
//!   // Download the certificate, and panic if it doesn't exist.
//!   let cert = order.certificate().await?.unwrap();
//!   assert!(cert.len() > 1);
//!
//!   Ok(())
//! }
//! ```
//!
mod account;
mod authorization;
mod directory;
mod error;
mod helpers;
mod jws;
mod order;

pub use account::*;
pub use authorization::*;
pub use directory::*;
pub use error::Error;
pub use error::ServerError;
pub use error::TransportError;
pub use helpers::gen_ec_p256_private_key;
pub use helpers::gen_rsa_private_key;
pub use helpers::Identifier;
pub use openssl;
pub use order::*;
