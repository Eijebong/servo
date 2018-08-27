/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use hosts::replace_host;
//use hyper::client::Pool;
use hyper::error::{Result as HyperResult, Error as HyperError};
//use hyper::net::{NetworkConnector, HttpsStream, HttpStream, SslClient};
use hyper::{Connect, ConnectFuture, HttpConnector as HyperHttpConnector};
use hyper_openssl::{HttpsConnector, OpensslClient};
use openssl::ssl::{SSL_OP_NO_COMPRESSION, SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3};
use openssl::ssl::{SslConnector, SslConnectorBuilder, SslMethod};
use openssl::x509;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::error::Error;
use tokio::reactor::Handle;

pub struct HttpConnector {
    inner: HyperHttpConnector
}

impl HttpConnector {
    fn new() -> HttpsConnector {
        HttpsConnector {
            inner: HyperHttpConnector::new(4) // TODO
        }
    }
}

impl Connect for HttpConnector {
    type Transport = HyperHttpConnector::Transport;
    type Error = HyperHttpConnector::Error;
    type Future = HyperHttpConnector::Future;

    fn connect(addr: &SocketAddr, local_addr: &Option<IpAddr>, handle: &Option<Handle>, reuse_address: bool) -> Self::Future {
        /*
         if scheme != "http" && scheme != "https" {
            return Err(HyperError::Io(io::Error::new(io::ErrorKind::InvalidInput,
                                                     "Invalid scheme for Http")));
        }
        */

        // Perform host replacement when making the actual TCP connection.
        let addr = &(&*replace_host(addr.host()), addr.port());
        HyperHttpConnector::connect(addr, local_addr, handle, reuse_address)
    }
}

pub type Connector = HttpsConnector<HttpConnector>;

pub fn create_ssl_connector(certs: &str) -> SslConnector {
    // certs include multiple certificates. We could add all of them at once,
    // but if any of them were already added, openssl would fail to insert all
    // of them.
    let mut certs = certs;
    let mut ssl_connector_builder = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
    loop {
        let token = "-----END CERTIFICATE-----";
        if let Some(index) = certs.find(token) {
            let (cert, rest) = certs.split_at(index + token.len());
            certs = rest;
            let cert = x509::X509::from_pem(cert.as_bytes()).unwrap();
            ssl_connector_builder.cert_store_mut().add_cert(cert).or_else(|e| {
                let v: Option<Option<&str>> = e.errors().iter().nth(0).map(|e| e.reason());
                if v == Some(Some("cert already in hash table")) {
                    warn!("Cert already in hash table. Ignoring.");
                    // Ignore error X509_R_CERT_ALREADY_IN_HASH_TABLE which means the
                    // certificate is already in the store.
                    Ok(())
                } else {
                    Err(e)
                }
            }).expect("could not set CA file");
        } else {
            break;
        }
    }
    ssl_connector_builder.set_cipher_list(DEFAULT_CIPHERS).expect("could not set ciphers");
    ssl_connector_builder.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
    ssl_connector_builder.build()
}

pub fn create_ssl_client(certs: &str) -> OpensslClient {
    let ssl_connector = create_ssl_connector(certs);
    OpensslClient::from(ssl_connector)
}

pub fn create_http_connector(ssl_client: OpensslClient) -> Connector {
    HttpsConnector::new(ssl_client)
}

// The basic logic here is to prefer ciphers with ECDSA certificates, Forward
// Secrecy, AES GCM ciphers, AES ciphers, and finally 3DES ciphers.
// A complete discussion of the issues involved in TLS configuration can be found here:
// https://wiki.mozilla.org/Security/Server_Side_TLS
const DEFAULT_CIPHERS: &'static str = concat!(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:",
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:",
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:",
    "ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:",
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:",
    "ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:",
    "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
);
