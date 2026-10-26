use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ServerConfig, crypto::ring};

/// STARTTLS acceptor whose certificate can be re-read from disk (SIGHUP), so
/// renewals don't need a restart.
pub struct TlsContext {
    paths: Option<(String, String)>,
    acceptor: RwLock<TlsAcceptor>,
}

impl TlsContext {
    pub fn load(cert_path: &str, key_path: &str) -> Result<Self> {
        let acceptor = read_acceptor(cert_path, key_path)?;
        Ok(Self {
            paths: Some((cert_path.to_owned(), key_path.to_owned())),
            acceptor: RwLock::new(acceptor),
        })
    }

    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        Ok(Self { paths: None, acceptor: RwLock::new(build_acceptor(cert_pem, key_pem)?) })
    }

    pub fn reload(&self) -> Result<()> {
        if let Some((cert, key)) = &self.paths {
            *self.acceptor.write().unwrap() = read_acceptor(cert, key)?;
        }
        Ok(())
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.read().unwrap().clone()
    }
}

fn read_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert = std::fs::read(cert_path).with_context(|| format!("reading {cert_path}"))?;
    let key = std::fs::read(key_path).with_context(|| format!("reading {key_path}"))?;
    build_acceptor(&cert, &key)
}

fn build_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing TLS certificate chain")?;
    anyhow::ensure!(!certs.is_empty(), "no certificate found in the TLS certificate file");
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("parsing TLS private key")?;
    let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}
