use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    },
    TlsAcceptor,
};

const CERT: &[u8] = include_bytes!("../../tests/fixtures/hosted-tls/server-cert.pem");
const ROOT: &[u8] = include_bytes!("../../tests/fixtures/hosted-tls/ca-cert.pem");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/hosted-tls/server-key.pem");

fn trusted_client() -> RelayHttp {
    RelayHttp {
        client: RelayHttp::client_builder()
            .timeout(Duration::from_secs(3))
            // The owned TLS fixture is not a permitted production destination.
            .resolve("localhost", "127.0.0.1:0".parse().unwrap())
            .resolve("mismatch.example", "127.0.0.1:0".parse().unwrap())
            .tls_certs_only([reqwest::Certificate::from_pem(ROOT).unwrap()])
            .build()
            .unwrap(),
        development: false,
    }
}

async fn server(
    host: &str,
    wrong_endpoint: bool,
    redirect: bool,
) -> (String, RelayPin, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{host}:{}", listener.local_addr().unwrap().port());
    let signer = SigningKey::from_bytes(&[7; 32]);
    let pin = RelayPin {
        key: signer.verifying_key().to_bytes(),
        run: [8; 32],
    };
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(CERT).unwrap()],
            PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let advertised = endpoint.clone();
    let pin_copy = pin.clone();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = match acceptor.accept(stream).await {
            Ok(s) => s,
            Err(error) => {
                eprintln!("owned TLS fixture handshake: {error:?}");
                return;
            }
        };
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            if stream.read_exact(&mut byte).await.is_err() {
                return;
            }
            request.push(byte[0]);
            assert!(request.len() <= 8192);
        }
        if redirect {
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1\r\nContent-Type: application/cbor\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            return;
        }
        let text = String::from_utf8(request).unwrap();
        let nonce = text
            .lines()
            .find_map(|line| line.strip_prefix("x-loki-challenge: "))
            .unwrap();
        let nonce = hex::decode(nonce).unwrap().try_into().unwrap();
        let body = challenge::encode_body(&challenge::ChallengeResponse {
            pin: pin_copy,
            endpoint: if wrong_endpoint {
                "https://other.example".into()
            } else {
                advertised
            },
            challenge: nonce,
        })
        .unwrap();
        let signature = signer.sign(&challenge::signature_input(&body).unwrap());
        let response = canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
        .unwrap();
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).as_bytes()).await.unwrap();
        stream.write_all(&response).await.unwrap();
    });
    (endpoint, pin, task)
}

#[tokio::test]
async fn verified_https_accepts_bound_relay_identity() {
    let (endpoint, pin, task) = server("localhost", false, false).await;
    let restricted = RelayHttp {
        client: RelayHttp::client_builder()
            .tls_certs_only([reqwest::Certificate::from_pem(ROOT).unwrap()])
            .build().unwrap(),
        development: false,
    };
    assert_eq!(restricted.authenticate_endpoint(&pin, &endpoint).await, Err(ClientError::Transport));
    assert!(!task.is_finished(), "a private DNS answer reached the listener");
    trusted_client()
        .authenticate_endpoint(&pin, &endpoint)
        .await
        .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn verified_https_rejects_hostname_mismatch() {
    let (endpoint, pin, task) = server("mismatch.example", false, false).await;
    assert_eq!(
        trusted_client()
            .authenticate_endpoint(&pin, &endpoint)
            .await,
        Err(ClientError::Transport)
    );
    task.await.unwrap();
}

#[tokio::test]
async fn production_trust_rejects_untrusted_certificate() {
    let (endpoint, pin, task) = server("localhost", false, false).await;
    let client = RelayHttp {
        client: RelayHttp::client_builder()
            .resolve("localhost", "127.0.0.1:0".parse().unwrap())
            .build().unwrap(),
        development: false,
    };
    assert_eq!(
        client
            .authenticate_endpoint(&pin, &endpoint)
            .await,
        Err(ClientError::Transport)
    );
    task.await.unwrap();
}

#[tokio::test]
async fn verified_https_rejects_signed_endpoint_substitution() {
    let (endpoint, pin, task) = server("localhost", true, false).await;
    assert_eq!(
        trusted_client()
            .authenticate_endpoint(&pin, &endpoint)
            .await,
        Err(ClientError::Receipt)
    );
    task.await.unwrap();
}

#[tokio::test]
async fn verified_https_does_not_follow_redirects() {
    let (endpoint, pin, task) = server("localhost", false, true).await;
    assert_eq!(
        trusted_client()
            .authenticate_endpoint(&pin, &endpoint)
            .await,
        Err(ClientError::Transport)
    );
    task.await.unwrap();
}
