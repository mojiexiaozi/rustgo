use rustgo_e2e::generate_ephemeral_pki;
use rustgo_transport::{TlsClient, TlsServer};

#[test]
fn generated_script_pki_passes_production_tls_loaders() {
    let directory = tempfile::tempdir().unwrap();
    let material = generate_ephemeral_pki(directory.path(), "localhost").unwrap();

    TlsServer::validate_identity(&material.certificate_file, &material.private_key_file).unwrap();
    TlsClient::from_ca_file(&material.certificate_authority_file, "localhost").unwrap();
}
