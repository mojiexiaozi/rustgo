const AUTH_DOMAIN: &[u8] = b"rustgo-auth-v1";

pub struct AuthTranscript {
    encoded: Vec<u8>,
}

impl AuthTranscript {
    #[must_use]
    pub fn new(
        challenge: Vec<u8>,
        session_id: Vec<u8>,
        protocol_version: u16,
        client_name: String,
    ) -> Self {
        let mut encoded = Vec::with_capacity(
            AUTH_DOMAIN.len() + challenge.len() + session_id.len() + client_name.len() + 14,
        );
        encoded.extend_from_slice(AUTH_DOMAIN);
        append_bytes(&mut encoded, &challenge);
        append_bytes(&mut encoded, &session_id);
        encoded.extend_from_slice(&protocol_version.to_be_bytes());
        append_bytes(&mut encoded, client_name.as_bytes());
        Self { encoded }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

fn append_bytes(encoded: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("authentication field exceeds 4 GiB");
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value);
}
