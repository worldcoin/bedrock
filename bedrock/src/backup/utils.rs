use base64::{engine::general_purpose::STANDARD, DecodeError, Engine};

pub fn base64_encode<T: AsRef<[u8]>>(input: T) -> String {
    STANDARD.encode(input)
}

#[allow(dead_code)]
pub fn base64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    STANDARD.decode(input)
}
