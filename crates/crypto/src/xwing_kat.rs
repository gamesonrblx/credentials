//! Draft-11 X-Wing known answers.
//!
//! The vectors are the three objects published with
//! `draft-connolly-cfrg-xwing-kem` and carried by `x-wing` 0.1.1.
//! Decapsulation of each ciphertext under the published secret key must
//! reproduce the shared secret and the encapsulation key.

use x_wing::kem::{Decapsulate, Decapsulator, KeyExport};
use x_wing::DecapsulationKey;

#[derive(serde::Deserialize)]
struct Vector {
    ss: String,
    sk: String,
    pk: String,
    ct: String,
}

#[test]
fn draft11_vectors_decapsulate() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../tests/xwing-draft11.json")).expect("vectors");
    assert_eq!(vectors.len(), 3);
    for vector in vectors {
        let sk = DecapsulationKey::from(hex_array(&vector.sk));
        let pk = sk.encapsulation_key().to_bytes();
        assert_eq!(pk.as_slice(), hex_vec(&vector.pk).as_slice());
        let shared = sk
            .decapsulate_slice(&hex_vec(&vector.ct))
            .expect("decapsulate");
        assert_eq!(shared.as_slice(), hex_vec(&vector.ss).as_slice());
    }
}

fn hex_vec(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_array(value: &str) -> [u8; 32] {
    let bytes = hex_vec(value);
    bytes.try_into().unwrap()
}
