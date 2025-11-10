use crate::interpreter::{
    precompiles::{PrecompileContext, PrecompileError, PrecompileResult},
    System,
};
use fil_actors_runtime::runtime::Runtime;

// p256 + ecdsa
use p256::ecdsa::{self, Signature, VerifyingKey};
// no need for EncodedPoint type import; we build SEC1 bytes directly

/// RIP-7212 P256VERIFY precompile
///
/// Input (160 bytes, big-endian):
///  - 32: message digest (hash)
///  - 32: r
///  - 32: s
///  - 32: x
///  - 32: y
/// Output:
///  - On success: 32-byte big-endian integer 1
///  - On failure: empty
pub fn p256_verify<RT: Runtime>(_: &mut System<RT>, input: &[u8], _: PrecompileContext) -> PrecompileResult {
    if input.len() != 160 {
        return Err(PrecompileError::IncorrectInputSize);
    }

    let hash = &input[0..32];
    let r = &input[32..64];
    let s = &input[64..96];
    let x = &input[96..128];
    let y = &input[128..160];

    // Reject (x,y) == (0,0) explicitly per spec.
    let all_zero = |b: &[u8]| b.iter().all(|&bb| bb == 0);
    if all_zero(x) && all_zero(y) {
        return Err(PrecompileError::InvalidInput);
    }

    // Build an uncompressed SEC1 encoded point from (x,y) = 0x04 || X || Y
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..65].copy_from_slice(y);

    // Parse verifying key; this enforces point is on curve and coordinates < p.
    let vk = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| PrecompileError::InvalidInput)?;

    // Concatenate r||s into a 64-byte raw signature.
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(r);
    sig_bytes[32..64].copy_from_slice(s);
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| PrecompileError::InvalidInput)?;

    // Verify over pre-hashed message (32 bytes).
    // Use hazmat prehash verifier to avoid re-hashing.
    use ecdsa::signature::hazmat::PrehashVerifier;
    match VerifyingKey::verify_prehash(&vk, hash, &sig) {
        Ok(()) => {
            let mut out = [0u8; 32];
            out[31] = 1;
            Ok(out.to_vec())
        }
        Err(_) => Ok(vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fil_actors_runtime::test_utils::MockRuntime;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn verify_valid_signature_returns_one() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let mut rng = StdRng::seed_from_u64(42);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::from(&sk);

        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);

        let sig: p256::ecdsa::Signature = PrehashSigner::sign_prehash(&sk, &hash).unwrap();

        let pk = vk.to_encoded_point(false);
        let (x, y) = (pk.x().unwrap(), pk.y().unwrap());
        let (r_bytes, s_bytes) = (sig.r().to_bytes(), sig.s().to_bytes());

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&r_bytes);
        input.extend_from_slice(&s_bytes);
        input.extend_from_slice(x);
        input.extend_from_slice(y);

        let out = p256_verify::<MockRuntime>(&mut sys, &input, default_ctx()).unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(out[31], 1);
        assert!(out[..31].iter().all(|b| *b == 0));
    }

    #[test]
    fn verify_wrong_hash_returns_empty() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let mut rng = StdRng::seed_from_u64(1337);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::from(&sk);

        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        let sig: p256::ecdsa::Signature = PrehashSigner::sign_prehash(&sk, &hash).unwrap();

        // Mutate the hash to make it invalid.
        hash[0] ^= 0x01;

        let pk = vk.to_encoded_point(false);
        let (x, y) = (pk.x().unwrap(), pk.y().unwrap());
        let (r_bytes, s_bytes) = (sig.r().to_bytes(), sig.s().to_bytes());

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&r_bytes);
        input.extend_from_slice(&s_bytes);
        input.extend_from_slice(x);
        input.extend_from_slice(y);

        let out = p256_verify::<MockRuntime>(&mut sys, &input, default_ctx()).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn invalid_input_size() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let err = p256_verify::<MockRuntime>(&mut sys, &[0u8; 10], default_ctx())
            .err()
            .unwrap();
        matches!(err, PrecompileError::IncorrectInputSize);
    }

    #[test]
    fn invalid_r_zero() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let mut rng = StdRng::seed_from_u64(99);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::from(&sk);

        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        let sig: p256::ecdsa::Signature = PrehashSigner::sign_prehash(&sk, &hash).unwrap();

        let pk = vk.to_encoded_point(false);
        let (x, y) = (pk.x().unwrap(), pk.y().unwrap());

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&[0u8; 32]); // r = 0
        input.extend_from_slice(&sig.s().to_bytes());
        input.extend_from_slice(x);
        input.extend_from_slice(y);

        let err = p256_verify::<MockRuntime>(&mut sys, &input, default_ctx()).err().unwrap();
        matches!(err, PrecompileError::InvalidInput);
    }

    #[test]
    fn invalid_s_zero() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let mut rng = StdRng::seed_from_u64(100);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::from(&sk);

        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        let sig: p256::ecdsa::Signature = PrehashSigner::sign_prehash(&sk, &hash).unwrap();

        let pk = vk.to_encoded_point(false);
        let (x, y) = (pk.x().unwrap(), pk.y().unwrap());

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&sig.r().to_bytes());
        input.extend_from_slice(&[0u8; 32]); // s = 0
        input.extend_from_slice(x);
        input.extend_from_slice(y);

        let err = p256_verify::<MockRuntime>(&mut sys, &input, default_ctx()).err().unwrap();
        matches!(err, PrecompileError::InvalidInput);
    }

    #[test]
    fn invalid_r_ge_n() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let mut rng = StdRng::seed_from_u64(101);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::from(&sk);

        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        let sig: p256::ecdsa::Signature = PrehashSigner::sign_prehash(&sk, &hash).unwrap();

        // r >= n: use 0xff..ff as a guaranteed out-of-range value
        let r_bad = [0xffu8; 32];

        let pk = vk.to_encoded_point(false);
        let (x, y) = (pk.x().unwrap(), pk.y().unwrap());

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&r_bad);
        input.extend_from_slice(&sig.s().to_bytes());
        input.extend_from_slice(x);
        input.extend_from_slice(y);

        let err = p256_verify::<MockRuntime>(&mut sys, &input, default_ctx()).err().unwrap();
        matches!(err, PrecompileError::InvalidInput);
    }

    #[test]
    fn invalid_s_ge_n() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let mut rng = StdRng::seed_from_u64(102);
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::from(&sk);

        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        let sig: p256::ecdsa::Signature = PrehashSigner::sign_prehash(&sk, &hash).unwrap();

        let s_bad = [0xffu8; 32];

        let pk = vk.to_encoded_point(false);
        let (x, y) = (pk.x().unwrap(), pk.y().unwrap());

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&sig.r().to_bytes());
        input.extend_from_slice(&s_bad);
        input.extend_from_slice(x);
        input.extend_from_slice(y);

        let err = p256_verify::<MockRuntime>(&mut sys, &input, default_ctx()).err().unwrap();
        matches!(err, PrecompileError::InvalidInput);
    }

    #[test]
    fn invalid_pubkey_zero_zero() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let mut rng = StdRng::seed_from_u64(103);
        let sk = SigningKey::random(&mut rng);

        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        let sig: p256::ecdsa::Signature = PrehashSigner::sign_prehash(&sk, &hash).unwrap();

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&sig.r().to_bytes());
        input.extend_from_slice(&sig.s().to_bytes());
        input.extend_from_slice(&[0u8; 32]); // x = 0
        input.extend_from_slice(&[0u8; 32]); // y = 0

        let err = p256_verify::<MockRuntime>(&mut sys, &input, default_ctx()).err().unwrap();
        matches!(err, PrecompileError::InvalidInput);
    }

    #[test]
    fn invalid_pubkey_off_curve() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let mut rng = StdRng::seed_from_u64(104);
        let sk = SigningKey::random(&mut rng);

        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        let sig: p256::ecdsa::Signature = PrehashSigner::sign_prehash(&sk, &hash).unwrap();

        let mut x = [0u8; 32];
        x[31] = 1; // x=1
        let y = [0u8; 32]; // y=0

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&sig.r().to_bytes());
        input.extend_from_slice(&sig.s().to_bytes());
        input.extend_from_slice(&x);
        input.extend_from_slice(&y);

        let err = p256_verify::<MockRuntime>(&mut sys, &input, default_ctx()).err().unwrap();
        matches!(err, PrecompileError::InvalidInput);
    }

    #[test]
    fn invalid_pubkey_coords_ge_p() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut sys = crate::interpreter::System::create(&rt).unwrap();

        let mut rng = StdRng::seed_from_u64(105);
        let sk = SigningKey::random(&mut rng);

        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        let sig: p256::ecdsa::Signature = PrehashSigner::sign_prehash(&sk, &hash).unwrap();

        // x and/or y >= p: use 0xff..ff to ensure invalid
        let x = [0xffu8; 32];
        let y = [0xffu8; 32];

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&sig.r().to_bytes());
        input.extend_from_slice(&sig.s().to_bytes());
        input.extend_from_slice(&x);
        input.extend_from_slice(&y);

        let err = p256_verify::<MockRuntime>(&mut sys, &input, default_ctx()).err().unwrap();
        matches!(err, PrecompileError::InvalidInput);
    }

    fn default_ctx() -> PrecompileContext {
        PrecompileContext { call_type: crate::interpreter::CallKind::StaticCall, gas: 0u8.into(), value: 0u8.into() }
    }
}
