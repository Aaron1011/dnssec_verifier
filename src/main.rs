use bytes::buf::FromBuf;
use bytes::{Bytes, IntoBuf};
use domain::core::bits::compose::Compose;
use domain::core::master::reader::{Reader, ReaderItem};
use domain::core::rdata::MasterRecordData;
use log::debug;
use ring::rand;
use ring::signature::{self, KeyPair};
use std::io::Read;

fn test_ecdsa() {
    let rng = rand::SystemRandom::new();
    let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
    let key_pair =
        signature::EcdsaKeyPair::from_pkcs8(alg, untrusted::Input::from(pkcs8.as_ref())).unwrap();

    const MESSAGE: &'static [u8] = b"hello, world";
    const MESSAGE1: &'static [u8] = b"hello, world a";
    let sig = key_pair
        .sign(&rng, untrusted::Input::from(MESSAGE))
        .unwrap();

    debug!("ECDSA Private : {}", base64::encode(&pkcs8));
    debug!(
        "ECDSA Public  : {:#?}",
        base64::encode(key_pair.public_key())
    );
    debug!("ECDSA Sig     : {:#?}", base64::encode(&sig));
    debug!("ECDSA Public  : {:#?}", key_pair.public_key());

    signature::verify(
        &signature::ECDSA_P256_SHA256_FIXED,
        untrusted::Input::from(key_pair.public_key().as_ref()),
        untrusted::Input::from(MESSAGE),
        untrusted::Input::from(sig.as_ref()),
    )
    .unwrap();
    debug!("ECDSA verified");
}

fn test_ring() {
    // Generate a key pair in PKCS#8 (v2) format.
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let key_pair =
        signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(pkcs8_bytes.as_ref()))
            .unwrap();
    debug!("{:#?}", key_pair);

    // Sign the message "hello, world".
    const MESSAGE: &[u8] = b"hello, world";
    let sig = key_pair.sign(MESSAGE);
    //debug!("{}", sig);

    // Normally an application would extract the bytes of the signature and
    // send them in a protocol message to the peer(s). Here we just get the
    // public key key directly from the key pair.
    let peer_public_key_bytes = key_pair.public_key().as_ref();
    let sig_bytes = sig.as_ref();

    debug!("{:#?}", peer_public_key_bytes);
    debug!("{:#?}", sig_bytes);

    // Verify the signature of the message using the public key. Normally the
    // verifier of the message would parse the inputs to `signature::verify`
    // out of the protocol message(s) sent by the signer.
    let peer_public_key = untrusted::Input::from(peer_public_key_bytes);
    let msg = untrusted::Input::from(MESSAGE);
    let sig = untrusted::Input::from(sig_bytes);
    debug!("{:#?}", peer_public_key);
    debug!("{:#?}", msg);
    debug!("{:#?}", sig);

    signature::verify(&signature::ED25519, peer_public_key, msg, sig).unwrap();
}

fn parse_dnstext(s: &str) -> Vec<domain::core::master::entry::MasterRecord> {
    let reader = Reader::new(s);
    let mut rrs = Vec::new();

    for item in reader {
        match item {
            Ok(item) => match item {
                ReaderItem::Record(record) => rrs.push(record),
                _ => debug!("record item not found"),
            },
            Err(err) => debug!("{:?}", err),
        }
    }
    rrs
}

fn take_one_rr(s: &str) -> Option<domain::core::master::entry::MasterRecord> {
    let rrs = parse_dnstext(s);
    if rrs.is_empty() {
        return None;
    }
    Some(rrs[0].clone())
}

fn main() {
    env_logger::init();
    // test_ring();
    test_ecdsa();

    let zsk = take_one_rr("cloudflare.com.         2992    IN      DNSKEY  257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==");
    let cdnskey = take_one_rr("cloudflare.com.         3600    IN      CDNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==");
    let rrsig = take_one_rr("cloudflare.com.         3600    IN      RRSIG   CDNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. odj8zT4s/4qlGiU6gozw1cBupGxwWf01E+l9cQKqUegbe+CLeg59tdCmIFbGMBFb2tTmTTw3F9vTwb21hwJDUg==");

    let mut peer_public_key = bytes::Bytes::new();
    let mut buf = vec![];
    let mut sig = bytes::Bytes::new();

    match zsk.unwrap().into_data() {
        MasterRecordData::Dnskey(rr) => peer_public_key = rr.public_key().clone(),
        _ => debug!("unknown"),
    }

    match rrsig.unwrap().into_data() {
        MasterRecordData::Rrsig(rr) => {
            let empty_rrsig = domain::core::rdata::Rrsig::new(
                rr.type_covered(),
                rr.algorithm(),
                rr.labels(),
                rr.original_ttl(),
                rr.expiration(),
                rr.inception(),
                rr.key_tag(),
                rr.signer_name().clone(),
                bytes::Bytes::new(),
            );
            //debug!("{:#?}", empty_rrsig);
            /*
            let rec = domain::core::bits::record::Record::new(
                rr.signer_name().clone(),
                domain::core::iana::class::Class::In,
                rr.original_ttl(),
                empty_rrsig,
            );
            debug!("{:#?}", rec);
            //debug!("{:#?}", base64::encode(rr.signature()));
            //rec.compose(&mut buf);
            */
            empty_rrsig.compose(&mut buf);
            debug!("{:?}", buf);

            sig = rr.signature().clone();
        }
        _ => debug!("unknown"),
    }
    cdnskey.unwrap().compose(&mut buf);

    debug!("signature: {:#?}", sig);
    debug!("signature: {:#?}", base64::encode(&sig));
    let vec = Vec::from_buf(sig.clone().into_buf());
    debug!("sig {:?}", vec);
    debug!("public key: {:#?}", peer_public_key);
    debug!("public key: {:#?}", base64::encode(&peer_public_key));
    let mut key_with_prefix: Vec<u8> = vec![0x4];
    let mut key = Vec::from_buf(peer_public_key.clone().into_buf());
    key_with_prefix.append(&mut key);
    debug!("key {:?}", key);
    debug!("buf: {:?}", buf);
    debug!("buf: {:?}", base64::encode(&buf));

    match signature::verify(
        &signature::ECDSA_P256_SHA256_FIXED,
        untrusted::Input::from(&key_with_prefix),
        untrusted::Input::from(&buf),
        untrusted::Input::from(&vec),
    ) {
        Ok(_) => debug!("Success"),
        Err(err) => debug!("Verification Error: {}", err),
    }
}
