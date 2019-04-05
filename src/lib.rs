use bytes::buf::FromBuf;
use bytes::{BufMut, Bytes, BytesMut, IntoBuf};
use chrono::Utc;
use domain::core::bits::compose::Compose;
use domain::core::bits::name::{DnameBuilder, Label, ToDname};
use domain::core::bits::rdata::RecordData;
use domain::core::bits::record::Record;
use domain::core::bits::serial::Serial;
use domain::core::bits::Dname;
use domain::core::iana::class::Class;
use domain::core::rdata;
use log::debug;
use ring::{rand, signature};

// currently only support algorithm 8 and 13
// RSA is restricted to >2048 bit because of ring
pub fn verify_rrsig<N, D>(
    pubkey: &rdata::Dnskey,
    rrs: Vec<Record<N, D>>,
    rrsig: &rdata::Rrsig,
    rrsig_owner: &N,
) -> bool
where
    N: ToDname + Clone + PartialEq + std::fmt::Display,
    D: RecordData + Clone,
{
    let rrsig_algo = rrsig.algorithm();
    let inception = rrsig.inception();
    let expiration = rrsig.expiration();
    let type_covered = rrsig.type_covered();
    let rrsig_orig_ttl = rrsig.original_ttl();
    let rrsig_keytag = rrsig.key_tag();

    // Generate a rrsig with empty signature
    let rrsig_rdata_nosig = rdata::Rrsig::new(
        type_covered,
        rrsig_algo,
        rrsig.labels(),
        rrsig_orig_ttl,
        expiration,
        inception,
        rrsig_keytag,
        rrsig.signer_name().clone(),
        Bytes::new(),
    );

    // return false if the rrsig inception and expiration is out of bounds
    if !rrsig_datetime_is_valid(inception, expiration) {
        return false;
    }

    // return false if the dnskey keytag and rrsig keytag doesn't match
    let keytag = dnskey_keytag(pubkey);
    if keytag != rrsig_keytag {
        debug!("keytag for public({}) != rrsig({})", keytag, rrsig_keytag);
        return false;
    }

    for rr in &rrs {
        // we only support IN class
        if rr.class() != Class::In {
            debug!("unsupported class {}", rr.class());
            return false;
        }

        // Verify owner in rrsig and rrset matches
        if rr.owner().to_name() != rrsig_owner {
            debug!(
                "owner mismatch rrsig({}) vs rr({})",
                rrsig_owner,
                rr.owner().to_name()
            );
            return false;
        }

        // Make sure rrsig type covered is same as rr type
        if type_covered != rr.rtype() {
            debug!("rrsig doesn't cover type {}", rr.rtype());
            return false;
        }

        let rr_ttl = rr.ttl();
        if rrsig_orig_ttl != rr_ttl {
            debug!("ttl({}) != rrsig ttl({})", rr_ttl, rrsig_orig_ttl);
            return false;
        }
    }

    // buffer to hold DNS binary message for verification
    let mut message = vec![];

    // Add rrsig rdata without the signature
    rrsig_rdata_nosig.compose(&mut message);

    // Add canonically sorted rrset to the buffer
    let mut sorted_rrset_bytes = prepare_rrset_to_sign(rrs, rrsig.original_ttl());
    message.append(&mut sorted_rrset_bytes);

    let sig = Vec::from_buf(rrsig.signature().clone().into_buf());

    // Add 0x4 idenfitifer to the ECDSA pubkey
    // required for crypto libraries
    let mut key: Vec<u8>;
    if rrsig_algo == 13 {
        key = vec![0x4];
        let mut a = Vec::from_buf(pubkey.public_key().clone().into_buf());
        key.append(&mut a);
    } else {
        key = Vec::from_buf(pubkey.public_key().clone().into_buf());
    }

    let message = untrusted::Input::from(&message);
    let sig = untrusted::Input::from(&sig);

    let res = match rrsig_algo.to_int() {
        8 => {
            // Extract public key exponent and modulus
            let (e, m) = rsa_exponent_modulus(&key).unwrap();
            let e = untrusted::Input::from(e);
            let m = untrusted::Input::from(m);
            signature::primitive::verify_rsa(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                (m, e),
                message,
                sig,
            )
        }
        13 => {
            let key = untrusted::Input::from(&key);
            signature::verify(&signature::ECDSA_P256_SHA256_FIXED, key, message, sig)
        }
        _ => {
            debug!("unknown algorithm {:#?}", rrsig_algo);
            Err(ring::error::Unspecified)
        }
    };

    match res {
        Ok(_) => true,
        Err(err) => {
            debug!("verification failed: {}", err);
            false
        }
    }
}

fn canonical_owner<N>(owner: &N) -> Dname
where
    N: ToDname + Clone,
{
    let mut dname_builder = DnameBuilder::new();
    for label in owner.to_name().iter() {
        let m: Vec<u8> = label.iter().map(u8::to_ascii_lowercase).collect();
        let label = Label::from_slice(&m).unwrap();
        dname_builder.append_label(label).unwrap();
    }
    dname_builder.into_dname().unwrap()
}

// prepares dns message from sorted rrset
// sorting is done as per https://tools.ietf.org/html/rfc4034#section-6.3
fn prepare_rrset_to_sign<N, D>(rrs: Vec<Record<N, D>>, ttl: u32) -> Vec<u8>
where
    N: ToDname + Clone,
    D: RecordData + Clone,
{
    let mut rr_data: Vec<Vec<u8>> = vec![vec![0]; rrs.len()];
    for (i, rr) in rrs.iter().enumerate() {
        let mut b = vec![];
        let rr = rr.clone();

        // build a new record with lowercased labels
        let mut rr = Record::new(
            canonical_owner(&rr.owner()),
            rr.class(),
            ttl,
            rr.into_data(),
        );
        rr.set_ttl(ttl);
        rr.compose(&mut b);
        rr_data[i] = b;
    }

    // sort by member byte array
    // a[0] = vec![4,5,6]
    // a[1] = vec![1,2,3]
    // returns
    // a[0] = vec![1,2,3]
    // a[1] = vec![4,5,6]
    rr_data.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // Collapse sorted multi dimension byte vector
    // a[0] = vec![1,2,3]
    // a[1] = vec![4,5,6]
    // returns
    // c = vec![1,2,3,4,5,6]
    let mut sorted_rr_bytes = vec![];
    for mut v in rr_data {
        sorted_rr_bytes.append(&mut v);
    }

    sorted_rr_bytes
}

// returns public key exponent and modulus from the dnskey encoded rsa pub key
// see https://tools.ietf.org/html/rfc3110#section-2 for dnskey format
// following code copied from
// https://github.com/bluejekyll/trust-dns/blob/master/crates/proto/src/rr/dnssec/rsa_public_key.rs#L16
fn rsa_exponent_modulus(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (e_len_len, e_len) = match input.get(0) {
        Some(&0) if input.len() >= 3 => (3, (usize::from(input[1]) << 8) | usize::from(input[2])),
        Some(e_len) if *e_len != 0 => (1, usize::from(*e_len)),
        _ => {
            return None;
        }
    };

    if input.len() < e_len_len + e_len {
        return None;
    };

    Some(input[e_len_len..].split_at(e_len))
}

fn rrsig_datetime_is_valid(inception: Serial, expiration: Serial) -> bool {
    let now = Utc::now().timestamp() as u32;
    let now = Serial(now);

    now >= inception && expiration >= now
}

pub fn ecdsa_sign(
    rng: &rand::SystemRandom,
    keypair: &ring::signature::EcdsaKeyPair,
    message: Vec<u8>,
) -> Vec<u8> {
    keypair
        .sign(rng, untrusted::Input::from(&message))
        .unwrap()
        .as_ref()
        .to_owned()
}

pub fn rsa_sign(
    rng: &rand::SystemRandom,
    keypair: &ring::signature::RsaKeyPair,
    message: Vec<u8>,
) -> Vec<u8> {
    let mut sig = vec![0; keypair.public_modulus_len()];
    keypair
        .sign(&signature::RSA_PKCS1_SHA256, rng, &message, &mut sig)
        .unwrap();
    sig
}

pub fn ecdsa_keypair(rng: &rand::SystemRandom) -> ring::signature::EcdsaKeyPair {
    let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(alg, rng).unwrap();
    signature::EcdsaKeyPair::from_pkcs8(alg, untrusted::Input::from(pkcs8.as_ref())).unwrap()
}

pub fn rsa_keypair() -> ring::signature::RsaKeyPair {
    let b = base64::decode(
        &"
MIIEpAIBAAKCAQEA4W8gkDyQZCWoFSAxiUmyrIA7H9tpd1EHkGxBDrpIOf+OT57s
AA5ROIZwwaPn5pqurU69tVbIglt/BKk1gwlFz3qGmGb1feaiqAhTGvan3yT2j+Qi
WxQz0VNxuZPhiKEQCk+QrCvZMV29q4gROVnIYC2T3+XQptu3+zzkfGTqCy5KkizW
IiZnbNszHUisXHF4+rB4coiWlIpd0MB9M3maCHqUpXqDmMRqr7V0foZXwTvkVfND
SZjWCs3LvINHIipS4+7ickj+VarMyDLIOYJhLakZ+7SHp/ZPLF/QB2jW8o22C8o5
2nHj1g7k6i5jr0LvmxXRayv4YSy8BfUKuuzTAQIDAQABAoIBAG8vQu1AoapzFCJP
PX9LtO71U7PToIGzmjp12eRspeDNFSBZ7mXcqdxqGkS3FVIcKljZxCEjC0OX4t6m
ofjd4uuAr8+MwDl3PfQIHwzmaEdbUKwJRZSMMz5jnGx97jdX0LR1J5JzEe0SIdDv
DCewC268K/m6vBz/sw8bqklb8D7QiZofje+u3ZO2jlQhtPSJdOdR5jvf1AMG0WXy
hB0eGiJOC0VgybWELLTjPbC+aAuaf05kzDPa7SiILFk0P2bxMFA8lqadF8bLrlR5
NrrpaKNbDpqeMwqlImnLKLZQHPXpwyy1QiXEivihCWjhlkheTH4mkqLDeOToo1Ec
UsJrKv0CgYEA/zEwzf/dRfoZ1K1jOPbRwWGUQNPSUG65LgElbqCIx9ddqxovl62W
s70BwaPSGlTi8wfiJwVGPERhb9UrpDILcmgBlH/qMCkCnhsvb/Xb3GnQS39u7fad
x35WDhsMyd1KRwOp0aPt0euWUCyOBqdl2rEov1C4cMWH5SHMYXbi/wMCgYEA4iXS
B/9WBb9LMYJTc6YCvPg7TpkMdgKAwVYAdwC6EVXSLI9vM+C9qO/d8pRHNMhJfcSd
CYnoQgp+WK1e5vxQFQnIrNPTH8iZaRG2WCkJuIxYdl6UxZ5eM0a/hND5MNeHXQSP
I3d2ezIjuaghpCUv3PyX1jWNiLKr1L806iAK1KsCgYAbwGa1UEjo7jzW4xAyRq0i
4ZC0yBRMCO58cUV31V9qlCIslElurkMAQuKpAz66/FY95bKTWcB8l1cdSUpYrdSO
2X6qfoqiOCN/vCcZftwtCRjMzQvsNvCLnFKRcCGg5j7IoD5cfP5E4ODU0TOUx6mM
8c0jmQylvuV7ZoSKaNpgrwKBgQDC6J3QzryxT2HbVdve/OG3RKq43yfiPd4Cw8C6
0CGN902hoi3RpI1SIQpFnI6Sa10LzH0cT4OiB7FFdIcqxaOvvjL64cZAyn+OEvn5
mcULDcrgmjvW5tuBjiRasFFVSy0bemZzxu6S12/6/3GfK33JFNs4gAdwHa4DOpi8
gMlU6QKBgQChi/b3efERN1n4BpKZOXC+Fh53aAcA59aH3SAFFvJn9+zIEhfk327q
aYrWpkyQFWwA2e4M5WEw7xuEbWXtvNg39YlDxVRlYY6PK7wrSGw7FhDaEMfjkPA0
PvJwvKhYPuBDSMSrYa28c6Q9F+SjUjKvm81lyIo+k86hLBfjCxNgVA==
"
        .replace('\n', ""),
    )
    .unwrap();
    signature::RsaKeyPair::from_der(untrusted::Input::from(&b)).unwrap()
}

// remove leading 0x4 from ecdsa pub key for dnskey rdata
pub fn ecdsa_dnskey_pubkey(keypair: &impl ring::signature::KeyPair) -> Bytes {
    let b = keypair.public_key().as_ref();
    if b.is_empty() || b.len() < 2 {
        return Bytes::new();
    }
    Bytes::from(&b[1..])
}

pub fn rsa_pubkey_from_keypair(keypair: &ring::signature::RsaKeyPair) -> Bytes {
    let pubkey = signature::KeyPair::public_key(keypair);
    let modulus = pubkey
        .modulus()
        .big_endian_without_leading_zero()
        .as_slice_less_safe();
    let modulus_len = keypair.public_modulus_len();
    let exponent = pubkey
        .exponent()
        .big_endian_without_leading_zero()
        .as_slice_less_safe();
    let exponent_len = exponent.len() as u8;

    debug!("modulus: {:?}", modulus);
    debug!("exponent: {:?}", exponent);
    debug!("modulus len: {:#?}", modulus_len);
    debug!("exponent len: {:#?}", exponent_len);

    let mut buf = BytesMut::with_capacity(1 + exponent.len() + modulus.len());
    // Assuming the exponent len is less than 256
    buf.put(exponent_len);
    buf.put(exponent);
    buf.put(modulus);
    buf.freeze()
}

// copied from https://github.com/miekg/dns/blob/master/dnssec.go#L135
pub fn dnskey_keytag(dnskey: &rdata::Dnskey) -> u16 {
    let mut buf = vec![];
    dnskey.compose(&mut buf);
    let mut keytag: u32 = 0;

    for (i, v) in buf.iter().enumerate() {
        if i & 1 != 0 {
            keytag += u32::from(*v);
        } else {
            keytag += u32::from(*v) << 8;
        }
    }
    keytag += (keytag >> 16) & 0xffff;
    keytag &= 0xffff;
    keytag as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use domain::core::bits::name::Dname;
    use domain::core::bits::record::Record;
    use domain::core::iana::rtype::Rtype;
    use domain::core::iana::secalg::SecAlg;
    use domain::core::master::entry::MasterRecord;
    use domain::core::master::reader::{Reader, ReaderItem};
    use domain::core::rdata::MasterRecordData;
    use std::str::FromStr;

    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn parse_dnstext(s: &str) -> Vec<MasterRecord> {
        let reader = Reader::new(s);
        let mut rrs = Vec::new();

        for item in reader {
            match item {
                Ok(item) => match item {
                    ReaderItem::Record(record) => rrs.push(record),
                    _ => debug!("record item not found"),
                },
                Err(err) => debug!("parse_dnstext err: {:?}", err),
            }
        }
        rrs
    }

    fn take_one_rr(s: &str) -> Option<MasterRecord> {
        let rrs = parse_dnstext(s);
        if rrs.is_empty() {
            return None;
        }
        Some(rrs[0].clone())
    }

    fn verify_rrsig_helper(dnskey: &str, rrsig: &str, rrs: Vec<&str>) -> bool {
        let dnskey = take_one_rr(dnskey).unwrap();
        let rrsig = take_one_rr(rrsig).unwrap();
        let mut rrset = vec![];
        if !rrs.is_empty() {
            for s in rrs {
                let rr = take_one_rr(s).unwrap();
                rrset.push(rr);
            }
        }

        let pubkey: Option<rdata::Dnskey> = match dnskey.into_data() {
            MasterRecordData::Dnskey(rr) => Some(rr),
            _ => None,
        };

        let sig = match rrsig.data() {
            MasterRecordData::Rrsig(rr) => Some(rr),
            _ => None,
        };

        verify_rrsig(&pubkey.unwrap(), rrset, &sig.unwrap(), rrsig.owner())
    }

    fn new_rrsig(
        owner: Dname,
        ttl: u32,
        dnskey: &rdata::Dnskey,
        rtype: Rtype,
        algo: SecAlg,
    ) -> rdata::Rrsig {
        let label_cnt = owner.label_count() as u8;
        let keytag = dnskey_keytag(dnskey);
        let validity_days = 1;

        let i = Serial((Utc::now() - Duration::days(validity_days)).timestamp() as u32);
        let e = Serial((Utc::now() + Duration::days(validity_days)).timestamp() as u32);

        rdata::Rrsig::new(
            rtype,
            algo,
            label_cnt,
            ttl,
            e,
            i,
            keytag,
            owner,
            Bytes::new(),
        )
    }

    fn new_rrsig_with_signature(rrsig: &rdata::Rrsig, signature: Vec<u8>) -> rdata::Rrsig {
        rdata::Rrsig::new(
            rrsig.type_covered(),
            rrsig.algorithm(),
            rrsig.labels(),
            rrsig.original_ttl(),
            rrsig.expiration(),
            rrsig.inception(),
            rrsig.key_tag(),
            rrsig.signer_name().clone(),
            Bytes::from(signature),
        )
    }

    fn dnskey_str(owner: &Dname, dnskey: &rdata::Dnskey) -> String {
        Record::new(owner.clone(), Class::In, 300, dnskey.clone()).to_string()
    }

    fn record_with_owner(owner: &Dname, data: &str) -> String {
        let mut a = String::from(owner.to_string());
        // Append the last label . and a space
        a.push_str(". ");
        a.push_str(data);
        a
    }

    fn rrset_with_owner(owner: &Dname, data: Vec<&str>) -> Vec<MasterRecord> {
        let mut rrset = vec![];

        for s in data {
            let rr = take_one_rr(&record_with_owner(owner, s)).unwrap();
            rrset.push(rr);
        }
        rrset
    }

    // Mock Signer to generate verifiable RRSIGs
    struct Signer<'a> {
        pub secalg: SecAlg,
        pub rng: rand::SystemRandom,
        pub ecdsa_keypair: Option<signature::EcdsaKeyPair>,
        pub rsa_keypair: Option<signature::RsaKeyPair>,
        pub pubkey: Bytes,
        pub owner_str: &'a str,
        pub owner: Dname,
        pub protocol: u8,
        pub flag: u16,
        pub dnskey: rdata::Dnskey,
    }

    impl<'a> Signer<'a> {
        fn new(owner_str: &str, secalg: SecAlg) -> Option<Signer> {
            let rng = rand::SystemRandom::new();
            let protocol = 3;
            let flag = 256;

            match secalg {
                SecAlg::EcdsaP256Sha256 => {
                    let keypair = ecdsa_keypair(&rng);
                    let pubkey = ecdsa_dnskey_pubkey(&keypair);
                    Some(Signer {
                        secalg,
                        rng,
                        ecdsa_keypair: Some(keypair),
                        rsa_keypair: None,
                        pubkey: pubkey.clone(),
                        owner_str,
                        owner: Dname::from_str(owner_str).unwrap(),
                        protocol,
                        flag,
                        dnskey: rdata::Dnskey::new(
                            flag,
                            protocol,
                            SecAlg::EcdsaP256Sha256,
                            bytes::Bytes::from(pubkey),
                        ),
                    })
                }

                SecAlg::RsaSha256 => {
                    let keypair = rsa_keypair();
                    let pubkey = rsa_pubkey_from_keypair(&keypair);
                    return Some(Signer {
                        secalg,
                        rng,
                        ecdsa_keypair: None,
                        rsa_keypair: Some(keypair),
                        pubkey: pubkey.clone(),
                        owner_str,
                        owner: Dname::from_str(owner_str).unwrap(),
                        protocol,
                        flag,
                        dnskey: rdata::Dnskey::new(
                            flag,
                            protocol,
                            SecAlg::RsaSha256,
                            bytes::Bytes::from(pubkey),
                        ),
                    });
                }
                _ => return None,
            }
        }

        fn sign<N, D>(&self, rrset: &Vec<Record<N, D>>) -> Option<rdata::Rrsig>
        where
            N: ToDname + Clone + PartialEq,
            D: RecordData + Clone,
        {
            if rrset.is_empty() {
                return None;
            }

            let mut message = vec![];
            let rrsig_ttl = rrset[0].ttl();
            let rrsig = new_rrsig(
                canonical_owner(&self.owner),
                rrsig_ttl,
                &self.dnskey,
                rrset[0].rtype(),
                self.secalg,
            );
            rrsig.compose(&mut message);
            let mut sorted_rrset_bytes = prepare_rrset_to_sign(rrset.clone(), rrsig.original_ttl());
            message.append(&mut sorted_rrset_bytes);

            let mut signature: Vec<u8> = vec![0];
            match self.secalg {
                SecAlg::EcdsaP256Sha256 => {
                    if let Some(keypair) = &self.ecdsa_keypair {
                        signature = ecdsa_sign(&self.rng, &keypair, message);
                    }
                }
                SecAlg::RsaSha256 => {
                    if let Some(keypair) = &self.rsa_keypair {
                        signature = rsa_sign(&self.rng, &keypair, message);
                    }
                }
                _ => return None,
            }
            Some(new_rrsig_with_signature(&rrsig, signature))
        }
    }

    // corrupt rrsig signature
    fn corrupt_signature(rrsig: &rdata::Rrsig) -> rdata::Rrsig {
        let mut c = rrsig.signature().to_vec();
        assert!(c.len() > 0);
        c[0] = c[0] + 1;
        new_rrsig_with_signature(rrsig, c)
    }

    // helper to generate test data
    fn mock_signed_rrs(secalg: SecAlg) -> (Signer<'static>, Vec<MasterRecord>, rdata::Rrsig) {
        let signer = Signer::new("example.com", secalg).unwrap();
        debug!("dnskey : {}", dnskey_str(&signer.owner, &signer.dnskey));
        let rrset = rrset_with_owner(
            &signer.owner,
            vec![" 3600 IN A 192.0.2.1", " 3600 IN A 192.0.2.2"],
        );
        for rr in &rrset {
            debug!("{}", rr);
        }
        let rrsig = signer.sign(&rrset).unwrap();
        debug!("rrsig : {}", rrsig);

        (signer, rrset, rrsig)
    }

    fn mock_signed_rrs_from_rrset(
        owner: &'static str,
        secalg: SecAlg,
        rrset: Vec<&str>,
    ) -> (Signer<'static>, Vec<MasterRecord>, rdata::Rrsig) {
        let signer = Signer::new(owner, secalg).unwrap();
        debug!("dnskey : {}", dnskey_str(&signer.owner, &signer.dnskey));
        let rrset = rrset_with_owner(&signer.owner, rrset);
        for rr in &rrset {
            debug!("{}", rr);
        }
        let rrsig = signer.sign(&rrset).unwrap();
        debug!("rrsig : {}", rrsig);

        (signer, rrset, rrsig)
    }

    #[test]
    fn verify_rrsig_ecdsa_good_signature() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs(SecAlg::EcdsaP256Sha256);
        assert!(verify_rrsig(&signer.dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn verify_rrsig_ecdsa_bad_signature() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs(SecAlg::EcdsaP256Sha256);
        // corrupt rrsig signature
        let rrsig = corrupt_signature(&rrsig);
        debug!("corrupt rrsig : {}", rrsig);
        assert!(!verify_rrsig(&signer.dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn verify_rrsig_rsa_good_signature() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs(SecAlg::RsaSha256);
        assert!(verify_rrsig(&signer.dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn verify_rrsig_rsa_bad_signature() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs(SecAlg::RsaSha256);
        // corrupt rrsig signature
        let rrsig = corrupt_signature(&rrsig);
        debug!("corrupt rrsig : {}", rrsig);
        assert!(!verify_rrsig(&signer.dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn verify_rrsig_ecdsa_mixed_case() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs_from_rrset(
            "exaMpLe.Com",
            SecAlg::EcdsaP256Sha256,
            vec![" 3600 IN A 192.0.2.1", " 3600 IN A 192.0.2.2"],
        );
        assert!(verify_rrsig(&signer.dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_order() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs_from_rrset(
            "example.com",
            SecAlg::EcdsaP256Sha256,
            vec![" 3600 IN A 192.0.2.3", " 3600 IN A 192.0.2.2"],
        );
        assert!(verify_rrsig(&signer.dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_ttl() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs_from_rrset(
            "example.com",
            SecAlg::EcdsaP256Sha256,
            vec![" 3600 IN A 192.0.2.1", " 300 IN A 192.0.2.2"],
        );
        assert!(!verify_rrsig(&signer.dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_class() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs_from_rrset(
            "example.com",
            SecAlg::EcdsaP256Sha256,
            vec![" 3600 IN A 192.0.2.1", " 300 IN AAAA 2001:DB8::1"],
        );
        assert!(!verify_rrsig(&signer.dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_owner() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs(SecAlg::EcdsaP256Sha256);
        let rrsig_owner = Dname::from_str("evil.com").unwrap();
        assert!(!verify_rrsig(&signer.dnskey, rrset, &rrsig, &rrsig_owner));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_type() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs(SecAlg::EcdsaP256Sha256);
        // change the covered type to NS
        let rrsig = rdata::Rrsig::new(
            Rtype::Ns,
            rrsig.algorithm(),
            rrsig.labels(),
            rrsig.original_ttl(),
            rrsig.expiration(),
            rrsig.inception(),
            rrsig.key_tag(),
            rrsig.signer_name().clone(),
            rrsig.signature().clone(),
        );
        debug!("mangled rrsig: {}", rrsig);
        assert!(!verify_rrsig(&signer.dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_keytag() {
        init_logger();
        let (signer, rrset, rrsig) = mock_signed_rrs(SecAlg::EcdsaP256Sha256);
        let wrong_dnskey = Signer::new(signer.owner_str, SecAlg::EcdsaP256Sha256)
            .unwrap()
            .dnskey;
        debug!("dnskey: {}", dnskey_str(&signer.owner, &wrong_dnskey));
        assert!(!verify_rrsig(&wrong_dnskey, rrset, &rrsig, &signer.owner));
    }

    #[test]
    fn rrsig_datetime_good() {
        init_logger();
        let offset = 1;
        let i = Serial((Utc::now() - Duration::days(offset)).timestamp() as u32);
        let e = Serial((Utc::now() + Duration::days(offset)).timestamp() as u32);
        assert!(rrsig_datetime_is_valid(i, e));
    }

    #[test]
    fn rrsig_datetime_expired() {
        init_logger();
        let offset = 1;
        let i = Serial((Utc::now() - Duration::days(offset)).timestamp() as u32);
        let e = Serial((Utc::now() - Duration::days(offset)).timestamp() as u32);
        assert!(!rrsig_datetime_is_valid(i, e));
    }

    #[test]
    fn rrsig_datetime_incepted_in_future() {
        init_logger();
        let offset = 1;
        let i = Serial((Utc::now() + Duration::days(offset)).timestamp() as u32);
        let e = Serial((Utc::now() + Duration::days(offset)).timestamp() as u32);
        assert!(!rrsig_datetime_is_valid(i, e));
    }

    #[test]
    fn dnskey_keytag_test() {
        let dnskey = take_one_rr("cloudflare.com. 600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==").unwrap();
        let pubkey: Option<rdata::Dnskey> = match dnskey.into_data() {
            MasterRecordData::Dnskey(rr) => Some(rr),
            _ => None,
        };
        let keytag = dnskey_keytag(&pubkey.unwrap());
        debug!("{}", keytag);
        assert_eq!(keytag, 34505);
    }

    #[test]
    #[ignore]
    fn verify_rrsig_rsa_good_signature_1024() {
        init_logger();
        assert!(verify_rrsig_helper(
        "nz. 3046 IN DNSKEY 256 3 8 AwEAAbhtcqZIlIYHyCzbBU8sa3W8f+lTYW0gFa+E/VjNJoRJ0FUrClmMI9EPTqfM1ujAkNIbewRC36GHSQ65jlwonCafO4eHbbhkBMuuKvMe2bf7f/csQvQ1PS1kNgl5fRFVIrDbne9I5kAcyVXoSMzRipGClHkHn+yNi/FGkIwNjE0H",
        "nz. 86400 IN RRSIG SOA 8 1 86400 20190406023219 20190322235821 16825 nz. XHH+w9a3vbmLFLvbi/5hXmQzCzIigGBZNIFDUOhOqaDbXbdSr602/iAglp7FXpcNxHefd2zfTM7kGQcuqbHwE72Kj5mcP8s+OHzWm1svxgMKQ0LJ6QnLy5B8DWR81bGEUuXIojNe4kRnUnJVJFew/7LCx6S4U51UprcrHuryYI8=",
        vec!["nz. 86400 IN SOA loopback.dns.net.nz. soa.nzrs.net.nz. 2019032353 900 300 604800 3600"],
        ));
    }
}
