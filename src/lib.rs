use bytes::buf::FromBuf;
use bytes::IntoBuf;
use chrono::Utc;
use domain::core::bits::compose::Compose;
use domain::core::bits::name::{DnameBuilder, Label, ToDname};
use domain::core::bits::rdata::RecordData;
use domain::core::bits::record::Record;
use domain::core::bits::serial::Serial;
use domain::core::iana::class::Class;
use domain::core::rdata;
use log::debug;
use ring::{rand, signature};

// currently on support algorith 8 and 13
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

    let rrsig_rdata_nosig = rdata::Rrsig::new(
        type_covered,
        rrsig_algo,
        rrsig.labels(),
        rrsig.original_ttl(),
        expiration,
        inception,
        rrsig.key_tag(),
        rrsig.signer_name().clone(),
        bytes::Bytes::new(),
    );

    // return false if the rrsig inception and expiration is out of bounds
    // to now
    if !rrsig_datetime_is_valid(inception, expiration) {
        return false;
    }

    for rr in &rrs {
        // we don't support any other types that IN
        if rr.class() != Class::In {
            debug!("unsupported class {}", rr.class());
            return false;
        }

        // Verify that the owner in RRSIG and RRSet are same
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
    }

    // buf to be signed/verified
    let mut message = vec![];

    // Add RRSIG rdata without the signature
    rrsig_rdata_nosig.compose(&mut message);

    // rrset
    let mut sorted_rrset_bytes = prepare_rrset_to_sign(rrs, rrsig.original_ttl());
    message.append(&mut sorted_rrset_bytes);

    let sig = Vec::from_buf(rrsig.signature().clone().into_buf());

    // Add 0x4 idenfitifer to the ECDSA pubkey
    // required for crypto libraries to recognize
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

// prepares dns message from sorted rrset
// sorting is done as per https://tools.ietf.org/html/rfc4034#section-6.3
// TODO: Verify the owner is same
fn prepare_rrset_to_sign<N, D>(rrs: Vec<Record<N, D>>, ttl: u32) -> Vec<u8>
where
    N: ToDname + Clone,
    D: RecordData + Clone,
{
    let mut rr_data: Vec<Vec<u8>> = vec![vec![0]; rrs.len()];
    for (i, rr) in rrs.iter().enumerate() {
        let mut b = vec![];
        let rr = rr.clone();

        // build a new Dname with lowercased labels
        let mut dname_builder = DnameBuilder::new();
        for l in rr.owner().to_name().iter() {
            let m: Vec<u8> = l.iter().map(u8::to_ascii_lowercase).collect();
            let l = Label::from_slice(&m).unwrap();
            dname_builder.append_label(l).unwrap();
        }

        // build a new record with lowercased labels
        let mut rr = Record::new(
            dname_builder.into_dname().unwrap(),
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

fn ecdsa_sign(
    rng: &rand::SystemRandom,
    key_pair: &ring::signature::EcdsaKeyPair,
    message: Vec<u8>,
) -> Vec<u8> {
    key_pair
        .sign(rng, untrusted::Input::from(&message))
        .unwrap()
        .as_ref()
        .to_owned()
}

fn ecdsa_keypair(rng: &rand::SystemRandom) -> ring::signature::EcdsaKeyPair {
    let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(alg, rng).unwrap();
    signature::EcdsaKeyPair::from_pkcs8(alg, untrusted::Input::from(pkcs8.as_ref())).unwrap()
}

// copied from https://github.com/miekg/dns/blob/master/dnssec.go#L135
pub fn dnskey_keytag(dnskey: rdata::Dnskey) -> u16 {
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
    use domain::core::master::entry::MasterRecord;
    use domain::core::master::reader::{Reader, ReaderItem};
    use domain::core::rdata::MasterRecordData;

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
                Err(err) => debug!("{:?}", err),
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

    #[test]
    fn verify_rrsig_ecdsa_good_signature() {
        init_logger();

        assert!(verify_rrsig_helper(
        "cloudflare.com. 2992 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 3600 IN RRSIG CDNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. odj8zT4s/4qlGiU6gozw1cBupGxwWf01E+l9cQKqUegbe+CLeg59tdCmIFbGMBFb2tTmTTw3F9vTwb21hwJDUg==",
        vec!["cloudflare.com. 3600 IN CDNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="]
        ));
    }

    #[test]
    fn verify_rrsig_ecdsa_bad_signature() {
        init_logger();

        assert!(!verify_rrsig_helper(
        "cloudflare.com. 2992 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 3600 IN RRSIG CDNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. bad+signatur++++gozw1cBupGxwWf01E+l9cQKqUegbe+CLeg59tdCmIFbGMBFb2tTmTTw3F9vTwb21hwJDUg==",
        vec!["cloudflare.com. 3600 IN CDNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="],
        ));
    }

    #[test]
    fn verify_rrsig_rsa_good_signature() {
        init_logger();

        assert!(verify_rrsig_helper(
        ". 172800 IN DNSKEY 256 3 8 AwEAAcH+axCdUOsTc9o+jmyVq5rsGTh1EcatSumPqEfsPBT+whyj0/UhD7cWeixV9Wqzj/cnqs8iWELqhdzGX41ZtaNQUfWNfOriASnWmX2D9m/EunplHu8nMSlDnDcT7+llE9tjk5HI1Sr7d9N16ZTIrbVALf65VB2ABbBG39dyAb7tz21PICJbSp2cd77UF7NFqEVkqohl/LkDw+7Apalmp0qAQT1Mgwi2cVxZMKUiciA6EqS+KNajf0A6olO2oEhZnGGY6b1LTg34/YfHdiIIZQqAfqbieruCGHRiSscC2ZE7iNreL/76f4JyIEUNkt6bQA29JsegxorLzQkpF7NKqZc=",
        ". 86400 IN RRSIG SOA 8 0 86400 20190402170000 20190320160000 16749 . tmdkfxbiKWgi0oHGp2ti1fvOmQNIlxZ/c65A0AmdiaHaH9MonVOLkpNYiz1JRXKNcXmdtLto1IikVwIyGCPLIrzr77yMawrGAhb7KisTbSGGx7czlyv9Qdmi4wTdO/6fq73DTGHKVYGILM15kFIdAEEHVP8OISXsBJwQOhvXlHIeOtC4oeR63RBNfOSS1V9hLs17K9OjK0EFxerCnOEoZHeFIhzqvWRXCZ4YVOEfpSOvPWRV+D/RfDTBPaf1U5qFu9H5WcUzyoUJakukvg1+WTUZ0LmdkFplOrel+yAd++QGbtguX8LftgY7qlDMuY7FvKqb3+TsAAvTXRot4tE1fw==",
        vec![". 86400   IN      SOA     a.root-servers.net. nstld.verisign-grs.com. 2019032001 1800 900 604800 86400"],
        ));
    }

    #[test]
    fn verify_rrsig_rsa_bad_signature() {
        init_logger();

        assert!(!verify_rrsig_helper(
        ". 172800 IN DNSKEY 256 3 8 +++BadSignature+++o+jmyVq5rsGTh1EcatSumPqEfsPBT+whyj0/UhD7cWeixV9Wqzj/cnqs8iWELqhdzGX41ZtaNQUfWNfOriASnWmX2D9m/EunplHu8nMSlDnDcT7+llE9tjk5HI1Sr7d9N16ZTIrbVALf65VB2ABbBG39dyAb7tz21PICJbSp2cd77UF7NFqEVkqohl/LkDw+7Apalmp0qAQT1Mgwi2cVxZMKUiciA6EqS+KNajf0A6olO2oEhZnGGY6b1LTg34/YfHdiIIZQqAfqbieruCGHRiSscC2ZE7iNreL/76f4JyIEUNkt6bQA29JsegxorLzQkpF7NKqZc=",
        ". 86400 IN RRSIG SOA 8 0 86400 20190402170000 20190320160000 16749 . tmdkfxbiKWgi0oHGp2ti1fvOmQNIlxZ/c65A0AmdiaHaH9MonVOLkpNYiz1JRXKNcXmdtLto1IikVwIyGCPLIrzr77yMawrGAhb7KisTbSGGx7czlyv9Qdmi4wTdO/6fq73DTGHKVYGILM15kFIdAEEHVP8OISXsBJwQOhvXlHIeOtC4oeR63RBNfOSS1V9hLs17K9OjK0EFxerCnOEoZHeFIhzqvWRXCZ4YVOEfpSOvPWRV+D/RfDTBPaf1U5qFu9H5WcUzyoUJakukvg1+WTUZ0LmdkFplOrel+yAd++QGbtguX8LftgY7qlDMuY7FvKqb3+TsAAvTXRot4tE1fw==",
        vec![". 86400 IN SOA a.root-servers.net. nstld.verisign-grs.com. 2019032001 1800 900 604800 86400"],
        ));
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

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_good_signature() {
        init_logger();

        assert!(verify_rrsig_helper(
        "cloudflare.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 3600 IN RRSIG DNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. IaVqBxfybMOKi35lu6sa+iizrcTi8T7f/Jhgss1qcrD7FFaQZZAMtBXVQxq2uZXLxubLP+Zt9bCYUxMOxnb/Jw==",
        vec![
          "cloudflare.com. 3600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
          "cloudflare.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        ]
        ));
    }
    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_mixed_case() {
        init_logger();

        assert!(verify_rrsig_helper(
        "cloudFlare.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 3600 IN RRSIG DNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. IaVqBxfybMOKi35lu6sa+iizrcTi8T7f/Jhgss1qcrD7FFaQZZAMtBXVQxq2uZXLxubLP+Zt9bCYUxMOxnb/Jw==",
        vec![
          "Cloudflare.com. 3600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
          "Cloudflare.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        ]
        ));
    }
    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_order() {
        init_logger();

        assert!(verify_rrsig_helper(
        "cloudflare.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 3600 IN RRSIG DNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. IaVqBxfybMOKi35lu6sa+iizrcTi8T7f/Jhgss1qcrD7FFaQZZAMtBXVQxq2uZXLxubLP+Zt9bCYUxMOxnb/Jw==",
        vec![
          "cloudflare.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
          "cloudflare.com. 3600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
        ]
        ));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_ttl() {
        init_logger();

        assert!(verify_rrsig_helper(
        "cloudflare.com. 600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 600 IN RRSIG DNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. IaVqBxfybMOKi35lu6sa+iizrcTi8T7f/Jhgss1qcrD7FFaQZZAMtBXVQxq2uZXLxubLP+Zt9bCYUxMOxnb/Jw==",
        vec![
          "cloudflare.com. 600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
          "cloudflare.com. 600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        ]
        ));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_class() {
        init_logger();

        assert!(!verify_rrsig_helper(
        "cloudflare.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 3600 IN RRSIG DNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. IaVqBxfybMOKi35lu6sa+iizrcTi8T7f/Jhgss1qcrD7FFaQZZAMtBXVQxq2uZXLxubLP+Zt9bCYUxMOxnb/Jw==",
        vec![
          "cloudflare.com. 3600 CH TXT id.version 2001",
        ]
        ));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_owner() {
        init_logger();

        assert!(!verify_rrsig_helper(
        "cloudflare.com. 600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "com. 600 IN RRSIG DNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. IaVqBxfybMOKi35lu6sa+iizrcTi8T7f/Jhgss1qcrD7FFaQZZAMtBXVQxq2uZXLxubLP+Zt9bCYUxMOxnb/Jw==",
        vec![
          "cloudflare.com. 600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
          "cloudflare.com. 600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        ]
        ));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_type() {
        init_logger();

        assert!(!verify_rrsig_helper(
        "cloudflare.com. 600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 600 IN RRSIG NS 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. IaVqBxfybMOKi35lu6sa+iizrcTi8T7f/Jhgss1qcrD7FFaQZZAMtBXVQxq2uZXLxubLP+Zt9bCYUxMOxnb/Jw==",
        vec![
          "cloudflare.com. 600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
          "cloudflare.com. 600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        ]
        ));
    }

    #[test]
    fn verify_rrsig_ecdsa_multiple_rr_wrong_keyid() {
        init_logger();

        assert!(verify_rrsig_helper(
        "cloudflare.com. 600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 600 IN RRSIG DNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. IaVqBxfybMOKi35lu6sa+iizrcTi8T7f/Jhgss1qcrD7FFaQZZAMtBXVQxq2uZXLxubLP+Zt9bCYUxMOxnb/Jw==",
        vec![
          "cloudflare.com. 600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
          "cloudflare.com. 600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        ]
        ));
    }

    use chrono::Duration;
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
        let keytag = dnskey_keytag(pubkey.unwrap());
        debug!("{}", keytag);
        assert_eq!(keytag, 34505);
    }

    use bytes::buf::IntoBuf;
    use domain::core::bits::name::Dname;
    use domain::core::iana::rtype::Rtype;
    use domain::core::iana::secalg::SecAlg;
    use ring::signature::KeyPair;
    use std::str::FromStr;
    #[test]
    fn ecdsa_keypair_test() {
        init_logger();

        let rng = rand::SystemRandom::new();
        let keypair = ecdsa_keypair(&rng);
        let pubkey = bytes::Bytes::from(&keypair.public_key().as_ref()[1..]);
        let message = Vec::from("hello world");
        debug!("keypair     : {:?}", keypair);
        debug!("pubkey: {:?}", pubkey);
        debug!("message     : {:?}", message);
        let signature = ecdsa_sign(&rng, &keypair, message);
        debug!("signature   : {:?}", signature);
        let owner = Dname::from_str("cloudflare.com").unwrap();
        let ttl = 3600;
        let keyid = 2371;
        let flag = 256;
        let protocol = 3;

        let offset = 1;
        let i = Serial((Utc::now() - Duration::days(offset)).timestamp() as u32);
        let e = Serial((Utc::now() + Duration::days(offset)).timestamp() as u32);
        let rrsig = rdata::Rrsig::new(
            Rtype::Dnskey,
            SecAlg::EcdsaP256Sha256,
            owner.clone().label_count() as u8,
            ttl,
            e,
            i,
            keyid,
            owner.clone(),
            bytes::Bytes::from(signature),
        );
        debug!("rrsig : {}", rrsig);
        let dnskey = rdata::Dnskey::new(
            flag,
            protocol,
            SecAlg::EcdsaP256Sha256,
            bytes::Bytes::from(pubkey),
        );
        debug!("dnskey: {}", dnskey);

        let mut rrset = vec![];
        let rrs = vec![
          "cloudflare.com. 600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
          "cloudflare.com. 600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        ];

        if !rrs.is_empty() {
            for s in rrs {
                let rr = take_one_rr(s).unwrap();
                rrset.push(rr);
            }
        }

        let rrsig = rdata::Rrsig::new(
            Rtype::Dnskey,
            SecAlg::EcdsaP256Sha256,
            owner.clone().label_count() as u8,
            ttl,
            e,
            i,
            keyid,
            owner.clone(),
            bytes::Bytes::new(),
        );

        let mut message = vec![];
        rrsig.compose(&mut message);
        let mut sorted_rrset_bytes = prepare_rrset_to_sign(rrset.clone(), rrsig.original_ttl());
        message.append(&mut sorted_rrset_bytes);

        let sig = ecdsa_sign(&rng, &keypair, message);
        let rrsig = rdata::Rrsig::new(
            Rtype::Dnskey,
            SecAlg::EcdsaP256Sha256,
            owner.label_count() as u8,
            ttl,
            e,
            i,
            keyid,
            owner.clone(),
            bytes::Bytes::from(sig),
        );
        for rr in rrset.clone() {
            debug!("rr: {}", rr);
        }
        debug!("dnskey: {}", dnskey);
        debug!("rrsig : {}", rrsig);

        assert!(verify_rrsig(&dnskey, rrset, &rrsig, &owner));
    }
}
