use bytes::buf::FromBuf;
use bytes::IntoBuf;
use domain::core::bits::compose::Compose;
use domain::core::rdata;
use log::debug;
use ring::signature;

pub fn verify_rrsig(pubkey: &rdata::Dnskey, rrs: Vec<impl Compose>, rrsig: &rdata::Rrsig) -> bool {
    let rrsig_algo = rrsig.algorithm();
    let rrsig_rdata_nosig = rdata::Rrsig::new(
        rrsig.type_covered(),
        rrsig_algo,
        rrsig.labels(),
        rrsig.original_ttl(),
        rrsig.expiration(),
        rrsig.inception(),
        rrsig.key_tag(),
        rrsig.signer_name().clone(),
        bytes::Bytes::new(),
    );

    // buf to be signed/verified
    let mut message = vec![];

    // Add RRSIG rdata without the signature
    rrsig_rdata_nosig.compose(&mut message);

    // append the RR
    // TODO: sort
    for rr in rrs {
        // set original TTL
        //rr.set_ttl(rrsig.original_ttl());
        rr.compose(&mut message);
    }
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

// return public key exponent and modulues from the dnskey encoded rsa pub key
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
        let sig: Option<rdata::Rrsig> = match rrsig.into_data() {
            MasterRecordData::Rrsig(rr) => Some(rr),
            _ => None,
        };

        verify_rrsig(&pubkey.unwrap(), rrset, &sig.unwrap())
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
        "CloudFlare.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
        "cloudflare.com. 3600 IN RRSIG DNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. IaVqBxfybMOKi35lu6sa+iizrcTi8T7f/Jhgss1qcrD7FFaQZZAMtBXVQxq2uZXLxubLP+Zt9bCYUxMOxnb/Jw==",
        vec![
          "cloudflare.com. 3600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
          "cloudflare.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
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
}
