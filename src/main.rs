use bytes::buf::FromBuf;
use bytes::IntoBuf;
use domain::core::bits::compose::Compose;
use domain::core::master::entry::MasterRecord;
use domain::core::master::reader::{Reader, ReaderItem};
use domain::core::rdata;
use domain::core::rdata::MasterRecordData;
use log::debug;
use ring::signature;

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

fn main() {
    env_logger::init();

    let zsk = take_one_rr("cloudflare.com.         2992    IN      DNSKEY  257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==");
    let cdnskey = take_one_rr("cloudflare.com.         3600    IN      CDNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==").unwrap();
    let rrsig = take_one_rr("cloudflare.com.         3600    IN      RRSIG   CDNSKEY 13 2 3600 20190408024840 20190207024840 2371 cloudflare.com. odj8zT4s/4qlGiU6gozw1cBupGxwWf01E+l9cQKqUegbe+CLeg59tdCmIFbGMBFb2tTmTTw3F9vTwb21hwJDUg==");

    let rrs = vec![cdnskey];

    let pubkey: Option<rdata::Dnskey> = match zsk.unwrap().into_data() {
        MasterRecordData::Dnskey(rr) => Some(rr),
        _ => None,
    };
    let sig: Option<rdata::Rrsig> = match rrsig.unwrap().into_data() {
        MasterRecordData::Rrsig(rr) => Some(rr),
        _ => None,
    };

    if !verify(&pubkey.unwrap(), rrs, &sig.unwrap()) {
        println!("Verification failed");
    }
    println!("Verification success");
}

fn verify(pubkey: &rdata::Dnskey, rrs: Vec<impl Compose>, rrsig: &rdata::Rrsig) -> bool {
    let rrsig_rdata_nosig = rdata::Rrsig::new(
        rrsig.type_covered(),
        rrsig.algorithm(),
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
        rr.compose(&mut message);
    }
    let sig = Vec::from_buf(rrsig.signature().clone().into_buf());

    // Add 0x4 idenfitifer to the pubkey
    // required for crypto libraries to recognize
    // TODO: ECDSA only ?
    let mut key: Vec<u8> = vec![0x4];
    let mut a = Vec::from_buf(pubkey.public_key().clone().into_buf());
    key.append(&mut a);

    match signature::verify(
        &signature::ECDSA_P256_SHA256_FIXED,
        untrusted::Input::from(&key),
        untrusted::Input::from(&message),
        untrusted::Input::from(&sig),
    ) {
        Ok(_) => true,
        Err(err) => {
            debug!("Verification Error: {}", err);
            false
        }
    }
}
