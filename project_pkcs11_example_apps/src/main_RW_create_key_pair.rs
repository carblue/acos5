/* main_RW_create_key_pair.rs */
/* This example implements "3.6 Example 2: Generating a key pair", page 16, from https://www.nlnetlabs.nl/downloads/publications/hsm/hsm.pdf
   main_RO_CKO_PRIVATE_KEY.rs: show some information about private keys in a read-only session
   Functions used:
   C_Initialize
   C_GetSlotList
   C_OpenSession
   C_Login
   C_GenerateKeyPair
   C_Logout
   C_CloseSession
   C_Finalize
 */


use cryptoki::context::{Pkcs11, CInitializeArgs};
use cryptoki::session::{UserType, Session};
use cryptoki::types::AuthPin;
use cryptoki::object::{Attribute, ObjectHandle, AttributeType/*, KeyType*/};
use cryptoki::error::Error;
use cryptoki::mechanism::Mechanism;

fn show_key_info(session: &Session, key: ObjectHandle) -> Result<(), Error> {
    println!("key {:?}", key);
    let template = [
        AttributeType::Label,
        AttributeType::Id,
        AttributeType::KeyType,
        AttributeType::Token,
        AttributeType::Private,
        AttributeType::Modifiable,

        AttributeType::Sensitive,
        AttributeType::Extractable,
        AttributeType::AlwaysSensitive,
        AttributeType::NeverExtractable,
        AttributeType::Local,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::SignRecover,
        AttributeType::VerifyRecover,
        AttributeType::Wrap,
        AttributeType::Unwrap,
    ];
    let attributes_vec = session.get_attributes(key, &template)?;
    for elem in attributes_vec {
        match elem {
            Attribute::Label(vec) => println!("attrib {:?}", unsafe { std::str::from_utf8_unchecked(&vec) } ),
            _ => println!("attrib {:?}", elem),
        }
    }
    Ok(())
}

fn create_key_pair(session: &Session) -> Result<(ObjectHandle, ObjectHandle), Error> {
/* */
    let mech = Mechanism::RsaPkcsKeyPairGen;
    let pub_key_template = [
        Attribute::Id(vec![2_u8]),
        Attribute::Label(vec![0x4D_u8, 0x79, 0x4B, 0x65, 0x79]),
        Attribute::ModulusBits(4096.into()),
        Attribute::PublicExponent(vec![1_u8, 0, 1])
    ];
    let priv_key_template = [
        Attribute::Id(vec![2_u8]),
        Attribute::Label(vec![0x4D_u8, 0x79, 0x4B, 0x65, 0x79]),
        Attribute::ModulusBits(4096.into()),
        Attribute::PublicExponent(vec![1_u8, 0, 1])
    ];

    session.generate_key_pair(
        &mech,
        &pub_key_template,
        &priv_key_template
    )

/*
4110: prkdf
A0 2B 30 0F 0C 06 43 41 72 6F 6F 74 03 02 06 C0 04 01 01 30 0A 04 01 01 03 01 00 03 02 03 B8 A1 0C 30 0A 30 08 04 06 3F 00 41 00 12 01



4111: pukdf
A0 28 30 0C 0C 06 43 41 72 6F 6F 74 03 02 06 40 30 0A 04 01 01 03 01 00 03 02 03 48 A1 0C 30 0A 30 08 04 06 3F 00 41 00 11 01

*/
/*
    // get mechanism
    let mechanism = Mechanism::EccKeyPairGen;
/*
NIST P-521
1.3.132.0.35
nistp521
secp521r1

    The NIST 521 bit curve, its OID and aliases.
*/
    let nistp256_oid: Vec<u8> = vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // pub key template
    let pub_key_template = vec![
        Attribute::KeyType(KeyType::EC),
        Attribute::EcParams(nistp256_oid),
        Attribute::Id(vec![2_u8]),
        Attribute::Label(vec![0x4D_u8, 0x79, 0x4B, 0x65, 0x79]),
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
        //Attribute::Derive(true),
        Attribute::Verify(true),
    ];

    // priv key template
    let priv_key_template = vec![
        Attribute::KeyType(KeyType::EC),
        Attribute::EcParams(nistp256_oid),
        Attribute::Id(vec![2_u8]),
        Attribute::Label(vec![0x4D_u8, 0x79, 0x4B, 0x65, 0x79]),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        //Attribute::Derive(true),
        Attribute::Sign(true),
    ];
    session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
*/
}

fn main() -> Result<(), Error> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            let ctx = Pkcs11::new("C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll")?;
        }
        else {
            //let ctx = Pkcs11::new("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")?;
            /* if p11-kit installed and opensc-pkcs11.so configured with highest priority */
            let ctx = Pkcs11::new("/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so")?;
        }
    }
    ctx.initialize(CInitializeArgs::OsThreads)?;
    let slot = ctx.get_slots_with_initialized_token()?.remove(0);
    let session = ctx.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new("12345678".into())))?;
    let (pub_oh, priv_oh) = create_key_pair(&session)?;

    println!("CKO_PUBLIC_KEY:");
    show_key_info(&session, pub_oh)?;
    println!("CKO_PRIVATE_KEY:");
    show_key_info(&session, priv_oh)?;
    session.logout()
}
/*

$ cargo run
CKO_PUBLIC_KEY:
key ObjectHandle { handle: 108806887690688 }
attrib "MyKey"
attrib Id([8])
attrib KeyType(KeyType { val: 0 })
attrib Token(true)
attrib Private(false)
attrib Modifiable(true)
attrib Sensitive(false)
attrib Extractable(true)
attrib Local(true)
attrib Encrypt(false)
attrib Verify(true)
attrib VerifyRecover(false)
attrib Wrap(false)
CKO_PRIVATE_KEY:
key ObjectHandle { handle: 108806887688896 }
attrib "MyKey"
attrib Id([8])
attrib KeyType(KeyType { val: 0 })
attrib Token(true)
attrib Private(true)
attrib Modifiable(true)
attrib Sensitive(true)
attrib Extractable(false)
attrib AlwaysSensitive(true)
attrib NeverExtractable(true)
attrib Local(true)
attrib Decrypt(false)
attrib Sign(true)
attrib SignRecover(false)
attrib Unwrap(false)



name: privateRSAKey  type: SEQUENCE
  name: commonObjectAttributes  type: SEQUENCE
    name: label  type: UTF8_STR  value: MyKey
    name: flags  type: BIT_STR  value(2): c0  ->  11
    name: authId  type: OCT_STR  value: 01
  name: commonKeyAttributes  type: SEQUENCE
    name: iD  type: OCT_STR  value: 08
    name: usage  type: BIT_STR  value(3): 20  ->  001
    name: native  type: BOOLEAN
      name: NULL  type: DEFAULT  value: TRUE
    name: accessFlags  type: BIT_STR  value(5): b8  ->  10111
    name: keyReference  type: INTEGER  value: 0x00
  name: privateRSAKeyAttributes  type: SEQUENCE
    name: value  type: CHOICE
      name: indirect  type: CHOICE
        name: path  type: SEQUENCE
          name: path  type: OCT_STR  value: 3f0041005000
    name: modulusLength  type: INTEGER  value: 0x1000



name: publicRSAKey  type: SEQUENCE
  name: commonObjectAttributes  type: SEQUENCE
    name: label  type: UTF8_STR  value: MyKey
    name: flags  type: BIT_STR  value(2): 40  ->  01
  name: commonKeyAttributes  type: SEQUENCE
    name: iD  type: OCT_STR  value: 08
    name: usage  type: BIT_STR  value(7): 02  ->  0000001
    name: native  type: BOOLEAN
      name: NULL  type: DEFAULT  value: TRUE
    name: accessFlags  type: BIT_STR  value(5): 48  ->  01001
    name: keyReference  type: INTEGER  value: 0x00
  name: publicRSAKeyAttributes  type: SEQUENCE
    name: value  type: CHOICE
      name: indirect  type: CHOICE
        name: path  type: SEQUENCE
          name: path  type: OCT_STR  value: 3f0041005001
    name: modulusLength  type: INTEGER  value: 0x1000
*/
