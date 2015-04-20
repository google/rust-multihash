#![feature(convert)]

extern crate openssl;

use openssl::crypto::hash::{hash, Type};

pub enum HashTypes {
    SHA1,
    SHA2256,
    SHA2512,
    SHA3,
    Blake2b,
    Blake2s
}

impl HashTypes {
    pub fn to_u8(&self) -> u8 {
        match *self {
            HashTypes::SHA1 => 0x11,
            HashTypes::SHA2256 => 0x12,
            HashTypes::SHA2512 => 0x13,
            HashTypes::SHA3 => 0x14,
            HashTypes::Blake2b => 0x40,
            HashTypes::Blake2s => 0x41,
        }
    }
}

pub fn multihash(wanthash: HashTypes, input: Vec<u8>) -> Result<Vec<u8>, String> {
    let ssl_hash: Option<Type> = match wanthash {
        HashTypes::SHA1 => Some(Type::SHA1),
        HashTypes::SHA2256 => Some(Type::SHA256),
        HashTypes::SHA2512 => Some(Type::SHA512),
        _ => None,
    };
    match ssl_hash {
        Some(openssl_type) => {
            let mut temphash = hash(openssl_type, input.as_slice());
            let length = temphash.len() as u8;
            temphash.insert(0, length);
            temphash.insert(0, wanthash.to_u8()); // Add the hashtype to the hash.
            Ok(temphash)
        }
        None => Err("Sorry, we don't support that hash algorithm yet.".to_string()),
    }
}

#[cfg(test)]
mod test {
    use super::{HashTypes, multihash};
    use openssl::crypto::hash::{hash, Type};

    #[test]
    fn test1() {
        let example = b"Hello World";
        let mut result = hash(Type::SHA256, example);
        let length = result.len() as u8;
        result.insert(0, 0x12);
        result.insert(1, length);

        assert_eq!(multihash(HashTypes::SHA2256, example.to_vec()).unwrap(), result);
    }
}
