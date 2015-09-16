// Copyright 2015 Google, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![feature(convert)]

extern crate openssl;

use openssl::crypto::hash::{hash, Type};

/// List of types currently supported in Multihash.
/// SHA3, Blake2b, and Blake2s are not yet supported in OpenSSL, so are not available in rust-multihash.
#[derive(PartialEq, Clone, Copy, Debug)]
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

/// Hashes the input using the given hash algorithm. Also adds the leading bytes for type of algo
/// and length of digest.
///
/// # Example
/// ```
/// use rust-multihash:::{HashTypes, multihash};
///
/// let testphrase = b"Hello World"
/// let digest = multihash(HashTypes::SHA2512, testphrase.to_vec());
/// ```
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
