Multihash for Rust
=====

rust-multihash is an implementation of the [multihash algorithm](https://github.com/jbenet/go-multihash) that allows for multiple different hash algorithms to be contained in the same format. This makes it extensible as new hashing algorithms are added.

To use, add `rust-multihash= "*"` to your `Cargo.toml` file.

Example
----
To get a SHA2-256 hash of a string:
```
use multihash::{HashType, multihash};

let hash = multihash(HashType::SHA2256, "Hello World".to_vec());
```

Contributing
----
This is not an official Google project, but it is governed by the Google Contributor License Agreement. To contribute code please agree to the [Google Contributor License Agreement](https://cla.developers.google.com/about/google-individual). Then please feel free to fork and issue a pull request.
