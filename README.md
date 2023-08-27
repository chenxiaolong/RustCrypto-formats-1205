This is a small reproducer for https://github.com/RustCrypto/formats/issues/1205.

To test:

```bash
cargo run --release -- default_params.pem openssl_params.pem

# Fails
openssl rsa -in default_params.pem -noout -text

# Works
openssl rsa -in openssl_params.pem -noout -text
```