The test key alice_rsa (tests/fixtures/keys) written by OpenSSL 3.0 in other PKCS#12 forms:
PBES2 with AES-128, AES-192 and 3DES, an unencrypted key bag (`plain`), and a file without a
MAC (`nomac`). Password: Qwerty12. Made with

    openssl pkcs12 -in alice_rsa.p12 -passin pass:Qwerty12 -nodes -legacy -out alice.pem
    openssl pkcs12 -export -in alice.pem -name alice -passout pass:Qwerty12 \
        -keypbe AES-128-CBC -certpbe AES-128-CBC -out aes128.p12
    # AES-192-CBC: aes192.p12, DES-EDE3-CBC: des3.p12, NONE: plain.p12, -nomac: nomac.p12
