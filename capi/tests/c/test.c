/* Checks the C interface from C: run by scripts/capi-test.sh with the test fixtures folder
 * (tests/fixtures) as its argument. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kzcrypto.h"

static int failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "%s:%d: failed: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                   \
        }                                                                 \
    } while (0)

static unsigned char *read_file(const char *dir, const char *name, size_t *len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot read %s\n", path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(n > 0 ? (size_t)n : 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) {
        exit(2);
    }
    fclose(f);
    *len = (size_t)n;
    return b;
}

/* A deterministic "random" source, to show the caller decides where randomness comes from. */
static int counter_rng(void *ctx, uint8_t *buf, size_t len) {
    unsigned *n = ctx;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)((*n)++ * 167u + 13u);
    }
    return 0;
}

static int broken_rng(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    (void)buf;
    (void)len;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s FIXTURES_DIR\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1];
    const int64_t now = 1798761600000; /* 2027-01-01 */
    KzBuf err = {0}, out = {0};

    CHECK(strlen(kz_version()) > 0);

    /* Streebog-512 of the empty string */
    CHECK(kz_hash("1.2.398.3.10.1.3.3", NULL, 0, &out, &err) == KZ_STATUS_OK);
    CHECK(out.len == 64 && out.ptr[0] == 0x8e && out.ptr[63] == 0x8a);
    kz_buf_free(&out);
    CHECK(out.ptr == NULL && out.len == 0);
    CHECK(kz_hash("1.2.3", (const uint8_t *)"x", 1, &out, &err) == KZ_STATUS_UNSUPPORTED);
    CHECK(err.len > 0 && out.ptr == NULL);
    kz_buf_free(&err);
    CHECK(kz_hash("1.2.3", NULL, 5, &out, &err) == KZ_STATUS_INVALID_ARGUMENT);
    kz_buf_free(&err);

    /* keys */
    size_t p12_len;
    unsigned char *p12 = read_file(dir, "keys/alice_gost2015.p12", &p12_len);
    KzKey *key = NULL;
    CHECK(kz_key_open(p12, p12_len, (const uint8_t *)"wrong", 5, NULL, &key, &err) ==
          KZ_STATUS_WRONG_PASSWORD);
    CHECK(key == NULL && err.len > 0);
    kz_buf_free(&err);
    CHECK(kz_key_open(p12, p12_len, (const uint8_t *)"Qwerty12", 8, NULL, &key, &err) ==
          KZ_STATUS_OK);
    CHECK(key != NULL);
    KzBuf cert = {0};
    CHECK(kz_key_certificate(key, &cert, NULL) == KZ_STATUS_OK && cert.len > 100);

    /* sign, attached, with the caller's random source */
    const char *doc = "a document";
    unsigned n = 1;
    KzBuf cms = {0};
    CHECK(kz_sign_cms(key, (const uint8_t *)doc, strlen(doc), true, now, counter_rng, &n, &cms,
                      &err) == KZ_STATUS_OK);
    CHECK(n > 1); /* the callback was used */
    size_t count = 0;
    CHECK(kz_cms_signer_count(cms.ptr, cms.len, &count, NULL) == KZ_STATUS_OK && count == 1);
    KzBuf content = {0};
    CHECK(kz_cms_content(cms.ptr, cms.len, &content, NULL) == KZ_STATUS_OK);
    CHECK(content.len == strlen(doc) && memcmp(content.ptr, doc, content.len) == 0);
    kz_buf_free(&content);

    KzSignerCheck r;
    KzBuf signer = {0};
    CHECK(kz_cms_check_signer(cms.ptr, cms.len, 0, NULL, 0, &r, &signer, NULL) == KZ_STATUS_OK);
    CHECK(r.signature == KZ_SIGNATURE_VALID && r.certificate_reference_ok);
    CHECK(r.has_signing_time && r.signing_time_ms == now);
    CHECK(signer.len == cert.len && memcmp(signer.ptr, cert.ptr, cert.len) == 0);
    kz_buf_free(&signer);
    CHECK(kz_cms_check_signer(cms.ptr, cms.len, 1, NULL, 0, &r, NULL, &err) ==
          KZ_STATUS_INVALID_ARGUMENT);
    kz_buf_free(&err);

    /* a changed document inside the file */
    unsigned char *changed = malloc(cms.len);
    memcpy(changed, cms.ptr, cms.len);
    unsigned char *at = memmem(changed, cms.len, doc, strlen(doc));
    CHECK(at != NULL);
    if (at) {
        at[0] ^= 1;
    }
    CHECK(kz_cms_check_signer(changed, cms.len, 0, NULL, 0, &r, NULL, NULL) == KZ_STATUS_OK);
    CHECK(r.signature == KZ_SIGNATURE_DIGEST_MISMATCH);
    free(changed);
    kz_buf_free(&cms);

    /* detached: needs the document */
    CHECK(kz_sign_cms(key, (const uint8_t *)doc, strlen(doc), false, now, NULL, NULL, &cms,
                      NULL) == KZ_STATUS_OK);
    CHECK(kz_cms_check_signer(cms.ptr, cms.len, 0, NULL, 0, &r, NULL, NULL) == KZ_STATUS_OK);
    CHECK(r.signature == KZ_SIGNATURE_NO_CONTENT);
    CHECK(kz_cms_check_signer(cms.ptr, cms.len, 0, (const uint8_t *)doc, strlen(doc), &r, NULL,
                              NULL) == KZ_STATUS_OK);
    CHECK(r.signature == KZ_SIGNATURE_VALID);
    kz_buf_free(&cms);

    /* by hash: the digest must have the key's length */
    KzBuf h = {0};
    CHECK(kz_hash("1.2.398.3.10.1.3.3", (const uint8_t *)doc, strlen(doc), &h, NULL) ==
          KZ_STATUS_OK);
    CHECK(kz_sign_digest(key, h.ptr, h.len, now, NULL, NULL, &cms, NULL) == KZ_STATUS_OK);
    CHECK(kz_cms_check_signer(cms.ptr, cms.len, 0, (const uint8_t *)doc, strlen(doc), &r, NULL,
                              NULL) == KZ_STATUS_OK);
    CHECK(r.signature == KZ_SIGNATURE_VALID);
    kz_buf_free(&cms);
    CHECK(kz_sign_digest(key, h.ptr, 3, now, NULL, NULL, &cms, &err) ==
          KZ_STATUS_INVALID_ARGUMENT);
    kz_buf_free(&err);
    kz_buf_free(&h);

    /* a random source that fails stops signing */
    CHECK(kz_sign_cms(key, (const uint8_t *)doc, strlen(doc), true, now, broken_rng, NULL, &cms,
                      &err) == KZ_STATUS_RANDOM);
    CHECK(cms.ptr == NULL);
    kz_buf_free(&err);

    /* trust: the test CA is not NCA RK, until it is added */
    bool trusted = true;
    KzTrust *nca = kz_trust_new_nca();
    CHECK(kz_cert_check(nca, cert.ptr, cert.len, now, &trusted, NULL, &err) == KZ_STATUS_OK);
    CHECK(!trusted && err.len > 0);
    kz_buf_free(&err);
    size_t ca_len;
    unsigned char *ca = read_file(dir, "keys/ca_gost2015.cer", &ca_len);
    KzTrust *test = kz_trust_new_empty();
    CHECK(kz_trust_add(test, ca, ca_len, NULL) == KZ_STATUS_OK);
    KzBuf issuer = {0};
    CHECK(kz_cert_check(test, cert.ptr, cert.len, now, &trusted, &issuer, &err) == KZ_STATUS_OK);
    CHECK(trusted && err.len == 0 && issuer.len == ca_len);
    kz_buf_free(&issuer);
    CHECK(kz_trust_add(test, (const uint8_t *)"junk", 4, &err) == KZ_STATUS_MALFORMED);
    kz_buf_free(&err);

    /* OCSP: a request is made; an answer that is not one is an error */
    KzBuf req = {0};
    const uint8_t nonce[16] = {1, 2, 3};
    CHECK(kz_ocsp_request(cert.ptr, cert.len, ca, ca_len, nonce, sizeof nonce, &req, NULL) ==
          KZ_STATUS_OK);
    CHECK(req.len > 50);
    KzOcspStatus st;
    CHECK(kz_ocsp_read((const uint8_t *)"\x30\x00", 2, cert.ptr, cert.len, ca, ca_len, nonce,
                       sizeof nonce, test, now, &st, NULL, &err) != KZ_STATUS_OK);
    kz_buf_free(&err);
    kz_buf_free(&req);

    /* timestamps: NCA's real answer to a real request (captured 2026-11-01) */
    size_t tsq_len, tsr_len;
    unsigned char *tsq = read_file(dir, "nca-live/sha256-policy-6.2/tsq.der", &tsq_len);
    unsigned char *tsr = read_file(dir, "nca-live/sha256-policy-6.2/tsr.der", &tsr_len);
    KzBuf token = {0};
    CHECK(kz_tsp_read_answer(tsq, tsq_len, tsr, tsr_len, &token, &err) == KZ_STATUS_OK);
    CHECK(token.len > 500);
    kz_buf_free(&token);
    tsq[tsq_len - 4] ^= 1; /* another nonce (the request ends with it and certReq) */
    CHECK(kz_tsp_read_answer(tsq, tsq_len, tsr, tsr_len, &token, &err) != KZ_STATUS_OK);
    CHECK(err.len > 0 && token.ptr == NULL);
    kz_buf_free(&err);
    uint8_t digest[32] = {7};
    CHECK(kz_tsp_request("2.16.840.1.101.3.4.2.1", digest, sizeof digest, "1.2.398.3.3.2.6.2",
                         nonce, 8, &req, NULL) == KZ_STATUS_OK);
    CHECK(req.len > 40);
    kz_buf_free(&req);

    kz_trust_free(nca);
    kz_trust_free(test);
    kz_buf_free(&cert);
    kz_key_free(key);
    kz_key_free(NULL);
    kz_trust_free(NULL);
    kz_buf_free(NULL);
    free(p12);
    free(ca);
    free(tsq);
    free(tsr);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("C interface: all checks passed\n");
    return 0;
}
