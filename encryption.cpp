#include "encryption.h"
#include <sodium.h>
#include <iostream>

static void buildNonce(uint64_t counter, unsigned char nonce[12]) {
    // 4 bytes zero prefix, 8 bytes big-endian counter
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (counter >> (56 - 8*i)) & 0xFF;
    }
}

bool encryptChunk(const std::vector<char>& plaintext,
                  std::vector<unsigned char>& ciphertext,
                  const std::vector<unsigned char>& key,
                  uint64_t nonceCounter) {
    if (sodium_init() < 0) return false;
    const size_t ptLen = plaintext.size();
    const size_t maxCtLen = ptLen + crypto_aead_chacha20poly1305_ietf_ABYTES;
    ciphertext.resize(maxCtLen);

    unsigned char nonce[12];
    buildNonce(nonceCounter, nonce);

    unsigned long long ctLen;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ctLen,
            reinterpret_cast<const unsigned char*>(plaintext.data()), ptLen,
            nullptr, 0, // no additional data
            nullptr, nonce, key.data()) != 0) {
        std::cerr << "AEAD encrypt failed" << std::endl;
        return false;
    }
    ciphertext.resize(ctLen);
    return true;
}

bool decryptChunk(const std::vector<unsigned char>& ciphertext,
                  std::vector<char>& plaintext,
                  const std::vector<unsigned char>& key,
                  uint64_t nonceCounter) {
    if (sodium_init() < 0) return false;
    const size_t ctLen = ciphertext.size();
    const size_t maxPtLen = ctLen - crypto_aead_chacha20poly1305_ietf_ABYTES;
    plaintext.resize(maxPtLen);

    unsigned char nonce[12];
    buildNonce(nonceCounter, nonce);

    unsigned long long ptLen;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(plaintext.data()), &ptLen,
            nullptr,
            ciphertext.data(), ctLen,
            nullptr, 0, // no additional data
            nonce, key.data()) != 0) {
        std::cerr << "AEAD decrypt failed or tampered" << std::endl;
        return false;
    }
    plaintext.resize(ptLen);
    return true;
}
