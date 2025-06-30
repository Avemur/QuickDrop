// crypto.cpp
// Implements zero-knowledge X25519 key exchange using libsodium (raw scalar multiplication)

#include <sodium.h>
#include <vector>
#include <string>
#include <iostream>
#include <sys/socket.h>

// Performs a raw X25519 ECDH handshake over the given connected socket fd.
// On success, sessionKey is filled with 32 bytes of shared secret.
// Returns true on success, false on any error.
bool doKeyExchange(int fd, std::vector<unsigned char>& sessionKey) {
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "libsodium initialization failed" << std::endl;
        return false;
    }

    // 1. Generate a random X25519 private key
    unsigned char my_priv[crypto_scalarmult_SCALARBYTES];
    randombytes_buf(my_priv, sizeof my_priv);

    // 2. Compute the corresponding public key
    unsigned char my_pub[crypto_scalarmult_BYTES];
    if (crypto_scalarmult_base(my_pub, my_priv) != 0) {
        std::cerr << "crypto_scalarmult_base failed" << std::endl;
        return false;
    }

    // 3. Exchange public keys
    if (send(fd, my_pub, sizeof my_pub, 0) != (ssize_t)sizeof my_pub) {
        perror("send public key");
        return false;
    }
    unsigned char peer_pub[crypto_scalarmult_BYTES];
    if (recv(fd, peer_pub, sizeof peer_pub, MSG_WAITALL) != (ssize_t)sizeof peer_pub) {
        perror("recv peer public key");
        return false;
    }

    // 4. Derive the shared secret
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared, my_priv, peer_pub) != 0) {
        std::cerr << "crypto_scalarmult failed" << std::endl;
        return false;
    }
    // Store 32-byte session key
    sessionKey.assign(shared, shared + crypto_scalarmult_BYTES);

    // 5. Compute a 4-digit fingerprint for manual confirmation
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof hash,
                       sessionKey.data(), sessionKey.size(),
                       nullptr, 0);
    uint16_t code = (uint16_t(hash[0]) << 8) | uint16_t(hash[1]);
    code %= 10000;  // reduce to 0-9999
    std::cout << "Verify code: " << code << std::endl;
    std::string input; std::getline(std::cin, input);

    return true;
}
