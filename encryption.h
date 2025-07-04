#pragma once
#include <vector>
#include <cstdint>

// Encrypts 'plaintext' into 'ciphertext' using ChaCha20-Poly1305.
// 'key' must be 32 bytes. 'nonceCounter' ensures a unique 12-byte nonce per chunk.
bool encryptChunk(const std::vector<char>& plaintext,
                  std::vector<unsigned char>& ciphertext,
                  const std::vector<unsigned char>& key,
                  uint64_t nonceCounter);

// Decrypts 'ciphertext' into 'plaintext' using ChaCha20-Poly1305.
// Returns false if authentication fails.
bool decryptChunk(const std::vector<unsigned char>& ciphertext,
                  std::vector<char>& plaintext,
                  const std::vector<unsigned char>& key,
                  uint64_t nonceCounter);