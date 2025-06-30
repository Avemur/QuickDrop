#pragma once
#include <vector>

// Performs an X25519 ECDH handshake over a connected socket (fd).
// On success, sessionKey is filled with 32 bytes of shared secret.
// Returns true on success, false on error.
bool doKeyExchange(int fd, std::vector<unsigned char>& sessionKey);