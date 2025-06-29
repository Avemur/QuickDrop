// Compression.h
#pragma once
#include <vector>

// Compresses `in` → `out`, returns true on success
bool compressChunk(const std::vector<char>& in,
                   std::vector<char>& out);

// Decompresses `in` → `out`, knowing the original size
bool decompressChunk(const std::vector<char>& in,
                     std::vector<char>& out,
                     size_t origSize);