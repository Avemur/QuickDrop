// Compression.cpp
#include "compression.h"
#include <zstd.h>
#include <iostream>

bool compressChunk(const std::vector<char>& in, std::vector<char>& out) {
  size_t maxCSize = ZSTD_compressBound(in.size());
  out.resize(maxCSize);
  size_t cSize = ZSTD_compress(out.data(), maxCSize,
                               in.data(), in.size(), 3);
  if (ZSTD_isError(cSize)) {
    std::cerr << "Zstd error: " << ZSTD_getErrorName(cSize) << "\n";
    return false;
  }
  out.resize(cSize);
  return true;
}

bool decompressChunk(const std::vector<char>& in,
                     std::vector<char>& out,
                     size_t origSize) {
  out.resize(origSize);
  size_t dSize = ZSTD_decompress(out.data(), origSize,
                                 in.data(), in.size());
  if (ZSTD_isError(dSize)) {
    std::cerr << "Zstd error: " << ZSTD_getErrorName(dSize) << "\n";
    return false;
  }
  return true;
}
