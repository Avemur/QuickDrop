// main.cpp
// Compile with:
//   g++ -std=c++17 main.cpp compression.cpp crypto.cpp encryption.cpp \
//       -lcrow -lsodium -lzstd -pthread \
//       -I/opt/homebrew/include -L/opt/homebrew/lib \
//       -o QuickDrop

#include "crow_all.h"
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <atomic>
#include <string>
#include <cstdint>
#include <sys/stat.h>
#include <iomanip>
#include <fstream>
#include <random>
#include <mutex>

#ifdef _WIN32
  #include <winsock2.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
  #define CLOSE_SOCKET closesocket
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <netinet/in.h>
  #define CLOSE_SOCKET close
#endif

#include "compression.h"   // compressChunk, decompressChunk
#include "crypto.h"        // doKeyExchange
#include "encryption.h"    // encryptChunk, decryptChunk

// Configuration constants
static const int    CHUNK_SIZE        = 64 * 1024;  // 64 KB
static const int    PORT_DEFAULT      = 9000;
static const int    DISCOVERY_PORT    = 9001;
static const char*  DISCOVERY_MESSAGE = "QUICKDROP_DISCOVERY";

// Global to hold the PIN for current listener session
static std::string currentListenPin;

namespace FileTransfer {

bool initSockets() {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2,2), &wsa) == 0;
#else
    return true;
#endif
}

void cleanupSockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

int createListener(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); exit(1); }
    if (listen(fd, 1) < 0) { perror("listen"); exit(1); }
    return fd;
}

// Helper function to parse host:port and return just the host
std::string parseHost(const std::string &hostPort) {
    size_t colonPos = hostPort.find(':');
    if (colonPos != std::string::npos) {
        return hostPort.substr(0, colonPos);
    }
    return hostPort;
}

int createConnection(const std::string &host, int port) {
    std::string cleanHost = parseHost(host);
    std::cout << "[DEBUG] Connecting to " << cleanHost << ":" << port << std::endl;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, cleanHost.c_str(), &addr.sin_addr) <= 0) {
        perror("inet_pton"); CLOSE_SOCKET(fd); return -1;
    }
    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); CLOSE_SOCKET(fd); return -1;
    }
    std::cout << "[DEBUG] Connected successfully" << std::endl;
    return fd;
}

void sendFile(int fd, const std::string &path, const std::vector<unsigned char>& sessionKey) {
    std::cout << "[DEBUG] Sending file: " << path << std::endl;
    struct stat st;
    if (stat(path.c_str(), &st) != 0) { perror("stat"); return; }
    size_t totalSize = st.st_size;
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { perror("fopen sendFile"); return; }

    std::vector<char> buffer(CHUNK_SIZE);
    size_t bytesRead;
    uint64_t chunkCounter = 0;
    size_t bytesProcessed = 0;
    auto startTime = std::chrono::steady_clock::now();

    while ((bytesRead = fread(buffer.data(), 1, CHUNK_SIZE, f)) > 0) {
        bytesProcessed += bytesRead;
        auto now     = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - startTime).count();
        double mbps    = (bytesProcessed / (1024.0 * 1024.0)) / (elapsed > 0 ? elapsed : 1.0);
        int pct       = int((double)bytesProcessed / totalSize * 100);

        std::cout << "\rProgress: " << pct << "% ("
                  << std::fixed << std::setprecision(1)
                  << mbps << " MB/s)"
                  << std::flush;

        // Compress
        std::vector<char> raw(buffer.begin(), buffer.begin() + bytesRead), comp;
        if (!compressChunk(raw, comp)) { fclose(f); return; }

        // Encrypt
        std::vector<unsigned char> cipher;
        if (!encryptChunk(comp, cipher, sessionKey, chunkCounter++)) {
            std::cerr << "\nEncryption failed" << std::endl;
            fclose(f);
            return;
        }

        uint32_t orig = htonl(static_cast<uint32_t>(bytesRead));
        uint32_t cps  = htonl(static_cast<uint32_t>(cipher.size()));
        send(fd, reinterpret_cast<char*>(&orig), sizeof(orig), 0);
        send(fd, reinterpret_cast<char*>(&cps), sizeof(cps), 0);

        size_t sent = 0;
        while (sent < cipher.size()) {
            ssize_t s = send(fd, reinterpret_cast<char*>(cipher.data()) + sent,
                             cipher.size() - sent, 0);
            if (s <= 0) { perror("send data"); fclose(f); return; }
            sent += s;
        }
    }

    fclose(f);

    auto totalElapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - startTime).count();
    double finalMbps = (bytesProcessed / (1024.0 * 1024.0)) /
                       (totalElapsed > 0 ? totalElapsed : 1.0);
    std::cout << "\rProgress: 100% ("
              << std::fixed << std::setprecision(1)
              << finalMbps << " MB/s)\n";
    std::cout << "[DEBUG] Finished sending file" << std::endl;
}

void receiveFile(int fd, const std::string &outPath, const std::vector<unsigned char>& sessionKey) {
    std::cout << "[DEBUG] Receiving to: " << outPath << std::endl;
    FILE* f = fopen(outPath.c_str(), "wb");
    if (!f) { perror("fopen receiveFile"); return; }

    size_t bytesReceived = 0;
    auto startTime = std::chrono::steady_clock::now();
    uint64_t chunkCounter = 0;

    while (true) {
        uint32_t orig_n, cps_n;
        if (recv(fd, reinterpret_cast<char*>(&orig_n), sizeof(orig_n), 0) <= 0) break;
        if (recv(fd, reinterpret_cast<char*>(&cps_n), sizeof(cps_n), 0) <= 0) break;

        size_t orig = ntohl(orig_n), cps = ntohl(cps_n);
        std::vector<unsigned char> cipher(cps);
        size_t recvd = 0;
        while (recvd < cps) {
            ssize_t r = recv(fd, reinterpret_cast<char*>(cipher.data()) + recvd, cps - recvd, 0);
            if (r <= 0) { perror("recv data"); fclose(f); return; }
            recvd += r;
        }

        std::vector<char> comp, decomp;
        if (!decryptChunk(cipher, comp, sessionKey, chunkCounter++)) {
            std::cerr << "Decryption/auth failed" << std::endl;
            fclose(f);
            return;
        }
        if (!decompressChunk(comp, decomp, orig)) {
            std::cerr << "Decompression failed" << std::endl;
            fclose(f);
            return;
        }

        fwrite(decomp.data(), 1, decomp.size(), f);
        bytesReceived += decomp.size();

        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - startTime).count();
        double mbps = (bytesReceived / (1024.0 * 1024.0)) / (elapsed > 0 ? elapsed : 1.0);

        std::cout << "\rReceiving: "
                  << std::fixed << std::setprecision(1)
                  << mbps << " MB/s"
                  << std::flush;
    }

    fclose(f);
    std::cout << "\n[DEBUG] Finished receiving file" << std::endl;
}

} // namespace FileTransfer

namespace Discovery {

int createUDPSocket(bool reuse=false, bool broadcast=false) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    int opt = 1;
    if (reuse)     setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#ifdef SO_REUSEPORT
    if (reuse)     setsockopt(s, SOL_SOCKET, SO_REUSEPORT,  (char*)&opt, sizeof(opt));
#endif
    if (broadcast) setsockopt(s, SOL_SOCKET, SO_BROADCAST,   (char*)&opt, sizeof(opt));
    return s;
}

void broadcastAvailability(int port, const std::string &alias) {
    int s = createUDPSocket(false, true);
    sockaddr_in b{};
    b.sin_family      = AF_INET;
    b.sin_port        = htons(DISCOVERY_PORT);
    b.sin_addr.s_addr = INADDR_BROADCAST;
    std::string msg = std::string(DISCOVERY_MESSAGE)
                    + ":" + std::to_string(port)
                    + ":" + alias
                    + ":" + currentListenPin;
    while (true) {
        sendto(s, msg.c_str(), msg.size(), 0, (sockaddr*)&b, sizeof(b));
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    CLOSE_SOCKET(s);
}

struct Receiver {
    std::string ip;
    int port;
    std::string alias;
    std::string pin;
};

} // namespace Discovery

// ----------------------------------------------------------------------------
// Persistent discovery listener defines (so we don't re-bind each /discover):
static std::vector<Discovery::Receiver> g_peers;
static std::mutex                       g_peersMutex;

static void discoveryListener() {
    int s = Discovery::createUDPSocket(true, false);
    if (s < 0) {
        perror("discoveryListener socket");
        return;
    }
    // Bind once, reuse address/port
    sockaddr_in bindAddr{};
    bindAddr.sin_family      = AF_INET;
    bindAddr.sin_port        = htons(DISCOVERY_PORT);
    bindAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr)) < 0) {
        perror("discoveryListener bind");
        CLOSE_SOCKET(s);
        return;
    }

    while (true) {
        char buf[512];
        sockaddr_in from{};
        socklen_t len = sizeof(from);
        ssize_t n = recvfrom(s, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &len);
        if (n <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        buf[n] = '\0';
        std::string msg(buf);
        if (msg.rfind(DISCOVERY_MESSAGE, 0) != 0) continue;

        // parse "QUICKDROP_DISCOVERY:port:alias:pin"
        size_t p1 = msg.find(':'),
               p2 = msg.find(':', p1+1),
               p3 = msg.find(':', p2+1);
        if (p1 == std::string::npos ||
            p2 == std::string::npos ||
            p3 == std::string::npos) continue;

        Discovery::Receiver r;
        r.ip    = inet_ntoa(from.sin_addr);
        r.port  = std::stoi(msg.substr(p1+1, p2-p1-1));
        r.alias = msg.substr(p2+1, p3-p2-1);
        r.pin   = msg.substr(p3+1);

        std::lock_guard<std::mutex> lk(g_peersMutex);
        bool exists = false;
        for (auto &e : g_peers) {
            if (e.ip == r.ip &&
                e.port == r.port &&
                e.alias == r.alias &&
                e.pin == r.pin) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            g_peers.push_back(r);
        }
    }

    CLOSE_SOCKET(s);
}

// ----------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    FileTransfer::initSockets();
    std::string cmd = (argc > 1 ? argv[1] : "");

    // Web UI mode
    if (cmd == "web") {
        // generate a new 4-digit PIN for this listener session
        {
            std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<int> dist(1000, 9999);
            currentListenPin = std::to_string(dist(rng));
        }

        // start persistent discovery listener
        std::thread(discoveryListener).detach();

        crow::SimpleApp app;

        // Serve landing page + JS/CSS
        CROW_ROUTE(app, "/")([](){
            return crow::response(200, R"(
<!DOCTYPE html>
<html>
<head>
    <title>QuickDrop Web UI</title>
    <style>
        body { font-family: Arial, sans-serif; background: #121212; color: #eee; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .section { margin: 20px 0; padding: 20px; background: #1e1e1e; border-radius: 5px; }
        button { padding: 10px 20px; margin: 5px; background: #bb86fc; color: #121212; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background: #9a63d8; }
        input, select { padding: 8px; margin: 5px 0; background: #2c2c2c; border: none; border-radius: 3px; color: #eee; }
        #peers { margin: 10px 0; }
        .peer { padding: 5px; margin: 2px 0; background: #2c2c2c; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>QuickDrop Web UI</h1>

        <div class="section">
            <h3>Discover Peers</h3>
            <button onclick=discoverPeers()>Discover</button>
            <div id="peers"></div>
        </div>

        <div class="section">
            <h3>Send File</h3>
            <input type=file id=fileInput><br>
            <input type=text id=filename placeholder=Filename to send><br>
            <input type=text id=pinInput placeholder=Enter receiver PIN><br>
            <input type=text id=targetIP placeholder=Target IP value=127.0.0.1><br>
            <input type=number id=targetPort placeholder=Port value=9000><br>
            <button onclick=sendFile()>Send File</button>
        </div>

        <div class="section">
            <h3>Listen for Files</h3>
            <p>Session PIN: <strong id=sessionPin>__</strong></p>
            <input type=text id=alias placeholder=Alias value=QuickDropPeer><br>
            <button onclick=startListening()>Start Listening</button>
        </div>
    </div>

    <script>
        function discoverPeers() {
            fetch('/discover')
            .then(resp => resp.json())
            .then(peers => {
                const div = document.getElementById('peers');
                div.innerHTML = '';
                for (let i = 0; i < peers.length; i++) {
                    const peer = peers[i];
                    const e = document.createElement('div');
                    e.className = 'peer';
                    e.textContent = peer.alias + ' (' + peer.ip + ':' + peer.port + ') PIN: ' + peer.pin;
                    div.appendChild(e);
                }
            })
            .catch(err => {
                console.error(err);
                alert('Discover failed');
            });
        }

        function sendFile() {
            const fileIn  = document.getElementById('fileInput');
            const name    = document.getElementById('filename').value.trim();
            const pin     = document.getElementById('pinInput').value.trim();
            const ip      = document.getElementById('targetIP').value;
            const port    = document.getElementById('targetPort').value;

            if (!fileIn.files[0])    { alert('Select a file');     return; }
            if (!name)               { alert('Enter a filename');  return; }
            if (!pin)                { alert('Enter receiver PIN'); return; }

            const fd = new FormData();
            fd.append('file',     fileIn.files[0]);
            fd.append('filename', name);
            fd.append('pin',      pin);
            fd.append('ip',       ip);
            fd.append('port',     port);

            fetch('/send', { method: 'POST', body: fd })
            .then(r => {
                if (r.status === 202)       alert('File sent!');
                else if (r.status === 403)  alert('Invalid PIN');
                else                         alert('Send error');
            })
            .catch(err => {
                console.error(err);
                alert('Send failed');
            });
        }

        function startListening() {
            const alias = document.getElementById('alias').value;
            fetch('/listen?alias=' + encodeURIComponent(alias))
            .then(r => {
                if (r.ok) {
                    return r.json();
                } else {
                    throw new Error('Listen failed');
                }
            })
            .then(j => {
                document.getElementById('sessionPin').textContent = j.pin;
                alert('Listening, PIN: ' + j.pin);
            })
            .catch(err => {
                console.error(err);
                alert('Listen error');
            });
        }
    </script>
</body>
</html>
            )");
        });

        // Discover—returns the in-memory vector, no re-binding
        CROW_ROUTE(app, "/discover")([](){
            std::lock_guard<std::mutex> lk(g_peersMutex);
            crow::json::wvalue out;
            for (size_t i = 0; i < g_peers.size(); ++i) {
                out[i]["alias"] = g_peers[i].alias;
                out[i]["ip"]    = g_peers[i].ip;
                out[i]["port"]  = g_peers[i].port;
                out[i]["pin"]   = g_peers[i].pin;
            }
            return crow::response(200, out);
        });

        // Listen—starts the broadcast & file-receive loop
        CROW_ROUTE(app, "/listen")([&](const crow::request& req){
            auto alias = req.url_params.get("alias") ? req.url_params.get("alias") : "QuickDropPeer";
            std::thread([alias](){
                std::thread(Discovery::broadcastAvailability, PORT_DEFAULT, alias).detach();
                int lst = FileTransfer::createListener(PORT_DEFAULT);
                while (true) {
                    sockaddr_in peer{}; socklen_t len = sizeof(peer);
                    int conn = accept(lst, (sockaddr*)&peer, &len);
                    if (conn < 0) break;
                    std::vector<unsigned char> key;
                    if (doKeyExchange(conn, key)) {
                        FileTransfer::receiveFile(conn, "received.bin", key);
                    }
                    CLOSE_SOCKET(conn);
                }
            }).detach();
            crow::json::wvalue res;
            res["pin"] = currentListenPin;
            return crow::response(200, res);
        });

        // Send—with PIN check
        CROW_ROUTE(app, "/send").methods("POST"_method)([&](const crow::request& req){
            auto parts = crow::multipart::message(req);
            if (parts.get_part_by_name("pin").body != currentListenPin) {
                return crow::response(403, "Invalid PIN");
            }
            std::string filename = "uploaded";
            auto fnp = parts.get_part_by_name("filename");
            if (!fnp.body.empty()) filename = fnp.body;

            std::string tmp = "/tmp/" + filename;
            auto fp = parts.get_part_by_name("file");
            if (!fp.body.empty()) {
                std::ofstream ofs(tmp, std::ios::binary);
                ofs.write(fp.body.c_str(), fp.body.size());
            }

            std::string ip = "127.0.0.1";
            int port = PORT_DEFAULT;
            auto ip_p = parts.get_part_by_name("ip");
            auto pt_p = parts.get_part_by_name("port");
            if (!ip_p.body.empty()) ip   = ip_p.body;
            if (!pt_p.body.empty()) port = std::stoi(pt_p.body);

            std::thread([tmp, ip, port](){
                int sock = FileTransfer::createConnection(ip, port);
                std::vector<unsigned char> key;
                if (doKeyExchange(sock, key)) {
                    FileTransfer::sendFile(sock, tmp, key);
                }
                CLOSE_SOCKET(sock);
            }).detach();

            return crow::response(202);
        });

        app.port(8080).multithreaded().run();
        FileTransfer::cleanupSockets();
        return 0;
    }

    // ------------------------------------------------------------------------

    // CLI modes unchanged from before…
    if (cmd == "listen") {
        std::string alias   = (argc > 2 ? argv[2] : "QuickDropPeer");
        std::string outFile = (argc > 3 ? argv[3] : "received.bin");
        std::thread bc(Discovery::broadcastAvailability, PORT_DEFAULT, alias);
        bc.detach();
        int lst = FileTransfer::createListener(PORT_DEFAULT);
        std::cout << "QuickDrop listening as '" << alias
                  << "' on port " << PORT_DEFAULT << ". Ctrl-C to quit." << std::endl;
        while (true) {
            sockaddr_in peer{}; socklen_t len = sizeof(peer);
            int conn = accept(lst, (sockaddr*)&peer, &len);
            if (conn < 0) { perror("accept"); break; }
            std::vector<unsigned char> sessionKey;
            if (!doKeyExchange(conn, sessionKey)) {
                std::cerr << "Key exchange failed" << std::endl;
                CLOSE_SOCKET(conn);
                continue;
            }
            FileTransfer::receiveFile(conn, outFile, sessionKey);
            CLOSE_SOCKET(conn);
        }
        CLOSE_SOCKET(lst);
        FileTransfer::cleanupSockets();
        return 0;
    }
    else if (cmd == "discover") {
        // Start discovery listener temporarily
        std::thread(discoveryListener).detach();
        std::this_thread::sleep_for(std::chrono::seconds(3));
        
        std::lock_guard<std::mutex> lk(g_peersMutex);
        if (g_peers.empty()) {
            std::cout << "No receivers found." << std::endl;
        } else {
            for (size_t i = 0; i < g_peers.size(); ++i) {
                std::cout << "  " << (i+1) << ": "
                          << g_peers[i].alias << " ("
                          << g_peers[i].ip << ":"
                          << g_peers[i].port << ") PIN: "
                          << g_peers[i].pin << "\n";
            }
        }
    }
    else if (cmd == "send" && argc == 3) {
        std::string filepath = argv[2];
        
        // Start discovery listener temporarily
        std::thread(discoveryListener).detach();
        std::this_thread::sleep_for(std::chrono::seconds(3));
        
        std::lock_guard<std::mutex> lk(g_peersMutex);
        if (g_peers.empty()) {
            std::cerr << "No receivers to send to." << std::endl;
            return 1;
        }
        auto target = g_peers[0];
        int sock = FileTransfer::createConnection(target.ip, target.port);
        if (sock < 0) return 1;
        std::vector<unsigned char> sessionKey;
        if (!doKeyExchange(sock, sessionKey)) {
            CLOSE_SOCKET(sock);
            return 1;
        }
        FileTransfer::sendFile(sock, filepath, sessionKey);
        CLOSE_SOCKET(sock);
    }
    else if (cmd == "send-to" && argc == 4) {
        std::string filepath = argv[2];
        std::string target   = argv[3];
        size_t pos = target.find(':');
        std::string ip   = target.substr(0, pos);
        int port         = (pos != std::string::npos) ? std::stoi(target.substr(pos+1)) : PORT_DEFAULT;
        int sock = FileTransfer::createConnection(ip, port);
        if (sock < 0) return 1;
        std::vector<unsigned char> sessionKey;
        if (!doKeyExchange(sock, sessionKey)) {
            CLOSE_SOCKET(sock);
            return 1;
        }
        FileTransfer::sendFile(sock, filepath, sessionKey);
        CLOSE_SOCKET(sock);
    }
    else {
        std::cout << "Usage:\n"
                  << "  QuickDrop web                       # launch browser UI\n"
                  << "  QuickDrop listen [alias] [outFile]  # listen (CLI)\n"
                  << "  QuickDrop discover                  # discover (CLI)\n"
                  << "  QuickDrop send <file>               # send (CLI)\n"
                  << "  QuickDrop send-to <file> <ip:port>  # send-to (CLI)\n";
    }

    FileTransfer::cleanupSockets();
    return 0;
}
