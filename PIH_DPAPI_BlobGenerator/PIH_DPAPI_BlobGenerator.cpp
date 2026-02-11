// Requiere OpenSSL 1.1+ o 3.x
// vcpkg: vcpkg install openssl
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>

static const std::vector<uint8_t> PASS_OBF = {
    0xFA, 0xE3, 0xE2, 0x87, 0xF9, 0xFE, 0xEB, 0xFE, 0xE3, 0xE9, 0x87,0xEF,
    0xE4, 0xFE, 0xF8, 0xE5, 0xFA, 0xF3, 0x87, 0x98, 0x9A, 0x98, 0x9C
};
static const uint8_t PASS_KEY = 0xAA;
static const int PBKDF2_ITERATIONS = 200000; // Ajusta según políticas
static const size_t SALT_LEN = 16;
static const size_t NONCE_LEN = 12;
static const size_t TAG_LEN = 16;
static const size_t KEY_LEN = 32; // AES-256

char* xorDecode(const std::vector<uint8_t>& data, uint8_t key)
{
    char* out = new char[data.size() + 1];
    for (size_t i = 0; i < data.size(); i++)
        out[i] = static_cast<char>(data[i] ^ key);
    out[data.size()] = '\0';
    return out;
}

int main()
{
    // 1) Credenciales a empaquetar (igual que tu flujo actual)
    const char* user = "StringTestAdmin";
    const char* pass = "StringTestPassword";

    std::string combined(user);
    combined.push_back('\0');
    combined += pass;
    combined.push_back('\0');

    // 2) Passphrase ofuscada (tu ENTROPY equivalente, pero usada para derivar clave)
    std::unique_ptr<char[]> passphrase(xorDecode(PASS_OBF, PASS_KEY));
    const unsigned char* pwd = reinterpret_cast<const unsigned char*>(passphrase.get());
    const int pwdLen = static_cast<int>(std::strlen(passphrase.get()));

    // 3) Genera salt y nonce aleatorios
    unsigned char salt[SALT_LEN];
    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(salt, (int)SALT_LEN) != 1 || RAND_bytes(nonce, (int)NONCE_LEN) != 1) {
        std::cerr << "[ERROR] RAND_bytes failed\n";
        return 1;
    }

    // 4) Deriva la clave con PBKDF2-HMAC-SHA256
    unsigned char key[KEY_LEN];
    if (PKCS5_PBKDF2_HMAC(passphrase.get(), pwdLen, salt, (int)SALT_LEN,
        PBKDF2_ITERATIONS, EVP_sha256(), (int)KEY_LEN, key) != 1) {
        std::cerr << "[ERROR] PBKDF2 failed\n";
        return 1;
    }

    // 5) AES-GCM encrypt
    std::vector<unsigned char> ciphertext(combined.size());
    unsigned char tag[TAG_LEN];

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[ERROR] EVP_CIPHER_CTX_new failed\n";
        return 1;
    }

    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)NONCE_LEN, nullptr);
    ok &= EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce);
    int outLen = 0, total = 0;
    ok &= EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen,
        reinterpret_cast<const unsigned char*>(combined.data()),
        (int)combined.size());
    total = outLen;
    ok &= EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &outLen);
    total += outLen;
    ciphertext.resize(total);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        std::cerr << "[ERROR] AES-GCM encryption failed\n";
        return 1;
    }

    // 6) Escribir blob portable: [MAGIC][VER][SALT][NONCE][TAG][CIPHERTEXT]
    const uint32_t MAGIC = 0x50494842; // 'PIHB'
    const uint16_t VER = 0x0001;

    std::ofstream ofs("artifacts/default_creds.blob", std::ios::binary);
    if (!ofs) {
        std::cerr << "[ERROR] cannot create artifacts/default_creds.blob\n";
        return 1;
    }

    ofs.write(reinterpret_cast<const char*>(&MAGIC), sizeof(MAGIC));
    ofs.write(reinterpret_cast<const char*>(&VER), sizeof(VER));
    ofs.write(reinterpret_cast<const char*>(salt), SALT_LEN);
    ofs.write(reinterpret_cast<const char*>(nonce), NONCE_LEN);
    ofs.write(reinterpret_cast<const char*>(tag), TAG_LEN);
    ofs.write(reinterpret_cast<const char*>(ciphertext.data()), (std::streamsize)ciphertext.size());
    ofs.close();

    std::cout << "[OK] Blob portable generado correctamente.\n";
    return 0;
}