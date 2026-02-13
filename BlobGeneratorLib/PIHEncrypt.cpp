#include "pch.h"
#include "PIHEncrypt.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h> // OPENSSL_cleanse
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <limits>
#include <stdexcept>

// ====== Parámetros criptográficos (idénticos al ejemplo) ======
static const int    PBKDF2_ITERATIONS = 200000;
static const size_t SALT_LEN = 16;
static const size_t NONCE_LEN = 12;
static const size_t TAG_LEN = 16;
static const size_t KEY_LEN = 32; // AES-256

// ====== Formato de blob ======
static const uint32_t MAGIC = 0x50494842; // 'PIHB'
static const uint16_t VER = 0x0001;

// ====== Manejo de error thread-local ======
static thread_local std::string g_lastError;

static void set_last_error(const char* msg) {
    g_lastError = (msg ? msg : "");
}

extern "C" MYENC_API const char* PIH_GetLastErrorMessage() {
    return g_lastError.c_str();
}

// Secure zero helper (intenta usar OPENSSL_cleanse)
static void secure_zero(void* p, size_t n) {
    if (!p || n == 0) return;
    OPENSSL_cleanse(p, n);
}

// ====== Lógica principal ======
static int encrypt_and_write_blob(const char* user,
    const char* pass,
    const char* pwd,
    const char* outPath)
{
    try {
        if (!user || !pass || !pwd || !outPath) {
            set_last_error("Invalid argument: null pointer.");
            return PIH_ERR_INVALID_ARG;
        }

        // 1) Empaquetar credenciales como en el ejemplo: user\0pass\0
        std::string combined(user);
        combined.push_back('\0');
        combined += pass;
        combined.push_back('\0');

        // 2) Preparar pwd
        const int pwdLen = static_cast<int>(std::strlen(pwd));
        if (pwdLen <= 0) {
            set_last_error("Invalid argument: empty password for PBKDF2.");
            return PIH_ERR_INVALID_ARG;
        }

        // 3) Salt y nonce aleatorios
        unsigned char salt[SALT_LEN];
        unsigned char nonce[NONCE_LEN];
        if (RAND_bytes(salt, (int)SALT_LEN) != 1 || RAND_bytes(nonce, (int)NONCE_LEN) != 1) {
            set_last_error("RAND_bytes failed.");
            return PIH_ERR_RAND;
        }

        // 4) Derivar clave con PBKDF2-HMAC-SHA256
        unsigned char key[KEY_LEN];
        if (PKCS5_PBKDF2_HMAC(pwd, pwdLen, salt, (int)SALT_LEN,
            PBKDF2_ITERATIONS, EVP_sha256(), (int)KEY_LEN, key) != 1) {
            set_last_error("PBKDF2 failed.");
            return PIH_ERR_PBKDF2;
        }

        // 5) AES-256-GCM
        std::vector<unsigned char> ciphertext(combined.size());
        unsigned char tag[TAG_LEN];

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            secure_zero(key, KEY_LEN);
            set_last_error("EVP_CIPHER_CTX_new failed.");
            return PIH_ERR_EVP;
        }

        int ok = 1;
        ok &= EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)NONCE_LEN, nullptr);
        ok &= EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce);

        int outLen = 0, total = 0;
        ok &= EVP_EncryptUpdate(ctx,
            ciphertext.data(), &outLen,
            reinterpret_cast<const unsigned char*>(combined.data()),
            (int)combined.size());
        total = outLen;

        // Final GCM
        ok &= EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &outLen);
        total += outLen;
        if (total < 0) total = 0;
        ciphertext.resize((size_t)total);

        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)TAG_LEN, tag);

        EVP_CIPHER_CTX_free(ctx);
        secure_zero(key, KEY_LEN);

        if (!ok) {
            set_last_error("AES-GCM encryption failed.");
            return PIH_ERR_EVP;
        }

        // 6) Escribir blob: [MAGIC][VER][SALT][NONCE][TAG][CIPHERTEXT]
        std::ofstream ofs(outPath, std::ios::binary);
        if (!ofs) {
            set_last_error("Cannot open output file.");
            return PIH_ERR_IO;
        }

        ofs.write(reinterpret_cast<const char*>(&MAGIC), sizeof(MAGIC));
        ofs.write(reinterpret_cast<const char*>(&VER), sizeof(VER));
        ofs.write(reinterpret_cast<const char*>(salt), (std::streamsize)SALT_LEN);
        ofs.write(reinterpret_cast<const char*>(nonce), (std::streamsize)NONCE_LEN);
        ofs.write(reinterpret_cast<const char*>(tag), (std::streamsize)TAG_LEN);
        if (!ciphertext.empty()) {
            ofs.write(reinterpret_cast<const char*>(ciphertext.data()),
                (std::streamsize)ciphertext.size());
        }
        ofs.close();

        // Limpiar sensible en RAM
        secure_zero(ciphertext.data(), ciphertext.size());
        secure_zero((void*)combined.data(), combined.size());

        set_last_error(""); // éxito, limpiar mensaje
        return PIH_OK;
    }
    catch (const std::exception& ex) {
        set_last_error(ex.what());
        return PIH_ERR_EXCEPTION;
    }
    catch (...) {
        set_last_error("Unknown exception.");
        return PIH_ERR_EXCEPTION;
    }
}

extern "C" MYENC_API int PIH_EncryptCredentialsToFile(const char* user,
    const char* pass,
    const char* pwd,
    const char* outPath)
{
    return encrypt_and_write_blob(user, pass, pwd, outPath);
}

extern "C" MYENC_API int PIH_GenerateDefaultCredsBlob() {
    const char* user = "StringTestAdmin";
    const char* pass = "StringTestPassword";
    const char* pwd = "PIH-STATIC-ENTROPY-2026";
    const char* outPath = "artifacts/default_creds.blob";
    return encrypt_and_write_blob(user, pass, pwd, outPath);
}