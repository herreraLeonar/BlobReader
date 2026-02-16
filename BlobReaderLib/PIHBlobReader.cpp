#include "pch.h"              // Solo para precompiled headers
#include "PIHBlobReader.h"
#include "resource.h"

#include <windows.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>   // OPENSSL_cleanse
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <cwchar>
#include <stdexcept>
#include <cstdint>

// --- Loader del recurso embebido (RCDATA) ---
extern "C" IMAGE_DOS_HEADER __ImageBase; // Para obtener HMODULE del módulo actual

// ====== Estructuras ======
struct BlobView {
    const unsigned char* data;
    size_t size;
};

// ====== Parámetros y formato de blob ======
static const uint32_t MAGIC_EXPECTED = 0x50494842; // 'PIHB'
static const uint16_t VER_EXPECTED = 0x0001;
static const size_t   SALT_LEN = 16;
static const size_t   NONCE_LEN = 12;
static const size_t   TAG_LEN = 16;
static const size_t   KEY_LEN = 32; // AES-256
static const int      PBKDF2_ITERATIONS = 200000;

// ====== Manejo de error thread-local ======
static thread_local std::string g_lastError;
static void set_last_error(const char* msg) { g_lastError = (msg ? msg : ""); }

extern "C" PIHREADER_API const char* PIHBR_GetLastErrorMessage() {
    return g_lastError.c_str();
}

// ====== Helpers de seguridad ======
static void secure_zero(void* p, size_t n) {
    if (p && n) OPENSSL_cleanse(p, n);
}

// ====== XOR / Ofuscación dinámica de entropy ======
static char* xorDecode(const std::vector<uint8_t>& data, uint8_t key) {
    char* out = new char[data.size() + 1];
    for (size_t i = 0; i < data.size(); ++i) out[i] = static_cast<char>(data[i] ^ key);
    out[data.size()] = '\0';
    return out;
}

static inline uint8_t DeriveKey() {
    uint8_t k = 0;
    k ^= 0xC3;
    k ^= 0x69;
    k = (uint8_t)((k ^ 0x00) + 0x00 - 0x00);
    return k; // 0xAA
}

static std::vector<uint8_t> ApplyUnshuffle(const std::vector<uint8_t>& shuffled,
    const std::vector<uint8_t>& perm) {
    const size_t n = shuffled.size();
    if (perm.size() != n) throw std::runtime_error("Invalid permutation size");
    std::vector<uint8_t> original(n, 0);
    for (size_t i = 0; i < n; ++i) {
        const size_t origPos = perm[i];
        if (origPos >= n) throw std::runtime_error("Permutation index out of range");
        original[origPos] = shuffled[i];
    }
    return original;
}

// Reconstruye: "PIH-STATIC-ENTROPY-2026" (sin literal en binario).
static char* BuildEntropy() {
    // Bytes obfuscados (ascii ^ 0xAA) y barajados. Longitud = 23
    const std::vector<uint8_t> OBF{
        0x87, 0xFE, 0xE3, 0xFE, 0xFA, 0xF8, 0xE9, 0xE2, 0xE4, 0xF9, 0xEB, 0xE3,
        0x87, 0xFE, 0xEF, 0xE5, 0xFA, 0x98, 0x87, 0x9A, 0xF3, 0x9C, 0x98
    };
    const std::vector<uint8_t> PERM{
        3, 7, 1, 5, 0, 14, 9, 2, 12, 4, 6, 8, 10, 13, 11, 15, 16, 19, 18, 20, 17, 22, 21
    };
    static const uint8_t PASS_KEY = DeriveKey();

    std::vector<uint8_t> xored = ApplyUnshuffle(OBF, PERM);
    char* entropy = xorDecode(xored, PASS_KEY); // new[] + '\0'
    return entropy;
}

// ====== Núcleo de descifrado desde MEMORIA ======
static int DecryptBlobFromMemory(const unsigned char* buf, size_t len,
    std::string& outUser, std::string& outPass) {
    try {
        if (!buf || len == 0) {
            set_last_error("Invalid argument: memory blob is null/empty.");
            return PIHBR_ERR_INVALID_ARG;
        }

        if (len < sizeof(uint32_t) + sizeof(uint16_t) + SALT_LEN + NONCE_LEN + TAG_LEN) {
            set_last_error("Blob too short for expected header.");
            return PIHBR_ERR_INVALID_BLOB;
        }

        size_t offset = 0;
        uint32_t magic = 0; std::memcpy(&magic, buf + offset, sizeof(magic)); offset += sizeof(magic);
        uint16_t ver = 0; std::memcpy(&ver, buf + offset, sizeof(ver));   offset += sizeof(ver);

        if (magic != MAGIC_EXPECTED || ver != VER_EXPECTED) {
            set_last_error("Unrecognized blob header (MAGIC/VER mismatch).");
            return PIHBR_ERR_INVALID_BLOB;
        }

        const unsigned char* salt = buf + offset; offset += SALT_LEN;
        const unsigned char* nonce = buf + offset; offset += NONCE_LEN;
        const unsigned char* tag = buf + offset; offset += TAG_LEN;

        if (offset > len) {
            set_last_error("Invalid header lengths.");
            return PIHBR_ERR_INVALID_BLOB;
        }

        const size_t ciphertext_len = len - offset;
        if (ciphertext_len == 0) {
            set_last_error("Empty ciphertext.");
            return PIHBR_ERR_INVALID_BLOB;
        }

        const unsigned char* ciphertext = buf + offset;

        // Reconstruir passphrase (entropy)
        struct ArrDel { void operator()(char* p) const { if (p) { OPENSSL_cleanse(p, std::strlen(p)); delete[] p; } } };
        std::unique_ptr<char[], ArrDel> passphrase(BuildEntropy());
        if (!passphrase) {
            set_last_error("Failed to build passphrase.");
            return PIHBR_ERR_EXCEPTION;
        }
        const int pwdLen = static_cast<int>(std::strlen(passphrase.get()));
        if (pwdLen <= 0) {
            set_last_error("Invalid passphrase length.");
            return PIHBR_ERR_INVALID_BLOB;
        }

        // Derivar clave
        unsigned char key[KEY_LEN];
        if (PKCS5_PBKDF2_HMAC(passphrase.get(), pwdLen, salt, (int)SALT_LEN,
            PBKDF2_ITERATIONS, EVP_sha256(), (int)KEY_LEN, key) != 1) {
            set_last_error("PBKDF2 failed.");
            secure_zero(key, KEY_LEN);
            return PIHBR_ERR_PBKDF2;
        }

        // AES-256-GCM decrypt
        std::vector<unsigned char> plaintext(ciphertext_len);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            set_last_error("EVP_CIPHER_CTX_new failed.");
            secure_zero(key, KEY_LEN);
            return PIHBR_ERR_EVP;
        }

        int ok = 1;
        ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)NONCE_LEN, nullptr);
        ok &= EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce);

        int outLen = 0, total = 0;
        ok &= EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext, (int)ciphertext_len);
        total = outLen;

        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)TAG_LEN, const_cast<unsigned char*>(tag));

        int finalLen = 0;
        ok &= EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &finalLen);
        EVP_CIPHER_CTX_free(ctx);
        secure_zero(key, KEY_LEN);

        if (!ok) {
            set_last_error("AES-GCM decryption failed (invalid TAG or corrupt data).");
            secure_zero(plaintext.data(), plaintext.size());
            return PIHBR_ERR_EVP;
        }

        total += finalLen;
        plaintext.resize((size_t)total);

        // Parseo user\0pass\0
        const char* p = reinterpret_cast<const char*>(plaintext.data());
        const size_t n = plaintext.size();

        const char* pEnd = (const char*)memchr(p, '\0', n);
        if (!pEnd) {
            set_last_error("Decrypted data format invalid (no first NUL).");
            secure_zero(plaintext.data(), plaintext.size());
            return PIHBR_ERR_INVALID_BLOB;
        }
        outUser.assign(p, pEnd - p);

        size_t consumed = (pEnd - p) + 1;
        if (consumed > n) {
            set_last_error("Decrypted data format invalid (bounds).");
            secure_zero(plaintext.data(), plaintext.size());
            return PIHBR_ERR_INVALID_BLOB;
        }
        const char* p2 = p + consumed;
        const size_t n2 = n - consumed;

        const char* p2End = (const char*)memchr(p2, '\0', n2);
        if (!p2End) p2End = p2 + n2;
        outPass.assign(p2, p2End - p2);

        secure_zero(plaintext.data(), plaintext.size());
        set_last_error("");
        return PIHBR_OK;
    }
    catch (const std::exception& ex) {
        set_last_error(ex.what());
        return PIHBR_ERR_EXCEPTION;
    }
    catch (...) {
        set_last_error("Unknown exception.");
        return PIHBR_ERR_EXCEPTION;
    }
}

// ====== Cargar blob embebido (RT_RCDATA) ======
static BlobView GetBlobFromResource(UINT resourceId) {
    HMODULE hMod = (HMODULE)&__ImageBase;
    HRSRC hRes = FindResourceW(hMod, MAKEINTRESOURCE(resourceId), RT_RCDATA);
    if (!hRes) {
        set_last_error("FindResource(RT_RCDATA) failed");
        throw std::runtime_error("FindResource failed");
    }
    HGLOBAL hData = LoadResource(hMod, hRes);
    if (!hData) {
        set_last_error("LoadResource failed");
        throw std::runtime_error("LoadResource failed");
    }
    DWORD size = SizeofResource(hMod, hRes);
    if (size == 0) {
        set_last_error("SizeofResource returned 0");
        throw std::runtime_error("SizeofResource returned 0");
    }
    const void* ptr = LockResource(hData);
    if (!ptr) {
        set_last_error("LockResource failed");
        throw std::runtime_error("LockResource failed");
    }
    return { static_cast<const unsigned char*>(ptr), static_cast<size_t>(size) };
}

// ====== Núcleo de descifrado desde PATH (existente) ======
static int DecryptBlobImpl(const wchar_t* blobPath, std::string& outUser, std::string& outPass) {
    try {
        if (!blobPath) {
            set_last_error("Invalid argument: blobPath is null.");
            return PIHBR_ERR_INVALID_ARG;
        }

        // Abrir el blob
        HANDLE h = CreateFileW(blobPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            set_last_error("Cannot open .blob file.");
            return PIHBR_ERR_IO;
        }

        LARGE_INTEGER fsizeLI{};
        if (!GetFileSizeEx(h, &fsizeLI)) {
            CloseHandle(h);
            set_last_error("GetFileSizeEx failed.");
            return PIHBR_ERR_IO;
        }
        if (fsizeLI.QuadPart <= 0 || fsizeLI.QuadPart > SIZE_MAX) {
            CloseHandle(h);
            set_last_error("File too large or invalid size.");
            return PIHBR_ERR_IO;
        }
        size_t size = static_cast<size_t>(fsizeLI.QuadPart);

        std::vector<unsigned char> buf(size);
        DWORD br = 0;
        BOOL rf = ReadFile(h, buf.data(), (DWORD)size, &br, nullptr);
        CloseHandle(h);
        if (!rf || br != size) {
            set_last_error("Failed to read .blob file.");
            return PIHBR_ERR_IO;
        }

        // Reutilizamos el pipeline de memoria:
        return DecryptBlobFromMemory(buf.data(), buf.size(), outUser, outPass);
    }
    catch (const std::exception& ex) {
        set_last_error(ex.what());
        return PIHBR_ERR_EXCEPTION;
    }
    catch (...) {
        set_last_error("Unknown exception.");
        return PIHBR_ERR_EXCEPTION;
    }
}

// ====== API: buffers del llamador (PATH) ======
extern "C" PIHREADER_API int PIH_DecryptBlobW(const wchar_t* blobPath,
    char* outUser, size_t userCapacity,
    char* outPass, size_t passCapacity,
    size_t* outUserNeeded,
    size_t* outPassNeeded) {
    std::string user, pass;
    int st = DecryptBlobImpl(blobPath, user, pass);
    if (st != PIHBR_OK) return st;

    // Tamaños requeridos (incluyen '\0')
    const size_t needUser = user.size() + 1;
    const size_t needPass = pass.size() + 1;
    if (outUserNeeded) *outUserNeeded = needUser;
    if (outPassNeeded) *outPassNeeded = needPass;

    if ((outUser && userCapacity < needUser) || (outPass && passCapacity < needPass)) {
        set_last_error("Insufficient buffer.");
        return PIHBR_ERR_INSUFFICIENT_BUFFER;
    }

    if (outUser) {
        std::memcpy(outUser, user.c_str(), needUser);
    }
    if (outPass) {
        std::memcpy(outPass, pass.c_str(), needPass);
    }
    set_last_error("");
    return PIHBR_OK;
}

// ====== API: asignación desde la DLL (PATH) ======
extern "C" PIHREADER_API int PIH_DecryptBlobToAllocatedW(const wchar_t* blobPath,
    char** outUser,
    char** outPass) {
    if (!outUser || !outPass) {
        set_last_error("Invalid argument: outUser/outPass null.");
        return PIHBR_ERR_INVALID_ARG;
    }

    std::string user, pass;
    int st = DecryptBlobImpl(blobPath, user, pass);
    if (st != PIHBR_OK) return st;

    // Asignar con LocalAlloc para interoperabilidad
    HLOCAL u = LocalAlloc(LMEM_FIXED, user.size() + 1);
    HLOCAL p = LocalAlloc(LMEM_FIXED, pass.size() + 1);
    if (!u || !p) {
        if (u) LocalFree(u);
        if (p) LocalFree(p);
        set_last_error("LocalAlloc failed.");
        return PIHBR_ERR_IO;
    }

    std::memcpy(u, user.c_str(), user.size() + 1);
    std::memcpy(p, pass.c_str(), pass.size() + 1);

    *outUser = reinterpret_cast<char*>(u);
    *outPass = reinterpret_cast<char*>(p);
    set_last_error("");
    return PIHBR_OK;
}

extern "C" PIHREADER_API void PIH_Free(void* mem) {
    if (mem) LocalFree(mem);
}

// ====== APIs: blob embebido (RT_RCDATA) ======
// Variante buffers del llamador
extern "C" PIHREADER_API int PIH_DecryptBlobFromResourceW(
    char* outUser, size_t userCapacity,
    char* outPass, size_t passCapacity,
    size_t* outUserNeeded,
    size_t* outPassNeeded)
{
    UINT resourceId = IDR_DEFAULT_CREDS_BLOB;
    std::string user, pass;

    try {
        BlobView bv = GetBlobFromResource(resourceId);
        int st = DecryptBlobFromMemory(bv.data, bv.size, user, pass);
        if (st != PIHBR_OK)
            return st;
    }
    catch (const std::exception&) {
        // g_lastError ya contiene el mensaje
        return PIHBR_ERR_IO;
    }

    // Tamaños requeridos (incluyen '\0')
    const size_t needUser = user.size() + 1;
    const size_t needPass = pass.size() + 1;

    if (outUserNeeded) *outUserNeeded = needUser;
    if (outPassNeeded) *outPassNeeded = needPass;

    // Validar buffers
    if ((outUser && userCapacity < needUser) ||
        (outPass && passCapacity < needPass))
    {
        set_last_error("Insufficient buffer.");
        return PIHBR_ERR_INSUFFICIENT_BUFFER;
    }

    // Copiar si el llamador proporciona buffers
    if (outUser) {
        std::memcpy(outUser, user.c_str(), needUser);
    }
    if (outPass) {
        std::memcpy(outPass, pass.c_str(), needPass);
    }

    set_last_error("");
    return PIHBR_OK;
}