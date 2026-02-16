#include <openssl/evp.h>
#include <openssl/rand.h>
#include <windows.h>
#include <winuser.h>

#include <wincrypt.h>
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <numeric>
#include "resource.h"

// --- Loader del recurso embebido (RCDATA) ---
extern "C" IMAGE_DOS_HEADER __ImageBase; // Para obtener HMODULE del módulo actual

struct BlobView {
    const unsigned char* data;
    size_t size;
};

// Helpers de consola
static void PrintLine(const wchar_t* s)
{
    DWORD written = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE)
    {
        WriteConsoleW(h, s, (DWORD)wcslen(s), &written, nullptr);
        WriteConsoleW(h, L"\r\n", 2, &written, nullptr);
    }
}

// - data: bytes de entrada ya barajados/obfuscados.
// - key : clave XOR (0xAA) usada para recuperar los ASCII reales.
// Retorna: puntero a un buffer asignado con 'new' terminado en '\0'.
// Nota:
//   - Se añade un byte extra para el terminador NUL y facilitar su uso como C-string..
// Ejemplo: dato (0x87): 1 0 0 0 0 1 1 1
// clave(0xAA) : 1 0 1 0 1 0 1 0
// Operación XOR :
// 1 y 1 son iguales \rightarrow 0
// 0 y 0 son iguales \rightarrow 0
// 0 y 1 son distintos \rightarrow 1
// 0 y 0 son iguales \rightarrow 0
// Rresultado : 0 0 1 0 1 1 0 1 = 0x2D (ASCII '-')
char* xorDecode(const std::vector<uint8_t>& data, uint8_t key)
{
    char* out = new char[data.size() + 1];

    for (size_t i = 0; i < data.size(); i++)
        out[i] = static_cast<char>(data[i] ^ key);

    out[data.size()] = '\0';
    return out;
}

// ------------------------------------------------------------------
// 1) Reconstrucción DINÁMICA de la ENTROPY
//
// obtener EXACTAMENTE "PIH-STATIC-ENTROPY-2026"
// sin que esa secuencia aparezca como literal en el binario.
// Para ello:
//   a) Partimos de bytes NO-ASCII (ya barajados).
//   b) Aplicamos una "unshuffling" (desbarajado) determinista.
//   c) Aplicamos un XOR con una clave derivada en tiempo de ejecución.
// El resultado final es la entropy real, en memoria, lista para OpenSSL.
// ------------------------------------------------------------------

// Derivamos una clave XOR (valor final = 0xAA) sin usar el literal tal cual.
// no es ASCII y no aparece como string imprimible.
static inline uint8_t DeriveKey()
{
    // Serie de operaciones sin patrón evidente para llegar a 0xAA.
    // 0xC3 ^ 0x69 = 0xAA
    uint8_t k = 0;
    k ^= 0xC3;
    k ^= 0x69;
    // Pequeñas “perturbaciones” inútiles (no afectan a 0xAA):
    k = (uint8_t)((k ^ 0x00) + 0x00 - 0x00);
    return k; // 0xAA
}

// Esta función “desbaraja” (unshuffle) un vector dejándolo en el
// orden original, siguiendo un vector de posiciones "perm" que
// indica en qué orden quedaron los elementos barajados.
//
// Si perm[i] = j significa que el elemento original de índice j
// ahora está en posición i (orden barajado).
// Para revertir, colocamos shuffled[i] -> original[perm[i]].
//
// Nota: aquí usamos “perm” fija (no ASCII) sólo de índices numéricos;
// no representa ningún texto, por lo que strings.exe no imprime nada útil.
static std::vector<uint8_t> ApplyUnshuffle(const std::vector<uint8_t>& shuffled,
    const std::vector<uint8_t>& perm)
{
    const size_t n = shuffled.size();
    std::vector<uint8_t> original(n, 0);
    for (size_t i = 0; i < n; ++i)
    {
        const size_t origPos = perm[i];
        original[origPos] = shuffled[i];
    }
    return original;
}

// Construye la ENTROPY real como string, sin dejar rastro ASCII en el binario.
// La longitud del texto "PIH-STATIC-ENTROPY-2026" es 23 bytes.
char* BuildEntropy()
{
    // 1) Bytes “obfuscados” (no ASCII, barajados). NO es la entropy real.
    //    Estos bytes son: (ascii ^ 0xAA) y además barajados.
    //    No forman texto legible.
    //    Longitud = 23.
    const std::vector<uint8_t> OBF{
        0x87, 0xFE, 0xE3, 0xFE, 0xFA, 0xF8, 0xE9, 0xE2, 0xE4, 0xF9, 0xEB, 0xE3,
        0x87, 0xFE, 0xEF, 0xE5, 0xFA, 0x98, 0x87, 0x9A, 0xF3, 0x9C, 0x98
    };

    // 2) Permutación que indica la posición original de cada byte.
    //    perm[i] = posición original del byte que ahora está en i.
    const std::vector<uint8_t> PERM{
        3, 7, 1, 5, 0, 14, 9, 2, 12, 4, 6, 8, 10, 13, 11, 15, 16, 19, 18, 20, 17, 22, 21
    };

    static const uint8_t PASS_KEY = DeriveKey(); //0xAA

    // 3) Revertimos el barajado para recuperar (ascii ^ key) en orden correcto.
    std::vector<uint8_t> xored = ApplyUnshuffle(OBF, PERM);

    // 4) Aplicamos XOR para obtener los ASCII reales.
    char* entropy = xorDecode(xored, PASS_KEY);

    // En este punto, 'entropy' == "PIH-STATIC-ENTROPY-2026"
    return entropy;
}

// 2) Descifrar el el blob embebido con OpenSSL usando la ENTROPY reconstruida
static BlobView GetDefaultCredsBlob()
{
    // HMODULE del módulo actual (EXE o DLL donde está este código)
    HMODULE hMod = (HMODULE)&__ImageBase;

    // Busca el recurso por ID y tipo RCDATA (binario crudo)
    HRSRC hRes = FindResourceW(hMod, MAKEINTRESOURCE(IDR_DEFAULT_CREDS_BLOB), RT_RCDATA);

    if (!hRes) {
        throw std::runtime_error("FindResource(IDR_DEFAULT_CREDS_BLOB, RT_RCDATA) failed");
    }

    // Carga el recurso en memoria
    HGLOBAL hData = LoadResource(hMod, hRes);
    if (!hData) {
        throw std::runtime_error("LoadResource failed");
    }

    // Tamaño del recurso
    DWORD size = SizeofResource(hMod, hRes);
    if (size == 0) {
        throw std::runtime_error("SizeofResource returned 0");
    }

    // Puntero a los datos (memoria de solo lectura administrada por el sistema)
    const void* ptr = LockResource(hData);
    if (!ptr) {
        throw std::runtime_error("LockResource failed");
    }

    return { static_cast<const unsigned char*>(ptr), static_cast<size_t>(size) };
}

static bool DecryptBlobWithOpenSSL_FromMemory(
    const unsigned char* data, size_t size,
    std::string& outUser, std::string& outPass)
{
    // Constantes del formato
    const uint32_t MAGIC_EXPECTED = 0x50494842; // 'PIHB'
    const uint16_t VER_EXPECTED = 0x0001;
    const size_t SALT_LEN = 16, NONCE_LEN = 12, TAG_LEN = 16;
    const size_t KEY_LEN = 32; // AES-256
    const int PBKDF2_ITERATIONS = 200000;

    if (size < sizeof(uint32_t) + sizeof(uint16_t) + SALT_LEN + NONCE_LEN + TAG_LEN) {
        PrintLine(L"[ERROR] Blob demasiado corto para cabecera esperada");
        return false;
    }

    size_t offset = 0;
    uint32_t magic = 0;
    std::memcpy(&magic, data + offset, sizeof(magic)); offset += sizeof(magic);

    uint16_t ver = 0;
    std::memcpy(&ver, data + offset, sizeof(ver));     offset += sizeof(ver);

    if (magic != MAGIC_EXPECTED || ver != VER_EXPECTED) {
        PrintLine(L"[ERROR] Encabezado de blob no reconocido (MAGIC/VER)");
        return false;
    }

    const unsigned char* salt = data + offset; offset += SALT_LEN;
    const unsigned char* nonce = data + offset; offset += NONCE_LEN;
    const unsigned char* tag = data + offset; offset += TAG_LEN;

    if (offset > size) {
        PrintLine(L"[ERROR] Offsets inválidos");
        return false;
    }

    const unsigned char* ciphertext = data + offset;
    const size_t ciphertext_len = size - offset;
    if (ciphertext_len == 0) {
        PrintLine(L"[ERROR] CIPHERTEXT vacío");
        return false;
    }

    // Passphrase ofuscada en tiempo de ejecución
    std::unique_ptr<char[]> passphrase(BuildEntropy());
    wprintf(L"[INFO] Entropy reconstruida: %hs \n", passphrase.get());
    const int pwdLen = static_cast<int>(std::strlen(passphrase.get()));

    // PBKDF2-HMAC-SHA256 -> key
    unsigned char key[KEY_LEN];
    if (PKCS5_PBKDF2_HMAC(passphrase.get(), pwdLen, salt, (int)SALT_LEN,
        PBKDF2_ITERATIONS, EVP_sha256(), (int)KEY_LEN, key) != 1) {
        PrintLine(L"[ERROR] PBKDF2 falló");
        return false;
    }

    // AES-256-GCM
    std::vector<unsigned char> plaintext(ciphertext_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        PrintLine(L"[ERROR] EVP_CIPHER_CTX_new falló");
        return false;
    }

    int ok = 1, outLen = 0, total = 0, finalLen = 0;
    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)NONCE_LEN, nullptr);
    ok &= EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce);
    ok &= EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext, (int)ciphertext_len);
    total = outLen;
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)TAG_LEN, (void*)tag);
    ok &= EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &finalLen);
    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        PrintLine(L"[ERROR] AES-GCM decryption falló (TAG inválido o datos corruptos)");
        return false;
    }

    total += finalLen;
    plaintext.resize(total);

    // Formato: user\0pass\0
    std::string combined(reinterpret_cast<const char*>(plaintext.data()),
        reinterpret_cast<const char*>(plaintext.data()) + plaintext.size());

    outUser = combined.c_str();
    const size_t userLen = outUser.size();
    if (userLen + 1 > combined.size()) {
        PrintLine(L"[ERROR] Formato de datos descifrados inválido");
        return false;
    }
    outPass = combined.c_str() + userLen + 1;
    return true;
}
// --- Fin de la funciones Blob Embebido de descifrado desde memoria ---

// 3) main(): descifra y muestra user/pass.
int wmain(int argc, wchar_t* argv[])
{
    std::string user, pass;

    if (argc > 0) {
        // Sin ruta -> usa el recurso embebido
        try {
            BlobView bv = GetDefaultCredsBlob();
            if (!DecryptBlobWithOpenSSL_FromMemory(bv.data, bv.size, user, pass)) {
                PrintLine(L"[FALLO] No se pudo descifrar el blob embebido.");
                return 1;
            }
        }
        catch (const std::exception& ex) {
            std::wstring msg = L"[ERROR] Exception: ";
            msg += std::wstring(ex.what(), ex.what() + std::strlen(ex.what()));
            PrintLine(msg.c_str());
            return 1;
        }
    }

    PrintLine(L"===== Blob Descifrado =====");
    std::wcout << L"User : " << user.c_str() << L"\n";
    std::wcout << L"Pass : " << pass.c_str() << L"\n";
    return 0;
}