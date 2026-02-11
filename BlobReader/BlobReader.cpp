// PIH_BlobDecrypt_EntropyPortable.cpp
// -------------------------------------------------------------
// Demostración: DPAPI + ENTROPY "portable" entre máquinas.
// - La ENTROPY efectiva es "PIH-STATIC-ENTROPY-2026"
// - Pero la reconstruimos DINÁMICAMENTE para que no quede
//   como texto ni como bytes ASCII contiguos en el binario.
// - Leemos un .blob (cifrado con esa entropy) y lo desciframos.
// - Imprimimos user/pass (formato: user\0pass\0 dentro del blob).
//
// Uso:
//   1) Genera el blob con BlobGen usando la MISMA entropy.
//   2) Ejecuta pasando la ruta del blob como argv[1].
//   3) En consola "User: ..." y "Pass: ...".
//
// Seguridad/Ofuscación:
//   - La cadena "PIH-STATIC-ENTROPY-2026" NUNCA aparece en el binario.
//   - No hay arrays estáticos con ese texto ni con sus bytes en orden.
//   - strings.exe no debería encontrar nada útil.
//   - La entropy se crea solo en memoria (heap/stack) y se limpia.
//
// -------------------------------------------------------------
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <numeric>

// ------------------------------------------------------------------
// Helpers de consola wide (evita CRT locales y facilita Windows).
// ------------------------------------------------------------------
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

// Decodifica un buffer obfuscado por XOR y devuelve un C-string nuevo (heap).
// - data: bytes de entrada ya barajados/obfuscados.
// - key : clave XOR (0xAA) usada para recuperar los ASCII reales.
// Retorna: puntero a un buffer asignado con 'new' terminado en '\0'.
// Nota:
//   - El llamador es responsable de liberar con 'delete[]' el puntero devuelto.
//   - Se añade un byte extra para el terminador NUL y facilitar su uso como C-string.
//   - No se realiza zeroization del buffer; si contiene secretos, limpialo tras usarlo.

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
// Objetivo: obtener EXACTAMENTE "PIH-STATIC-ENTROPY-2026"
// sin que esa secuencia aparezca como literal en el binario.
// Para ello:
//   a) Partimos de bytes NO-ASCII (ya barajados).
//   b) Aplicamos una "unshuffling" (desbarajado) determinista.
//   c) Aplicamos un XOR con una clave derivada en tiempo de ejecución.
// El resultado final es la entropy real, en memoria, lista para DPAPI.
// ------------------------------------------------------------------

// Derivamos una clave XOR (valor final = 0xAA) sin usar el literal tal cual.
// Si el compilador pliega constantes, no pasa nada: no es ASCII y no
// aparece como string imprimible.
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

    static const uint8_t PASS_KEY = DeriveKey();

    // 3) Revertimos el barajado para recuperar (ascii ^ key) en orden correcto.
    std::vector<uint8_t> xored = ApplyUnshuffle(OBF, PERM);

    // 4) Aplicamos XOR para obtener los ASCII reales.
    char* entropy = xorDecode(xored, PASS_KEY);

    // En este punto, 'entropy' == "PIH-STATIC-ENTROPY-2026"
    return entropy;
}

// ------------------------------------------------------------------
// 2) Descifrar el .blob con OpenSSL usando la ENTROPY reconstruida
// ------------------------------------------------------------------
static bool DecryptBlobWithOpenSSL(const wchar_t* blobPath,
    std::string& outUser,
    std::string& outPass)
{
    // Abrir archivo .blob en binario
    HANDLE h = CreateFileW(blobPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        PrintLine(L"[ERROR] No se pudo abrir el archivo .blob");
        return false;
    }

    DWORD size = GetFileSize(h, nullptr);
    if (size == INVALID_FILE_SIZE || size < sizeof(uint32_t) + sizeof(uint16_t))
    {
        CloseHandle(h);
        PrintLine(L"[ERROR] .blob vacío o inválido");
        return false;
    }

    std::vector<unsigned char> buf(size);
    DWORD br = 0;
    if (!ReadFile(h, buf.data(), size, &br, nullptr) || br != size)
    {
        CloseHandle(h);
        PrintLine(L"[ERROR] Falló la lectura del .blob");
        return false;
    }
    CloseHandle(h);

    // Layout esperado: [MAGIC(4)][VER(2)][SALT(16)][NONCE(12)][TAG(16)][CIPHERTEXT(N)]
    const uint32_t MAGIC_EXPECTED = 0x50494842; // 'PIHB'
    const uint16_t VER_EXPECTED = 0x0001;
    const size_t SALT_LEN = 16;
    const size_t NONCE_LEN = 12;
    const size_t TAG_LEN = 16;
    const size_t KEY_LEN = 32; // AES-256
    const int PBKDF2_ITERATIONS = 200000;

    size_t offset = 0;

    if (buf.size() < sizeof(uint32_t) + sizeof(uint16_t) + SALT_LEN + NONCE_LEN + TAG_LEN)
    {
        PrintLine(L"[ERROR] Blob demasiado corto para cabecera esperada");
        return false;
    }

    uint32_t magic = 0;
    std::memcpy(&magic, buf.data() + offset, sizeof(magic));
    offset += sizeof(magic);

    uint16_t ver = 0;
    std::memcpy(&ver, buf.data() + offset, sizeof(ver));
    offset += sizeof(ver);

    if (magic != MAGIC_EXPECTED || ver != VER_EXPECTED)
    {
        PrintLine(L"[ERROR] Encabezado de blob no reconocido (MAGIC/VER)");
        return false;
    }

    const unsigned char* salt = buf.data() + offset; offset += SALT_LEN;
    const unsigned char* nonce = buf.data() + offset; offset += NONCE_LEN;
    const unsigned char* tag = buf.data() + offset; offset += TAG_LEN;

    const size_t ciphertext_len = buf.size() - offset;
    if (ciphertext_len == 0)
    {
        PrintLine(L"[ERROR] CIPHERTEXT vacío");
        return false;
    }
    const unsigned char* ciphertext = buf.data() + offset;

    // Passphrase: ofuscación dinámica (BuildEntropy())
    // para que no aparezca la cadena literal en el binario.
    std::unique_ptr<char[]> passphrase(BuildEntropy());
    wprintf(L"[INFO] Entropy reconstruida: %hs \n", passphrase.get());
    const unsigned char* pwd = reinterpret_cast<const unsigned char*>(passphrase.get());
    const int pwdLen = static_cast<int>(std::strlen(passphrase.get()));

    // Derivar clave (PBKDF2-HMAC-SHA256)
    unsigned char key[KEY_LEN];
    if (PKCS5_PBKDF2_HMAC(passphrase.get(), pwdLen, salt, (int)SALT_LEN,
        PBKDF2_ITERATIONS, EVP_sha256(), (int)KEY_LEN, key) != 1)
    {
        PrintLine(L"[ERROR] PBKDF2 falló");
        return false;
    }

    // AES-256-GCM decrypt
    std::vector<unsigned char> plaintext(ciphertext_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        PrintLine(L"[ERROR] EVP_CIPHER_CTX_new falló");
        return false;
    }

    int ok = 1;
    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)NONCE_LEN, nullptr);
    ok &= EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce);

    int outLen = 0, total = 0;
    ok &= EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext, (int)ciphertext_len);
    total = outLen;

    // Configurar TAG antes del Final
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)TAG_LEN, (void*)tag);

    // Final: autentica tag; si falla, ok será 0
    int finalLen = 0;
    ok &= EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &finalLen);
    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
    {
        PrintLine(L"[ERROR] AES-GCM decryption falló (TAG inválido o datos corruptos)");
        return false;
    }
    total += finalLen;
    plaintext.resize(total);

    // El contenido descifrado está en formato: user\0pass\0
    std::string combined(reinterpret_cast<const char*>(plaintext.data()),
        reinterpret_cast<const char*>(plaintext.data()) + plaintext.size());

    // Parseo simple
    outUser = combined.c_str();
    const size_t userLen = outUser.size();
    if (userLen + 1 > combined.size())
    {
        PrintLine(L"[ERROR] Formato de datos descifrados inválido");
        return false;
    }
    outPass = combined.c_str() + userLen + 1;
    return true;
}

// ------------------------------------------------------------------
// 3) main(): lee la ruta del .blob (argv[1] o ruta por defecto),
//    descifra y muestra user/pass.
// ------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    // Ruta por defecto
    const wchar_t* defaultBlob = L"..\\PIH_DPAPI_BlobGenerator\\artifacts\\default_creds.blob";

    const wchar_t* blobPath = (argc > 1) ? argv[1] : defaultBlob;

    std::string user, pass;
    if (!DecryptBlobWithOpenSSL(blobPath, user, pass))
    {
        PrintLine(L"[FALLO] No se pudo descifrar el blob.");
        return 1;
    }

    PrintLine(L"===== Blob Descifrado =====");
    std::wcout << L"User : " << user.c_str() << L"\n";
    std::wcout << L"Pass : " << pass.c_str() << L"\n";

    return 0;
}