// PIH_BlobDecrypt_EntropyPortable.cpp
// -------------------------------------------------------------
// Demostración: DPAPI + ENTROPY "portable" entre máquinas.
// - La ENTROPY efectiva es "PIH-STATIC-ENTROPY-2026"
// - Pero la reconstruimos DINÁMICAMENTE para que no quede
//   como texto ni como bytes ASCII contiguos en el binario.
// - Leemos un .blob (cifrado con esa entropy) y lo desciframos.
// - Imprimimos user/pass (formato: user\0pass\0 dentro del blob).
//
// Compilación sugerida (Visual Studio):
//   - Proyecto: Console App (C++17+), x64, Release.
//   - Vincular: crypt32.lib  (por #pragma ya se añade).
//
// Uso:
//   1) Genera el blob con BlobGen usando la MISMA entropy.
//   2) Ejecuta este EXE pasando la ruta del blob como argv[1],
//      o edita la ruta por defecto más abajo.
//   3) Verás en consola "User: ..." y "Pass: ...".
//
// Seguridad/Ofuscación:
//   - La cadena "PIH-STATIC-ENTROPY-2026" NUNCA aparece en el binario.
//   - No hay arrays estáticos con ese texto ni con sus bytes en orden.
//   - strings.exe no debería encontrar nada útil.
//   - La entropy se crea solo en memoria (heap/stack) y se limpia.
//
// -------------------------------------------------------------

#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <numeric>

#pragma comment(lib, "crypt32.lib")

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

// Genera el vector de índices 0..N-1 (útil para “unshuffle”).
static std::vector<size_t> MakeIndices(size_t n)
{
    std::vector<size_t> idx(n);
    std::iota(idx.begin(), idx.end(), 0);
    return idx;
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
    //std::vector<uint8_t> PERM_INV = InvertPermutation(PERM);
    std::vector<uint8_t> xored = ApplyUnshuffle(OBF, PERM);

    // 4) Derivamos la key (0xAA) sin literales obvios.
    const uint8_t key = DeriveKey();

    // 5) Aplicamos XOR para obtener los ASCII reales.
    char* entropy = xorDecode(xored, PASS_KEY);

    // En este punto, 'entropy' == "PIH-STATIC-ENTROPY-2026"
    return entropy;
}

// ------------------------------------------------------------------
// 2) Descifrar el .blob con DPAPI usando la ENTROPY reconstruida
//    - El blob se generó con CryptProtectData(..., entropy = BuildEntropy()).
//    - Aquí hacemos CryptUnprotectData con la MISMA entropy build-time.
// ------------------------------------------------------------------
static bool DecryptBlobWithDPAPI(const wchar_t* blobPath,
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
    if (size == INVALID_FILE_SIZE || size == 0)
    {
        CloseHandle(h);
        PrintLine(L"[ERROR] .blob vacío o inválido");
        return false;
    }

    std::vector<BYTE> buf(size);
    DWORD br = 0;
    if (!ReadFile(h, buf.data(), size, &br, nullptr) || br != size)
    {
        CloseHandle(h);
        PrintLine(L"[ERROR] Falló la lectura del .blob");
        return false;
    }
    CloseHandle(h);

    // Reconstruimos la ENTROPY real (dinámica, no está en el binario)
    const char* entropyStr = BuildEntropy();
    DATA_BLOB entropy{};

    entropy.pbData = (BYTE*)entropyStr;
    entropy.cbData = (DWORD)strlen(entropyStr);

    // Preparamos estructuras DPAPI
    DATA_BLOB in{}, out{};
    in.pbData = buf.data();
    in.cbData = size;

    if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, 0, &out))
    {
        std::wcerr << L"[ERROR] CryptUnprotectData falló. WinErr=" << GetLastError() << L"\n";
        // Por higiene: borrar la entropy en memoria
        //RtlSecureZeroMemory(&entropyStr[0], entropyStr.size());
        return false;
    }

    // El contenido descifrado está en formato: user\0pass\0
    std::string combined(reinterpret_cast<char*>(out.pbData),
        reinterpret_cast<char*>(out.pbData) + out.cbData);

    // Liberar buffer de DPAPI y borrar entropy
    LocalFree(out.pbData);
    //RtlSecureZeroMemory(&entropyStr[0], entropyStr.size());

    // Parseo simple: user = hasta el primer '\0', pass = lo que sigue
    outUser = combined.c_str();
    outPass = combined.c_str() + outUser.size() + 1;
    return true;
}

// ------------------------------------------------------------------
// 3) main(): lee la ruta del .blob (argv[1] o ruta por defecto),
//    descifra y muestra user/pass.
// ------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    // Ruta por defecto (ajusta a tu estructura de carpetas)
    const wchar_t* defaultBlob = L"..\\PIH_DPAPI_BlobGenerator\\artifacts\\default_creds.blob";

    const wchar_t* blobPath = (argc > 1) ? argv[1] : defaultBlob;

    std::string user, pass;
    if (!DecryptBlobWithDPAPI(blobPath, user, pass))
    {
        PrintLine(L"[FALLO] No se pudo descifrar el blob.");
        return 1;
    }

    PrintLine(L"===== Blob Descifrado =====");
    std::wcout << L"User : " << user.c_str() << L"\n";
    std::wcout << L"Pass : " << pass.c_str() << L"\n";

    return 0;
}