#pragma once

// Export/import clásico para Windows DLL
#if defined(_WIN32) || defined(_WIN64)
#ifdef PIHREADER_EXPORTS
#define PIHREADER_API __declspec(dllexport)
#else
#define PIHREADER_API __declspec(dllimport)
#endif
#else
#define PIHREADER_API
#endif

#include <cstddef>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Códigos de estado para la API
    enum PIHBR_Status {
        PIHBR_OK = 0,
        PIHBR_ERR_INVALID_ARG = 1,
        PIHBR_ERR_IO = 2,
        PIHBR_ERR_INVALID_BLOB = 3,
        PIHBR_ERR_PBKDF2 = 4,
        PIHBR_ERR_EVP = 5,
        PIHBR_ERR_INSUFFICIENT_BUFFER = 6,
        PIHBR_ERR_EXCEPTION = 7
    };

    /**
     * @brief Descifra el blob (.blob) usando OpenSSL (PBKDF2-HMAC-SHA256 + AES-256-GCM)
     *        y devuelve user/pass en buffers del llamador (formato ASCII/UTF-8).
     *
     * Protocolo de buffers:
     *   - outUser/outPass pueden ser NULL para consultar tamaños requeridos.
     *   - outUserNeeded/outPassNeeded (si no son NULL) devuelven tamaños requeridos (incluyendo '\0').
     *   - Si la capacidad no alcanza, devuelve PIHBR_ERR_INSUFFICIENT_BUFFER y no escribe en los buffers.
     *
     * @param blobPath         Ruta del .blob (WCHAR).
     * @param outUser          Buffer destino para user (puede ser NULL).
     * @param userCapacity     Capacidad en bytes de outUser.
     * @param outPass          Buffer destino para pass (puede ser NULL).
     * @param passCapacity     Capacidad en bytes de outPass.
     * @param outUserNeeded    Devuelve tamaño requerido para user (incluye '\0') si no es NULL.
     * @param outPassNeeded    Devuelve tamaño requerido para pass (incluye '\0') si no es NULL.
     * @return PIHBR_Status
     */
    PIHREADER_API int PIH_DecryptBlobW(const wchar_t* blobPath,
        char* outUser, size_t userCapacity,
        char* outPass, size_t passCapacity,
        size_t* outUserNeeded,
        size_t* outPassNeeded);

    /**
     * @brief Variante que asigna memoria desde la DLL (LocalAlloc).
     *        El llamador debe liberar con PIH_Free().
     *
     * @param blobPath Ruta del .blob (WCHAR).
     * @param outUser* Recibe puntero a memoria con user (ASCII/UTF-8).
     * @param outPass* Recibe puntero a memoria con pass (ASCII/UTF-8).
     * @return PIHBR_Status
     */
    PIHREADER_API int PIH_DecryptBlobToAllocatedW(const wchar_t* blobPath,
        char** outUser,
        char** outPass);

    /**
     * @brief Libera memoria asignada por la DLL (para PIH_DecryptBlobToAllocatedW).
     */
    PIHREADER_API void PIH_Free(void* p);

    /**
     * @brief Devuelve el último mensaje de error (thread-local).
     *        Puntero válido hasta nueva llamada o fin del hilo.
     */
    PIHREADER_API const char* PIHBR_GetLastErrorMessage();

#ifdef __cplusplus
} // extern "C"
#endif