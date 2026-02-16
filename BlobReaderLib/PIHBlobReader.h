#pragma once

#include <cstddef>   // size_t
#include <cstdint>   // uint32_t, etc.

#ifdef _WIN32
#include <windows.h>  // UINT
#endif

 // ================================================
 // Export/Import macro
 // ================================================
#ifdef _WIN32
#ifdef PIHREADER_EXPORTS
#define PIHREADER_API __declspec(dllexport)
#else
#define PIHREADER_API __declspec(dllimport)
#endif
#else
#define PIHREADER_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

    // ================================================
    // Códigos de estado
    // ================================================
    /**
     * @name Códigos de retorno
     * @brief 0 indica éxito; valores negativos indican error.
     * @{
     */
    enum {
        PIHBR_OK = 0,
        PIHBR_ERR_INVALID_ARG = -1,
        PIHBR_ERR_IO = -2,
        PIHBR_ERR_INVALID_BLOB = -3,
        PIHBR_ERR_PBKDF2 = -4,
        PIHBR_ERR_EVP = -5,
        PIHBR_ERR_INSUFFICIENT_BUFFER = -6,
        PIHBR_ERR_EXCEPTION = -7
    };
    /** @} */

    // ================================================
    // Utilidad: último error (thread-local)
    // ================================================
    /**
     * @brief Devuelve el último mensaje de error (thread-local), en UTF-8.
     * @return const char* puntero a buffer interno; no liberar.
     *
     * @note El buffer se invalida en la siguiente llamada a una API de este módulo.
     */
    PIHREADER_API const char* PIHBR_GetLastErrorMessage(void);

    // ================================================
    // APIs basadas en PATH (fichero .blob en disco)
    // ================================================
    /**
     * @brief Descifra un blob desde ruta de archivo y copia en buffers del llamador.
     *
     * @param[in]  blobPath       Ruta (UTF-16) al fichero .blob.
     * @param[out] outUser        Buffer destino para user (UTF-8, con '\0'). Puede ser NULL.
     * @param[in]  userCapacity   Capacidad en bytes de outUser (incluye '\0'). Ignorado si outUser==NULL.
     * @param[out] outPass        Buffer destino para pass (UTF-8, con '\0'). Puede ser NULL.
     * @param[in]  passCapacity   Capacidad en bytes de outPass (incluye '\0'). Ignorado si outPass==NULL.
     * @param[out] outUserNeeded  (Opc.) tamaño requerido (incluye '\0') para user.
     * @param[out] outPassNeeded  (Opc.) tamaño requerido (incluye '\0') para pass.
     *
     * @return PIHBR_OK en éxito; error negativo en fallo.
     *
     * @note Patrón habitual:
     *   1) Llamar con outUser/outPass=NULL para obtener tamaños (outUserNeeded/outPassNeeded).
     *   2) Reservar buffers y llamar de nuevo para copiar datos.
     */
    PIHREADER_API int PIH_DecryptBlobW(
        const wchar_t* blobPath,
        char* outUser, size_t userCapacity,
        char* outPass, size_t passCapacity,
        size_t* outUserNeeded,
        size_t* outPassNeeded
    );

    /**
     * @brief Descifra un blob desde ruta y devuelve cadenas asignadas por la DLL.
     *
     * @param[in]  blobPath  Ruta (UTF-16) al fichero .blob.
     * @param[out] outUser   Recibe puntero a memoria asignada con LocalAlloc (LMEM_FIXED).
     * @param[out] outPass   Recibe puntero a memoria asignada con LocalAlloc (LMEM_FIXED).
     *
     * @return PIHBR_OK en éxito; error negativo en fallo.
     *
     * @warning Liberar la memoria con @ref PIH_Free.
     */
    PIHREADER_API int PIH_DecryptBlobToAllocatedW(
        const wchar_t* blobPath,
        char** outUser,
        char** outPass
    );

    // ================================================
    // APIs basadas en RCDATA (recurso embebido)
    // ================================================
    /**
     * @brief Descifra el blob embebido por defecto (IDR_DEFAULT_CREDS_BLOB) y copia en buffers del llamador.
     *
     * @param[out] outUser        Buffer destino para user (UTF-8, con '\0'). Puede ser NULL.
     * @param[in]  userCapacity   Capacidad en bytes de outUser (incluye '\0'). Ignorado si outUser==NULL.
     * @param[out] outPass        Buffer destino para pass (UTF-8, con '\0'). Puede ser NULL.
     * @param[in]  passCapacity   Capacidad en bytes de outPass (incluye '\0'). Ignorado si outPass==NULL.
     * @param[out] outUserNeeded  (Opc.) tamaño requerido (incluye '\0') para user.
     * @param[out] outPassNeeded  (Opc.) tamaño requerido (incluye '\0') para pass.
     *
     * @return PIHBR_OK en éxito; error negativo en fallo.
     *
     * @note El ID del recurso por defecto debe estar definido en `resource.h` como `IDR_DEFAULT_CREDS_BLOB`.
     */
    PIHREADER_API int PIH_DecryptBlobFromResourceW(
        char* outUser, size_t userCapacity,
        char* outPass, size_t passCapacity,
        size_t* outUserNeeded,
        size_t* outPassNeeded
    );

    /**
     * @brief Descifra un blob embebido (por ID) y devuelve cadenas asignadas por la DLL.
     *
     * @param[in]  resourceId  Identificador del recurso RCDATA (p. ej., IDR_DEFAULT_CREDS_BLOB).
     * @param[out] outUser     Recibe puntero a memoria asignada con LocalAlloc (LMEM_FIXED).
     * @param[out] outPass     Recibe puntero a memoria asignada con LocalAlloc (LMEM_FIXED).
     *
     * @return PIHBR_OK en éxito; error negativo en fallo.
     *
     * @warning Liberar la memoria con @ref PIH_Free.
     */
    PIHREADER_API int PIH_DecryptBlobFromResourceToAllocatedW(
        unsigned int resourceId,
        char** outUser,
        char** outPass
    );

    // ================================================
    // Liberación de memoria devuelta por las APIs *ToAllocated*
    // ================================================
    /**
     * @brief Libera memoria asignada por esta DLL (LocalAlloc).
     * @param[in] mem  Puntero a liberar; acepta NULL (no-op).
     */
    PIHREADER_API void PIH_Free(void* mem);

#ifdef __cplusplus
} // extern "C"
#endif