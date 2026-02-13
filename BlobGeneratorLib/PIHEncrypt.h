#pragma once

// Export/import clásico para Windows DLL
#if defined(_WIN32) || defined(_WIN64)
#ifdef MYENC_EXPORTS
#define MYENC_API __declspec(dllexport)
#else
#define MYENC_API __declspec(dllimport)
#endif
#else
#define MYENC_API
#endif

#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

    // Códigos de estado
    enum PIH_Status {
        PIH_OK = 0,
        PIH_ERR_INVALID_ARG = 1,
        PIH_ERR_RAND = 2,
        PIH_ERR_PBKDF2 = 3,
        PIH_ERR_EVP = 4,
        PIH_ERR_IO = 5,
        PIH_ERR_EXCEPTION = 6
    };

    /**
     * @brief Cifra user/pass con AES-256-GCM derivando la clave con PBKDF2-HMAC-SHA256,
     *        y escribe un blob portable: [MAGIC][VER][SALT][NONCE][TAG][CIPHERTEXT].
     *
     * @param user    Nombre de usuario (ASCII/UTF-8). Requerido.
     * @param pass    Password. Requerido.
     * @param pwd     Password del archivo (para PBKDF2). Requerido.
     * @param outPath Ruta de salida del blob (ej: "artifacts/default_creds.blob"). Requerido.
     * @return PIH_Status (0 = OK)
     */
    MYENC_API int PIH_EncryptCredentialsToFile(const char* user,
        const char* pass,
        const char* pwd,
        const char* outPath);

    /**
     * @brief Conveniencia: usa los valores "por defecto" de tu ejemplo y
     *        escribe en "artifacts/default_creds.blob".
     *
     * user="StringTestAdmin", pass="StringTestPassword",
     * pwd="PIH-STATIC-ENTROPY-2026".
     */
    MYENC_API int PIH_GenerateDefaultCredsBlob();

    /**
     * @brief Devuelve el mensaje de error de la última llamada (thread-local).
     *        Puntero válido hasta que el hilo termine o se llame de nuevo a la API.
     */
    MYENC_API const char* PIH_GetLastErrorMessage();

#ifdef __cplusplus
} // extern "C"
#endif