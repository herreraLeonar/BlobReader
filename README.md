# PIH Blob Reader / Generator
**PBKDF2 + AES-256-GCM secure blob for default credentials (Windows + OpenSSL)**  

Este repositorio contiene dos componentes:

   Herramienta que genera un archivo `.blob` seguro, que contiene usuario/contraseña protegidos con:
   - PBKDF2-HMAC-SHA256 (200k iteraciones)
   - AES-256-GCM (IV 12B + TAG 16B)
   - Cabecera portable: `[MAGIC][VER][SALT][NONCE][TAG][CIPHERTEXT]`

   Biblioteca que permite **leer y descifrar** ese `.blob` tanto desde:
   - un **recurso RCDATA embebido** dentro del ejecutable/DLL.

El objetivo es permitir aplicaciones PIH (Printer Interface Host) a recuperar credenciales de “default admin” de forma segura, sin dejar secretos duros en el binario.

---

## 📦 Requisitos

- **Windows**  
- **Visual Studio 2019/2022**  
- **OpenSSL 1.1.1+ / 3.x** (Se usa libcrypto para PBKDF2 y AES-GCM)

---

## 🔧 Instalación de OpenSSL (Windows)

### Opción 1 — Usando Winget (sencillo)

```powershell
winget install ShiningLight.OpenSSL

Usando vcpkg
vcpkg install openssl:x64-windows

Si los includes fallan, normalmente aparece:
fatal error C1083: Cannot open include file: 'openssl/evp.h'

cl /EHsc ^
  /I "C:\Program Files\OpenSSL-Win64\include" ^
  myfile.cpp ^
  /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib" libcrypto.lib

Verifica Instalacion
openssl version
where libcrypto-*.dll
