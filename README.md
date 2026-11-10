# netmail-sieve-assets

Biblioteca dinámica multiplataforma (C-ABI) de alto rendimiento para el análisis sintáctico (AST), validación y evaluación de scripts **Sieve (RFC 5228)** y respuestas de ausencia **Vacation (RFC 5230)**, empaquetada como asset reutilizable para [NetMail](https://github.com/your-username/netmail) y aplicaciones .NET 8/9.

---

## 🚀 Arquitectura y Características

- **Motor Rust de referencia:** Apoyado en `mailrs-sieve` (v2.0) y `mailrs-sieve-core` (v0.3) con licencia permisiva **MIT / Apache-2.0**.
- **Cero dependencias en tiempo de ejecución:** Expone una C-ABI plana (`extern "C"`) y serializa los ASTs y diagnósticos directamente en JSON para un desacoplamiento total.
- **Compilación multiplataforma automatizada:** GitHub Actions compila automáticamente binarios nativos optimizados para tamaño (`opt-level = "z"`, LTO, strip):
  - `netmail_sieve.dll` para **Windows x64**
  - `libnetmail_sieve.so` para **Linux x64**
  - `libnetmail_sieve.dylib` para **macOS Apple Silicon (arm64)** y **macOS Intel (x64)**

---

## 📦 Instrucciones para subir a GitHub y generar las librerías

### 1. Inicializar el repositorio remoto

Desde una terminal en esta carpeta (`c:\Users\Miguel\Documents\projects\netmail_sieve_assets`):

```bash
git remote add origin https://github.com/devMls/netmail-sieve-assets.git
git branch -M main
git push -u origin main
```

### 2. Compilación automática en GitHub Actions

Una vez hecho el `push`:
1. Ve a la pestaña **Actions** en tu repositorio de GitHub.
2. Verás ejecutándose el workflow **Build Sieve Native Binaries** en paralelo sobre Windows, Ubuntu y macOS.
3. Al finalizar (~2 minutos), descarga el artefacto **`netmail_sieve_runtimes`** (o desde la sección Releases si creas un tag `v0.1.0`).

### 3. Incorporar en NetMail

Descomprime el archivo descargado en la carpeta de NetMail:
`c:\Users\Miguel\Documents\projects\netmail\src\NetMail.Protocol.Imap\`

La estructura resultante será exactamente la esperada por el runtime de .NET:

```text
NetMail.Protocol.Imap/
└── runtimes/
    ├── win-x64/native/netmail_sieve.dll
    ├── linux-x64/native/libnetmail_sieve.so
    ├── osx-arm64/native/libnetmail_sieve.dylib
    └── osx-x64/native/libnetmail_sieve.dylib
```

---

## 💻 Consumo desde C# (.NET 8 / 9)

En `NetMail.Protocol.Imap`, la llamada se realiza mediante `[LibraryImport]` con cero sobrecarga:

```csharp
using System.Runtime.InteropServices;

namespace NetMail.Protocol.Imap.Sieve;

internal static partial class SieveNative
{
    private const string LibraryName = "netmail_sieve";

    [LibraryImport(LibraryName, EntryPoint = "sieve_validate", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int Validate(string script);

    [LibraryImport(LibraryName, EntryPoint = "sieve_validate_detail_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial IntPtr ValidateDetailJson(string script);

    [LibraryImport(LibraryName, EntryPoint = "sieve_parse_ast_json", StringMarshalling = StringMarshalling.Utf8)]
    public static partial IntPtr ParseAstJson(string script);

    [LibraryImport(LibraryName, EntryPoint = "sieve_free_string")]
    public static partial void FreeString(IntPtr ptr);

    public static string? ParseAst(string script)
    {
        var ptr = ParseAstJson(script);
        if (ptr == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(ptr); }
        finally { FreeString(ptr); }
    }
}
```

---

## 📄 Licencia

Este proyecto está bajo licencia dual **MIT** y **Apache-2.0**.
