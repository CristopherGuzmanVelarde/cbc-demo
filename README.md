# 🔐 Demo de Cifrado AES en Java

Una demostración interactiva de cifrado simétrico usando el módulo **Cipher** de Java con el algoritmo **AES** (Advanced Encryption Standard).

## 📋 Características

- ✅ **Sin librerías externas**: Solo APIs nativas de Java
- ✅ **Cifrado simétrico**: Utiliza la misma clave para cifrar y descifrar
- ✅ **Algoritmo AES**: Estándar de cifrado avanzado de 256 bits
- ✅ **Modo CBC**: Cipher Block Chaining con padding PKCS5
- ✅ **Vector de Inicialización (IV)**: Generación aleatoria para mayor seguridad
- ✅ **Codificación Base64**: Para visualización segura de datos binarios

## 🛠️ Tecnologías Utilizadas

| Componente | Descripción |
|------------|-------------|
| `javax.crypto.Cipher` | Módulo principal de cifrado de Java |
| `javax.crypto.KeyGenerator` | Generación de claves criptográficas |
| `javax.crypto.SecretKey` | Manejo de claves simétricas |
| `java.security.SecureRandom` | Generación de números aleatorios seguros |
| `java.util.Base64` | Codificación/decodificación Base64 |

## 🔧 Requisitos del Sistema

- **Java 8** o superior
- **JDK** instalado con soporte para criptografía
- Sistema operativo: Windows, Linux, macOS

## 🚀 Compilación y Ejecución

### Paso 1: Compilar
```bash
javac CifradoAESDemo.java
```

### Paso 2: Ejecutar
```bash
java CifradoAESDemo
```

## 📱 Interfaz de Usuario

Al ejecutar la aplicación, verás un menú interactivo:

```
=================================
   DEMO DE CIFRADO AES - JAVA   
=================================

✓ Clave AES generada automáticamente
  Algoritmo: AES
  Tamaño: 256 bits
  Clave (Base64): [clave-generada-automáticamente]

┌─────────────────────────────┐
│         MENÚ PRINCIPAL      │
├─────────────────────────────┤
│ 1. Cifrar texto             │
│ 2. Descifrar texto          │
│ 3. Regenerar clave AES      │
│ 4. Salir                    │
└─────────────────────────────┘
```

## 🔍 Funcionalidades Detalladas

### 1. 🔒 Cifrar Texto

**¿Qué hace?**
- Toma un texto plano ingresado por el usuario
- Genera un IV (Vector de Inicialización) aleatorio
- Cifra el texto usando AES-256-CBC
- Combina IV + datos cifrados
- Retorna el resultado codificado en Base64

**Proceso técnico:**
```java
// 1. Crear instancia del cipher
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

// 2. Generar IV aleatorio (16 bytes)
byte[] iv = new byte[16];
new SecureRandom().nextBytes(iv);

// 3. Inicializar en modo cifrado
cipher.init(Cipher.ENCRYPT_MODE, claveSecreta, new IvParameterSpec(iv));

// 4. Cifrar el texto
byte[] textoCifrado = cipher.doFinal(textoPlano.getBytes("UTF-8"));

// 5. Combinar IV + datos cifrados y codificar en Base64
```

### 2. 🔓 Descifrar Texto

**¿Qué hace?**
- Toma un texto cifrado en Base64
- Extrae el IV de los primeros 16 bytes
- Extrae los datos cifrados del resto
- Descifra usando la misma clave AES
- Retorna el texto plano original

**Proceso técnico:**
```java
// 1. Decodificar de Base64
byte[] datosCifrados = Base64.getDecoder().decode(textoCifradoBase64);

// 2. Extraer IV (primeros 16 bytes)
byte[] iv = Arrays.copyOfRange(datosCifrados, 0, 16);

// 3. Extraer datos cifrados (resto)
byte[] textoCifrado = Arrays.copyOfRange(datosCifrados, 16, datosCifrados.length);

// 4. Inicializar cipher en modo descifrado
cipher.init(Cipher.DECRYPT_MODE, claveSecreta, new IvParameterSpec(iv));

// 5. Descifrar
byte[] textoPlano = cipher.doFinal(textoCifrado);
```

### 3. 🔑 Regenerar Clave AES

**¿Qué hace?**
- Genera una nueva clave AES de 256 bits
- Utiliza `KeyGenerator` con generación aleatoria segura
- **⚠️ IMPORTANTE**: Invalida todos los textos cifrados anteriores

**Proceso técnico:**
```java
KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
keyGenerator.init(256); // 256 bits de longitud
SecretKey nuevaClave = keyGenerator.generateKey();
```

## 🔬 Conceptos Criptográficos Implementados

### AES (Advanced Encryption Standard)
- **Tipo**: Cifrado simétrico por bloques
- **Tamaño de bloque**: 128 bits (16 bytes)
- **Tamaño de clave**: 256 bits (32 bytes)
- **Rondas de cifrado**: 14 (para AES-256)

### Modo CBC (Cipher Block Chaining)
- **Propósito**: Evita patrones en el texto cifrado
- **Funcionamiento**: Cada bloque se XOR con el bloque cifrado anterior
- **Primer bloque**: Se XOR con el IV (Vector de Inicialización)

### Padding PKCS5
- **Problema**: Los datos pueden no ser múltiplos del tamaño de bloque
- **Solución**: Agrega bytes de relleno según el estándar PKCS#5
- **Ejemplo**: Si faltan 3 bytes, agrega `[0x03, 0x03, 0x03]`

### Vector de Inicialización (IV)
- **Tamaño**: 16 bytes (128 bits) para AES
- **Generación**: Aleatoria para cada operación de cifrado
- **Propósito**: Asegurar que el mismo texto produzca diferentes resultados cifrados

## 🛡️ Aspectos de Seguridad

### ✅ Implementaciones Seguras
- **Generación de claves**: Utiliza `KeyGenerator` con entropía del sistema
- **IV aleatorio**: Nuevo IV para cada operación de cifrado
- **Algoritmo robusto**: AES-256 es considerado seguro contra ataques conocidos
- **Modo CBC**: Previene análisis de patrones

### ⚠️ Consideraciones Importantes
- **Gestión de claves**: En producción, las claves deben almacenarse de forma segura
- **Intercambio de claves**: Este demo no cubre el intercambio seguro de claves
- **Autenticación**: No incluye verificación de integridad (considerar AES-GCM)
- **Ataques de canal lateral**: No protege contra análisis de tiempo/energía

## 📊 Ejemplo de Uso

### Caso de Uso: Cifrar mensaje secreto

1. **Entrada**: `"Mi mensaje super secreto"`
2. **Proceso**:
   - Clave AES: `P8YQzY2j8K1+vZXiAJf2uS7xRq3N5M6E9T4vB1nC8Hw=` (ejemplo)
   - IV generado: `1a2b3c4d5e6f708192a3b4c5d6e7f801` (ejemplo)
   - Cifrado AES-CBC
3. **Salida**: `Ghs9Kkq7xVyMJK8hB3YcBd/OqP5tQxRnF2kL3mN4oA6wE7yU8iT9rV1s=` (ejemplo)

### Verificación de Descifrado

1. **Entrada**: `Ghs9Kkq7xVyMJK8hB3YcBd/OqP5tQxRnF2kL3mN4oA6wE7yU8iT9rV1s=`
2. **Proceso**:
   - Extrae IV: `1a2b3c4d5e6f708192a3b4c5d6e7f801`
   - Descifra con la misma clave AES
3. **Salida**: `"Mi mensaje super secreto"` ✅

## 🧪 Casos de Prueba Sugeridos

### Pruebas Básicas
- [ ] Cifrar texto corto (< 16 caracteres)
- [ ] Cifrar texto largo (> 100 caracteres)
- [ ] Cifrar texto con caracteres especiales (ñ, á, é, 中文)
- [ ] Cifrar cadena vacía
- [ ] Descifrar texto válido
- [ ] Intentar descifrar con clave incorrecta

### Pruebas de Seguridad
- [ ] Verificar que el mismo texto produce diferentes cifrados (por IV aleatorio)
- [ ] Regenerar clave y verificar que los cifrados antiguos fallen
- [ ] Intentar descifrar texto Base64 inválido
- [ ] Verificar longitud mínima del texto cifrado

## 📚 Referencias y Recursos Adicionales

### Documentación Oficial
- [Java Cryptography Architecture (JCA)](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- [Cipher Class Documentation](https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html)
- [AES Specification (NIST)](https://csrc.nist.gov/publications/detail/fips/197/final)

### Estándares Criptográficos
- **FIPS 197**: Advanced Encryption Standard (AES)
- **RFC 3565**: Use of AES Encryption Algorithm in CMS
- **PKCS #5**: Password-Based Cryptography Specification

### Libros Recomendados
- "Applied Cryptography" by Bruce Schneier
- "Cryptography Engineering" by Ferguson, Schneier, and Kohno

## 🤝 Contribuciones y Mejoras

Este proyecto es educativo y puede extenderse con:

- **Autenticación**: Implementar HMAC o usar AES-GCM
- **Derivación de claves**: Implementar PBKDF2 para claves basadas en contraseñas
- **Interfaz gráfica**: Crear una GUI con Swing o JavaFX
- **Persistencia**: Guardar/cargar claves desde archivos
- **Múltiples algoritmos**: Soportar DES, 3DES, ChaCha20

## 📄 Licencia

Este proyecto es de dominio público con fines educativos. Úsalo libremente para aprender sobre criptografía en Java.

---

**⚠️ Disclaimer**: Esta es una demostración educativa. Para aplicaciones en producción, consulta con expertos en seguridad y sigue las mejores prácticas de la industria.
