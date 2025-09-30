import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

/**
 * Demo de Cifrado AES - Consola Simple
 * 
 * Esta aplicación demuestra el uso del módulo Cipher de Java
 * para cifrado y descifrado simétrico con algoritmo AES.
 * 
 * Características:
 * - No utiliza librerías externas (solo APIs nativas de Java)
 * - Generación automática de claves AES
 * - Cifrado/descifrado con modo CBC y padding PKCS5
 * - Codificación en Base64 para visualización
 */
public class CifradoAESDemo {
    
    private static final String ALGORITMO = "AES";
    private static final String TRANSFORMACION = "AES/CBC/PKCS5Padding";
    private static final int TAMAÑO_CLAVE = 256; // bits
    private static final int TAMAÑO_IV = 16; // bytes (128 bits)
    
    private static SecretKey claveSecreta;
    private static Scanner scanner = new Scanner(System.in);
    
    public static void main(String[] args) {
        System.out.println("=================================");
        System.out.println("   DEMO DE CIFRADO AES - JAVA   ");
        System.out.println("=================================");
        System.out.println();
        
        try {
            // Generar clave AES automáticamente
            claveSecreta = generarClaveAES();
            System.out.println("✓ Clave AES generada automáticamente");
            System.out.println("  Algoritmo: " + ALGORITMO);
            System.out.println("  Tamaño: " + TAMAÑO_CLAVE + " bits");
            System.out.println("  Clave (Base64): " + Base64.getEncoder().encodeToString(claveSecreta.getEncoded()));
            System.out.println();
            
            // Bucle principal del programa
            boolean continuar = true;
            while (continuar) {
                mostrarMenu();
                int opcion = leerOpcion();
                
                switch (opcion) {
                    case 1:
                        realizarCifrado();
                        break;
                    case 2:
                        realizarDescifrado();
                        break;
                    case 3:
                        regenerarClave();
                        break;
                    case 4:
                        continuar = false;
                        System.out.println("¡Hasta luego!");
                        break;
                    default:
                        System.out.println("❌ Opción no válida. Intente nuevamente.");
                }
                System.out.println();
            }
            
        } catch (Exception e) {
            System.err.println("❌ Error en la aplicación: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
    
    /**
     * Genera una clave AES secreta de forma automática
     * @return SecretKey - Clave AES generada
     * @throws Exception si hay error en la generación
     */
    private static SecretKey generarClaveAES() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITMO);
        keyGenerator.init(TAMAÑO_CLAVE);
        return keyGenerator.generateKey();
    }
    
    /**
     * Genera un Vector de Inicialización (IV) aleatorio
     * @return byte[] - IV de 16 bytes
     */
    private static byte[] generarIV() {
        byte[] iv = new byte[TAMAÑO_IV];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    /**
     * Cifra un texto plano usando AES
     * @param textoPlano - Texto a cifrar
     * @return String - Texto cifrado en Base64 (IV + datos cifrados)
     * @throws Exception si hay error en el cifrado
     */
    private static String cifrarTexto(String textoPlano) throws Exception {
        // Crear instancia del cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMACION);
        
        // Generar IV aleatorio
        byte[] iv = generarIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        // Inicializar cipher en modo cifrado
        cipher.init(Cipher.ENCRYPT_MODE, claveSecreta, ivSpec);
        
        // Cifrar el texto
        byte[] textoCifrado = cipher.doFinal(textoPlano.getBytes("UTF-8"));
        
        // Combinar IV + datos cifrados
        byte[] resultado = new byte[iv.length + textoCifrado.length];
        System.arraycopy(iv, 0, resultado, 0, iv.length);
        System.arraycopy(textoCifrado, 0, resultado, iv.length, textoCifrado.length);
        
        // Retornar en Base64
        return Base64.getEncoder().encodeToString(resultado);
    }
    
    /**
     * Descifra un texto cifrado en Base64
     * @param textoCifradoBase64 - Texto cifrado en Base64
     * @return String - Texto plano descifrado
     * @throws Exception si hay error en el descifrado
     */
    private static String descifrarTexto(String textoCifradoBase64) throws Exception {
        // Decodificar de Base64
        byte[] datosCifrados = Base64.getDecoder().decode(textoCifradoBase64);
        
        // Extraer IV (primeros 16 bytes)
        byte[] iv = new byte[TAMAÑO_IV];
        System.arraycopy(datosCifrados, 0, iv, 0, TAMAÑO_IV);
        
        // Extraer datos cifrados (resto)
        byte[] textoCifrado = new byte[datosCifrados.length - TAMAÑO_IV];
        System.arraycopy(datosCifrados, TAMAÑO_IV, textoCifrado, 0, textoCifrado.length);
        
        // Crear instancia del cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMACION);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        // Inicializar cipher en modo descifrado
        cipher.init(Cipher.DECRYPT_MODE, claveSecreta, ivSpec);
        
        // Descifrar
        byte[] textoPlano = cipher.doFinal(textoCifrado);
        
        return new String(textoPlano, "UTF-8");
    }
    
    /**
     * Muestra el menú principal
     */
    private static void mostrarMenu() {
        System.out.println("┌─────────────────────────────┐");
        System.out.println("│         MENÚ PRINCIPAL      │");
        System.out.println("├─────────────────────────────┤");
        System.out.println("│ 1. Cifrar texto             │");
        System.out.println("│ 2. Descifrar texto          │");
        System.out.println("│ 3. Regenerar clave AES      │");
        System.out.println("│ 4. Salir                    │");
        System.out.println("└─────────────────────────────┘");
        System.out.print("Seleccione una opción (1-4): ");
    }
    
    /**
     * Lee la opción del usuario
     * @return int - Opción seleccionada
     */
    private static int leerOpcion() {
        try {
            return Integer.parseInt(scanner.nextLine().trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }
    
    /**
     * Realiza el proceso de cifrado
     */
    private static void realizarCifrado() {
        try {
            System.out.println("\n🔒 PROCESO DE CIFRADO");
            System.out.println("─────────────────────");
            System.out.print("Ingrese el texto a cifrar: ");
            String textoPlano = scanner.nextLine();
            
            if (textoPlano.trim().isEmpty()) {
                System.out.println("❌ El texto no puede estar vacío.");
                return;
            }
            
            System.out.println("\n⏳ Cifrando texto...");
            String textoCifrado = cifrarTexto(textoPlano);
            
            System.out.println("\n✅ RESULTADO DEL CIFRADO:");
            System.out.println("Texto original: " + textoPlano);
            System.out.println("Texto cifrado (Base64): " + textoCifrado);
            System.out.println("Longitud cifrada: " + textoCifrado.length() + " caracteres");
            
        } catch (Exception e) {
            System.err.println("❌ Error durante el cifrado: " + e.getMessage());
        }
    }
    
    /**
     * Realiza el proceso de descifrado
     */
    private static void realizarDescifrado() {
        try {
            System.out.println("\n🔓 PROCESO DE DESCIFRADO");
            System.out.println("─────────────────────────");
            System.out.print("Ingrese el texto cifrado (Base64): ");
            String textoCifrado = scanner.nextLine().trim();
            
            if (textoCifrado.isEmpty()) {
                System.out.println("❌ El texto cifrado no puede estar vacío.");
                return;
            }
            
            System.out.println("\n⏳ Descifrando texto...");
            String textoDescifrado = descifrarTexto(textoCifrado);
            
            System.out.println("\n✅ RESULTADO DEL DESCIFRADO:");
            System.out.println("Texto cifrado: " + textoCifrado);
            System.out.println("Texto descifrado: " + textoDescifrado);
            
        } catch (Exception e) {
            System.err.println("❌ Error durante el descifrado: " + e.getMessage());
            System.err.println("   Verifique que el texto cifrado sea válido y haya sido generado con la clave actual.");
        }
    }
    
    /**
     * Regenera la clave AES
     */
    private static void regenerarClave() {
        try {
            System.out.println("\n🔑 REGENERANDO CLAVE AES");
            System.out.println("─────────────────────────");
            System.out.print("¿Está seguro? Esto invalidará todos los textos cifrados anteriores (s/N): ");
            String confirmacion = scanner.nextLine().trim().toLowerCase();
            
            if (confirmacion.equals("s") || confirmacion.equals("si") || confirmacion.equals("sí")) {
                claveSecreta = generarClaveAES();
                System.out.println("✅ Nueva clave AES generada exitosamente");
                System.out.println("   Clave (Base64): " + Base64.getEncoder().encodeToString(claveSecreta.getEncoded()));
            } else {
                System.out.println("❌ Operación cancelada.");
            }
            
        } catch (Exception e) {
            System.err.println("❌ Error al regenerar la clave: " + e.getMessage());
        }
    }
}