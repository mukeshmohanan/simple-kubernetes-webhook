import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.RSAKeyGenParameterSpec;

public class KeyPairGeneratorUtil {

    static {
        // Register BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generates an RSA KeyPair using BouncyCastle with the specified key size.
     * 
     * @param keySize The size of the key (e.g., 2048 or 4096 bits)
     * @return A KeyPair containing the public and private keys.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     * @throws NoSuchProviderException  If BouncyCastle provider is not available.
     */
    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");  // Use BouncyCastle provider
        keyGen.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));  // Use 65537 as public exponent
        return keyGen.generateKeyPair();
    }

    public static void main(String[] args) {
        try {
            KeyPair keyPair = generateKeyPair(2048); // Generate 2048-bit key pair
            System.out.println("KeyPair generated successfully!");
            System.out.println("Private Key: " + keyPair.getPrivate());
            System.out.println("Public Key: " + keyPair.getPublic());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
