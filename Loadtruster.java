import java.io.FileInputStream;
import java.security.KeyStore;

public class TrustStoreLoader {

    public static KeyStore loadTrustStore(String trustStorePath, String trustStorePassword) throws Exception {
        // Create an instance of KeyStore (JKS or PKCS12 depending on your format)
        KeyStore trustStore = KeyStore.getInstance("JKS"); // Use "PKCS12" if using a PKCS12 file
        
        // Open the trust store file as an input stream
        try (FileInputStream trustStoreStream = new FileInputStream(trustStorePath)) {
            // Load the KeyStore from the file using the provided password
            trustStore.load(trustStoreStream, trustStorePassword.toCharArray());
        }
        
        // Return the loaded KeyStore object
        return trustStore;
    }
}
