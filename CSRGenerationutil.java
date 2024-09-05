import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;

public class CSRGeneratorUtil {

    /**
     * Generates a CSR using the provided KeyPair and subject.
     * 
     * @param keyPair The KeyPair to be used for signing the CSR.
     * @param subject The subject for the certificate request (e.g., "CN=example.com, O=MyOrg")
     * @return A PKCS10CertificationRequest representing the CSR.
     * @throws Exception If there is an error during CSR creation.
     */
    public static PKCS10CertificationRequest generateCSR(KeyPair keyPair, String subject) throws Exception {
        // Define the subject for the CSR
        X500Name x500Name = new X500Name(subject);

        // Create a CSR builder
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(x500Name, keyPair.getPublic());

        // Sign the CSR using the private key with SHA256 and RSA
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        // Build the CSR and return it
        return new PKCS10CertificationRequest(csrBuilder.build(signer).getEncoded());
    }

    /**
     * Converts a PKCS10CertificationRequest to a PEM-encoded string.
     * 
     * @param csr The PKCS10CertificationRequest to be converted.
     * @return A String representing the PEM-encoded CSR.
     * @throws Exception If there is an error during conversion.
     */
    public static String convertCSRToPEM(PKCS10CertificationRequest csr) throws Exception {
        StringWriter str = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(str);
        pemWriter.writeObject(csr);
        pemWriter.close();
        return str.toString();
    }

    public static void main(String[] args) {
        try {
            // First, generate a KeyPair using BouncyCastle
            KeyPair keyPair = KeyPairGeneratorUtil.generateKeyPair(2048);

            // Generate the CSR using the KeyPair
            String subject = "CN=example.com, O=MyOrg";
            PKCS10CertificationRequest csr = generateCSR(keyPair, subject);
            System.out.println("CSR generated successfully!");

            // Convert the CSR to PEM format for further use
            String csrPEM = convertCSRToPEM(csr);
            System.out.println("Generated CSR in PEM format:\n" + csrPEM);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
