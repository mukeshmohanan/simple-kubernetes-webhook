import org.jscep.client.verification.CertificateVerifier;
import java.security.cert.X509Certificate;

public class AlwaysAcceptVerifier implements CertificateVerifier {

    @Override
    public boolean verify(X509Certificate cert) {
        // Always return true to accept the certificate without validation
        return true;
    }
}
