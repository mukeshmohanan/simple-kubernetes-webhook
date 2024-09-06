import org.jscep.client.verification.CertificateVerifier;

import java.security.KeyStore;
import java.security.cert.*;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class TrustStoreCertificateVerifier implements CertificateVerifier {

    private final KeyStore trustStore;

    public TrustStoreCertificateVerifier(KeyStore trustStore) {
        this.trustStore = trustStore;
    }

    @Override
    public boolean verify(X509Certificate cert) {
        try {
            // Create a CertPathValidator for PKIX validation
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");

            // Create a CertPath from the provided certificate
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certFactory.generateCertPath(Collections.singletonList(cert));

            // Extract the trust anchors from the trust store
            Set<TrustAnchor> trustAnchors = getTrustAnchorsFromTrustStore();

            // Create PKIX parameters with the trust anchors
            PKIXParameters pkixParams = new PKIXParameters(trustAnchors);
            pkixParams.setRevocationEnabled(false);  // Disable CRL checks for simplicity (customize as needed)

            // Validate the certificate path
            certPathValidator.validate(certPath, pkixParams);

            // If validation is successful
            System.out.println("Certificate is trusted: " + cert.getSubjectDN());
            return true;
        } catch (Exception e) {
            System.out.println("Certificate verification failed: " + e.getMessage());
            return false;
        }
    }

    private Set<TrustAnchor> getTrustAnchorsFromTrustStore() throws KeyStoreException {
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (String alias : Collections.list(trustStore.aliases())) {
            if (trustStore.isCertificateEntry(alias)) {
                X509Certificate trustedCert = (X509Certificate) trustStore.getCertificate(alias);
                TrustAnchor anchor = new TrustAnchor(trustedCert, null);
                trustAnchors.add(anchor);
            }
        }
        return trustAnchors;
    }
}
