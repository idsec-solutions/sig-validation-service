package se.idsec.sigval.sigvalservice.configuration;

import lombok.Getter;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.idsec.sigval.cert.validity.crl.CRLCache;
import se.idsec.sigval.commons.utils.SVAUtils;
import se.idsec.sigval.sigvalservice.configuration.keys.TslTrustCertStoreFactory;

import java.io.*;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class CertificateValidators {

  private final CRLCache crlCache;

  @Getter private CertificateValidator signatureCertificateValidator;
  @Getter private CertificateValidator timestampCertificateValidator;
  @Getter private CertificateValidator svtCertificateValidator;

  @Autowired
  public CertificateValidators(
    CRLCache crlCache,
    @Value("${sigval-service.cert-validator.sig.tsltrust-root:#{null}}") String sigTslTrustRoot,
    @Value("${sigval-service.cert-validator.sig.trusted-folder:#{null}}") String sigTrustFolder,
    @Value("${sigval-service.cert-validator.tsa.tsltrust-root:#{null}}") String tsaTslTrustRoot,
    @Value("${sigval-service.cert-validator.tsa.trusted-folder:#{null}}") String tsaTrustFolder,
    @Value("${sigval-service.cert-validator.svt.tsltrust-root:#{null}}") String svtTslTrustRoot,
    @Value("${sigval-service.cert-validator.svt.trusted-folder:#{null}}") String svtTrustFolder
  ) throws IOException, CertificateException {
    this.crlCache = crlCache;
    signatureCertificateValidator = getCertValidator(crlCache, sigTrustFolder, sigTslTrustRoot);
    timestampCertificateValidator = getCertValidator(crlCache, tsaTrustFolder, tsaTslTrustRoot);
    svtCertificateValidator = getCertValidator(crlCache, svtTrustFolder, svtTslTrustRoot);
  }

  private CertificateValidator getCertValidator(CRLCache crlCache, String trustFolder, String tslTrustRoot)
    throws IOException, CertificateException {

    X509Certificate policyRoot = null;
    CertStore certStore = null;

    if (tslTrustRoot != null) {
      TslTrustCertStoreFactory ttCSFactory = new TslTrustCertStoreFactory(tslTrustRoot);
      policyRoot = ttCSFactory.getPolicyRoot();
      certStore = ttCSFactory.getCertStore();
    }
    X509Certificate[] additionalCertsArray = getAdditionalTrustedCerts(policyRoot, trustFolder);
    return new StatusCheckingCertificateValidatorImpl(crlCache, certStore, additionalCertsArray);
  }

  private X509Certificate[] getAdditionalTrustedCerts(X509Certificate policyRoot, String trustFolderName) {
    List<X509Certificate> taCertList = new ArrayList<>();
    if (policyRoot != null) taCertList.add(policyRoot);

    if (StringUtils.isNotEmpty(trustFolderName)) {
      // Collect all certs from trust folder
      File trustFolder = new File(trustFolderName);
      File[] certFiles = trustFolder.listFiles((dir, name) -> name.endsWith(".cer") || name.endsWith(".crt"));
      Arrays.stream(certFiles)
        .map(file -> getCertificate(file))
        .forEach(x509certList -> x509certList.forEach(x509cert -> taCertList.add(x509cert)));
    }

    return taCertList.toArray(new X509Certificate[taCertList.size()]);
  }

  private List<X509Certificate> getCertificate(File file) {
    try {
      return getCertificatesFromPem(new FileInputStream(file));
    } catch (Exception ex){
      return new ArrayList<>();
    }
  }

  /**
   * Retrieve a list of PEM objects found in the provided input stream that are of the types PrivateKey (Encrypted or Plaintext), KeyPair or certificate
   *
   * @param is InputStream holding the PEM encoded certificates
   * @return A list of Certificates
   * @throws IOException on error
   */
  public static List<X509Certificate> getCertificatesFromPem(InputStream is)
    throws IOException {
    List<X509Certificate> pemObjList = new ArrayList<>();
    Reader rdr = new BufferedReader(new InputStreamReader(is));
    PEMParser parser = new PEMParser(rdr);
    Object o;
    while ((o = parser.readObject()) != null) {
      if (o instanceof X509CertificateHolder) {
        X509Certificate cert = SVAUtils.getCertOrNull(((X509CertificateHolder) o).getEncoded());
        if (cert != null) pemObjList.add(cert);
      }
    }
    return pemObjList;
  }
}
