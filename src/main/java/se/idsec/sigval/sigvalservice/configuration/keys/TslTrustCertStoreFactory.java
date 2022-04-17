package se.idsec.sigval.sigvalservice.configuration.keys;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.GeneralName;
import se.swedenconnect.sigval.cert.utils.CertUtils;
import se.swedenconnect.sigval.commons.utils.SVAUtils;
import se.swedenconnect.cert.extensions.SubjectInformationAccess;
import se.swedenconnect.cert.extensions.data.OidName;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

@Slf4j
@Getter
public class TslTrustCertStoreFactory {

  X509Certificate policyRoot;
  CertStore certStore;

  public TslTrustCertStoreFactory(String policyRootLocation) throws IOException, CertificateException {
    this.policyRoot = SVAUtils.getCertificate(IOUtils.toByteArray(new FileInputStream(new File(policyRootLocation))));
    init();
  }
  public TslTrustCertStoreFactory(X509Certificate policyRoot) {
    this.policyRoot = policyRoot;
    init();
  }

  private void init() {
    List<X509Certificate> certificateList = new ArrayList<>();
    try {
      SubjectInformationAccess siaExtension = CertUtils.getSIAExtension(policyRoot);
      if (siaExtension == null){
        log.debug("The policy root certificate contains no SubjectInformationAccess Extension");
        return;
      }
      GeneralName generalName = Arrays.stream(siaExtension.getAccessDescriptions())
        .filter(accessDescription -> accessDescription.getAccessMethod().getId().equals(OidName.id_pkix_ad_caRepository.getOid()))
        .map(accessDescription -> accessDescription.getAccessLocation())
        .findFirst().get();
      String location = ((DERIA5String) generalName.getName()).getString();

      URL url = new URL(location);
      URLConnection connection = url.openConnection();
      connection.setConnectTimeout(1000);
      connection.setReadTimeout(3000);
      byte[] bytes = IOUtils.toByteArray(connection);

      ASN1InputStream ain = new ASN1InputStream(bytes);
      ContentInfo cmsContentInfo = ContentInfo.getInstance(ain.readObject());
      if (!cmsContentInfo.getContentType().equals(CMSObjectIdentifiers.signedData)){
        throw new IOException("Illegal content type");
      }
      SignedData signedData = SignedData.getInstance(cmsContentInfo.getContent());
      Iterator<ASN1Encodable> iterator = signedData.getCertificates().iterator();
      while (iterator.hasNext()){
        try {
          byte[] certByte = iterator.next().toASN1Primitive().getEncoded("DER");
          certificateList.add(CertUtils.getCert(new ByteArrayInputStream(certByte)));
        } catch (Exception ex){
          log.warn("Unable to decode certificate from signed data");
        }
      }

      CertStoreParameters certStoreParameters = new CollectionCertStoreParameters(certificateList);
      certStore = CertStore.getInstance("Collection", certStoreParameters, "BC");

    } catch (Exception ex){
      log.warn("Unable to extract cert store from provided policy root certificate", ex);
      throw new RuntimeException("Unable to extract cert store from provided policy root certificate");
    }
  }

}
