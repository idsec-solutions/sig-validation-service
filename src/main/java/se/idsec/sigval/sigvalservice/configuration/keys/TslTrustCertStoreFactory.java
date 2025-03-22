/*
 * Copyright (c) 2022. IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.GeneralName;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import se.swedenconnect.cert.extensions.SubjectInformationAccess;
import se.swedenconnect.cert.extensions.data.OidName;
import se.swedenconnect.sigval.cert.utils.CertUtils;
import se.swedenconnect.sigval.commons.utils.SVAUtils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

@Slf4j
@Getter
public class TslTrustCertStoreFactory {

  final X509Certificate policyRoot;
  private final WebClient webClient;
  CertStore certStore;

  public TslTrustCertStoreFactory(String policyRootLocation, WebClient webClient)
    throws IOException, CertificateException {
    this.policyRoot = SVAUtils.getCertificate(IOUtils.toByteArray(new FileInputStream(policyRootLocation)));
    this.webClient = webClient;
    init();
  }

  public TslTrustCertStoreFactory(X509Certificate policyRoot, WebClient webClient) {
    this.policyRoot = policyRoot;
    this.webClient = webClient;
    init();
  }

  private void init() {
    List<X509Certificate> certificateList = new ArrayList<>();
    try {
      SubjectInformationAccess siaExtension = CertUtils.getSIAExtension(policyRoot);
      if (siaExtension == null) {
        log.debug("The policy root certificate contains no SubjectInformationAccess Extension");
        return;
      }
      GeneralName generalName = Arrays.stream(siaExtension.getAccessDescriptions())
        .filter(accessDescription -> accessDescription.getAccessMethod()
          .getId()
          .equals(OidName.id_pkix_ad_caRepository.getOid()))
        .map(AccessDescription::getAccessLocation)
        .findFirst().orElseThrow(() -> new IllegalArgumentException("No CA repository access description available"));
      String location = ((DERIA5String) generalName.getName()).getString();

      byte[] bytes;
      try {
        bytes = webClient.get()
            .uri(location)
            .retrieve()
            .onStatus(HttpStatusCode::isError, response -> {
              // Create an Exception if the status code indicates an error
              return response.bodyToMono(String.class)
                  .flatMap(errorBody -> {
                    String errorMessage = String.format(
                        "Http error %s: %s. Unable to download cert store certificates from %s",
                        response.statusCode(), errorBody, location
                    );
                    return Mono.error(new IOException(errorMessage));
                  });
            })
            .bodyToMono(byte[].class)
            .block();
      } catch (Exception ex) {
        throw new IOException("Connection timeout: " + ex.getMessage(), ex);
      }
      if (bytes == null) {
        throw new IOException("No data returned from CA repository");
      }
      try(ASN1InputStream ain = new ASN1InputStream(bytes)) {
        ContentInfo cmsContentInfo = ContentInfo.getInstance(ain.readObject());
        if (!cmsContentInfo.getContentType().equals(CMSObjectIdentifiers.signedData)) {
          throw new IOException("Illegal content type");
        }
        SignedData signedData = SignedData.getInstance(cmsContentInfo.getContent());
        Iterator<ASN1Encodable> iterator = signedData.getCertificates().iterator();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        while (iterator.hasNext()) {
          try (ByteArrayInputStream is = new ByteArrayInputStream(iterator.next().toASN1Primitive().getEncoded("DER"))) {
            certificateList.add((X509Certificate) cf.generateCertificate(is));
            if (log.isTraceEnabled()) {
              log.trace("Added certificate {} for {}", certificateList.size(),
                  certificateList.getLast().getSubjectX500Principal());
            }
          }
          catch (Exception ex) {
            log.warn("Unable to decode certificate from signed data");
          }
        }

        CertStoreParameters certStoreParameters = new CollectionCertStoreParameters(certificateList);
        certStore = CertStore.getInstance("Collection", certStoreParameters, "BC");
      }

    }
    catch (Exception ex) {
      log.warn("Unable to extract cert store from provided policy root certificate", ex);
      throw new RuntimeException("Unable to extract cert store from provided policy root certificate", ex);
    }
  }

}
