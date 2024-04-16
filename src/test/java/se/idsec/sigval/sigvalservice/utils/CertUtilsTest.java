/*
 * Copyright (c) 2024. IDsec Solutions AB
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

package se.idsec.sigval.sigvalservice.utils;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.idsec.sigval.sigvalservice.result.cert.CertUtils;
import se.idsec.sigval.sigvalservice.result.cert.SubjectDnAttribute;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;

import java.io.FileReader;
import java.io.Reader;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * Testing certificate utils
 */
public class CertUtilsTest {


  static X509Certificate complexCert;

  @BeforeAll
  static void init() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    try(Reader reader = new FileReader(CertUtilsTest.class.getClassLoader().getResource("complex-cert.crt").getFile())) {
      PEMParser pemParser = new PEMParser(reader);
      X509CertificateHolder certificateHolder = (X509CertificateHolder) pemParser.readObject();
      JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
      complexCert = converter.getCertificate(certificateHolder);
    }
  }


  @Test
  void testCertAttributeValueExtraction() throws  Exception {

    String cnAttrValue = CertUtils.getReferencedAttributeValue(complexCert, AttributeMapping.Type.rdn,
      SubjectDnAttribute.cn.getOid());
    Assertions.assertEquals("Nisse Hult", cnAttrValue);

    String sanAttrValue = CertUtils.getReferencedAttributeValue(complexCert, AttributeMapping.Type.san, "6");
    Assertions.assertEquals("https://example.com/alt-name-uri", sanAttrValue);

    String dateOfBirth = CertUtils.getReferencedAttributeValue(complexCert, AttributeMapping.Type.sda,
      BCStyle.DATE_OF_BIRTH.getId());
    Assertions.assertEquals("1962-11-02", dateOfBirth);

    Assertions.assertNull(CertUtils.getReferencedAttributeValue(complexCert, AttributeMapping.Type.rdn,
      SubjectDnAttribute.pseudonym.getOid()));
    Assertions.assertNull(CertUtils.getReferencedAttributeValue(complexCert, AttributeMapping.Type.san, "2"));
    Assertions.assertNull(CertUtils.getReferencedAttributeValue(complexCert, AttributeMapping.Type.sda,
      SubjectDnAttribute.pseudonym.getOid()));
  }
}
