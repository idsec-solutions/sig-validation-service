/*
 * Copyright 2022-2025 IDsec Solutions AB
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

package se.idsec.sigval.sigvalservice.result.cert;

import lombok.extern.java.Log;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Log
public class CertUtils {

  /**
   * Gets a map of recognized subject DN attributes.
   *
   * @param cert
   *          X.509 certificate
   * @return subject DN attribute map
   * @throws IOException
   *           for errors getting the subject attributes from the certificate
   */
  public static Map<SubjectDnAttribute, String> getSubjectAttributes(final Certificate cert) throws IOException {

    try {
      final ASN1InputStream ain = new ASN1InputStream(cert.getEncoded());
      ASN1Sequence certSeq = null;
      try {
        certSeq = (ASN1Sequence) ain.readObject();
      }
      finally {
        ain.close();
      }
      final ASN1Sequence tbsSeq = (ASN1Sequence) certSeq.getObjectAt(0);

      int counter = 0;
      while (tbsSeq.getObjectAt(counter) instanceof ASN1TaggedObject) {
        counter++;
      }
      // Get subject
      final ASN1Sequence subjectDn = (ASN1Sequence) tbsSeq.getObjectAt(counter + 4);
      final Map<SubjectDnAttribute, String> subjectDnAttributeMap = getSubjectAttributes(subjectDn);

      return subjectDnAttributeMap;
    }
    catch (CertificateEncodingException e) {
      throw new IOException("Failed to get subject attributes from certificate - " + e.getMessage(), e);
    }
  }

  /**
   * Gets a map of recognized subject DN attributes.
   *
   * @param subjectDn
   *          subject DN
   * @return subject DN attribute map
   */
  public static Map<SubjectDnAttribute, String> getSubjectAttributes(final ASN1Sequence subjectDn) {
    final Map<SubjectDnAttribute, String> subjectDnAttributeMap = new EnumMap<>(SubjectDnAttribute.class);

    final Iterator<ASN1Encodable> subjDnIt = subjectDn.iterator();
    while (subjDnIt.hasNext()) {
      final ASN1Set rdnSet = (ASN1Set) subjDnIt.next();
      final Iterator<ASN1Encodable> rdnSetIt = rdnSet.iterator();
      while (rdnSetIt.hasNext()) {
        final ASN1Sequence rdnSeq = (ASN1Sequence) rdnSetIt.next();
        final ASN1ObjectIdentifier rdnOid = (ASN1ObjectIdentifier) rdnSeq.getObjectAt(0);
        final String oidStr = rdnOid.getId();
        final ASN1Encodable rdnVal = rdnSeq.getObjectAt(1);
        final String rdnValStr = getStringValue(rdnVal);
        final SubjectDnAttribute subjectDnAttr = SubjectDnAttribute.getSubjectDnFromOid(oidStr);
        if (!subjectDnAttr.equals(SubjectDnAttribute.unknown)) {
          subjectDnAttributeMap.put(subjectDnAttr, rdnValStr);
        }
      }
    }

    return subjectDnAttributeMap;
  }

  private static String getStringValue(final ASN1Encodable attrVal) {
    if (attrVal instanceof DERUTF8String) {
      DERUTF8String utf8Str = (DERUTF8String) attrVal;
      return utf8Str.getString();
    }
    if (attrVal instanceof DERPrintableString) {
      DERPrintableString str = (DERPrintableString) attrVal;
      return str.getString();
    }
    if (attrVal instanceof DERIA5String) {
      DERIA5String str = (DERIA5String) attrVal;
      return str.getString();
    }
    if (attrVal instanceof ASN1GeneralizedTime) {
      ASN1GeneralizedTime dgTime = (ASN1GeneralizedTime) attrVal;
      try {
        return Instant.ofEpochMilli(dgTime.getDate().getTime()).atZone(ZoneId.of("UTC")).format(DateTimeFormatter.ISO_LOCAL_DATE);
      }
      catch (Exception e) {
        dgTime.toString();
      }
    }
    return attrVal.toString();
  }

  public static String getReferencedAttributeValue(X509Certificate certificate, AttributeMapping.Type type, String ref) throws IOException {
    switch (type) {
    case rdn:
      return getRdn(certificate, ref);
    case san:
      return getSan(certificate, ref);
    case sda:
      return getSda(certificate, ref);
    }
    throw new IOException("Illegal attribute mapping type");
  }

  private static String getSda(X509Certificate certificate, String ref) throws IOException {
    try {
      X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());
      Extension extension = certificateHolder.getExtension(Extension.subjectDirectoryAttributes);
      if(extension == null) {
        return null;
      }
      SubjectDirectoryAttributes sdaExt = SubjectDirectoryAttributes.getInstance(extension.getParsedValue());
      Vector<Attribute> attributes = sdaExt.getAttributes();
      for (Attribute attribute : attributes) {
        ASN1ObjectIdentifier attrOid = attribute.getAttrType();
        if (attrOid.getId().equals(ref)) {
          ASN1Set attrValues = attribute.getAttrValues();
          if (attrValues.size() > 0) {
            ASN1Encodable attrValue = attrValues.getObjectAt(0);
            return getStringValue(attrValue);
          }
        }
      }
    }
    catch (CertificateEncodingException e) {
      throw new IOException(e);
    }
    return null;
  }

  private static String getSan(X509Certificate certificate, String ref) throws IOException {
    try {
      X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());
      Extension extension = certificateHolder.getExtension(Extension.subjectAlternativeName);
      GeneralNames generalNames = GeneralNames.getInstance(extension.getParsedValue());
      List<String> subjectAltNames = new ArrayList<>();
      for (GeneralName generalName : generalNames.getNames()) {
        if (String.valueOf(generalName.getTagNo()).equals(ref) ) {
          subjectAltNames.add(DERIA5String.getInstance(generalName.getName()).getString());
        }
      }
      return subjectAltNames.isEmpty() ? null : String.join(",", subjectAltNames);
    }
    catch (Exception e) {
      throw new IOException(e);
    }
  }

  private static String getRdn(X509Certificate certificate, String ref) throws IOException {
    Map<SubjectDnAttribute, String> subjectAttributes = getSubjectAttributes(certificate);
    return subjectAttributes.keySet().stream()
      .filter(subjectDnAttribute -> subjectDnAttribute.getOid().equalsIgnoreCase(ref))
      .map(subjectAttributes::get)
      .findFirst()
      .orElse(null);
  }

}
