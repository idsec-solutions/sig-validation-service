/*
 * Copyright 2025 IDsec Solutions AB
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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import lombok.extern.slf4j.Slf4j;

/**
 * Basic X509 certificate static utils.
 */
@Slf4j
public class BasicX509Utils {

  /** Hide constructor */
  private BasicX509Utils() {
  }

  /**
   * Generate a V1 certificate
   *
   * @param pair key pair
   * @param subjectDN subject name
   * @return X.509 V1 certificate
   * @throws OperatorCreationException signing error
   * @throws IOException data processing error
   * @throws CertificateException error parsing certificate data
   * @throws KeyStoreException key store error
   */
  public static X509Certificate generateV1Certificate(final KeyPair pair, final X500Name subjectDN)
      throws OperatorCreationException, IOException, CertificateException, KeyStoreException {
    final BigInteger certSerial = BigInteger.valueOf(System.currentTimeMillis());
    final Calendar startTime = Calendar.getInstance();
    startTime.setTime(new Date());
    startTime.add(10, -2);
    final Calendar expiryTime = Calendar.getInstance();
    expiryTime.setTime(new Date());
    expiryTime.add(1, 5);
    final Date notBefore = startTime.getTime();
    final Date notAfter = expiryTime.getTime();
    final PublicKey pubKey = pair.getPublic();
    final X509v1CertificateBuilder certGen =
        new JcaX509v1CertificateBuilder(subjectDN, certSerial, notBefore, notAfter, subjectDN, pubKey);
    final ContentSigner signer = new JcaContentSignerBuilder("SHA512WITHRSA").build(pair.getPrivate());
    final byte[] encoded = certGen.build(signer).getEncoded();
    final CertificateFactory fact = CertificateFactory.getInstance("X.509");
    try (InputStream is = new ByteArrayInputStream(encoded)) {
      return (X509Certificate) fact.generateCertificate(is);
    }
  }

  /**
   * Get X500 distinguished name
   *
   * @param nameMap name type and value map
   * @return {@link X500Name}
   */
  public static X500Name getDn(final Map<X509DnNameType, String> nameMap) {
    final Set<X509DnNameType> keySet = nameMap.keySet();
    final RDN[] rdnArray = new RDN[keySet.size()];
    int i = 0;

    AttributeTypeAndValue atav;
    for (final Iterator<?> var5 = keySet.iterator(); var5.hasNext(); rdnArray[i++] = new RDN(atav)) {
      final X509DnNameType nt = (X509DnNameType) var5.next();
      final String value = nameMap.get(nt);
      atav = nt.getAttribute(value);
    }

    final X500Name dn = new X500Name(rdnArray);
    return dn;
  }

  /**
   * Retrieve a list of PEM objects found in the provided input stream that are of the types PrivateKey (Plaintext),
   * KeyPair or certificate*
   *
   * @param is Inputstream with the PEM resources
   * @return A list of objects (PrivateKey, KeyPair or X509CertificateHolder)
   * @throws IOException data handling error
   * @throws OperatorCreationException key handling error
   * @throws PKCSException PKCS8 error
   */
  public static List<Object> getPemObjects(final InputStream is)
      throws IOException, OperatorCreationException, PKCSException {
    return getPemObjects(is, null);
  }

  /**
   * Retrieve a list of PEM objects found in the provided input stream that are of the types PrivateKey (Encrypted or
   * Plaintext), KeyPair or certificate
   *
   * @param is Inputstream with the PEM resources
   * @param password Optional Password for decrypting PKCS8 private key
   * @return A list of objects (PrivateKey, KeyPair or X509CertificateHolder)
   * @throws IOException data handling error
   * @throws OperatorCreationException key handling error
   * @throws PKCSException PKCS8 error
   */
  public static List<Object> getPemObjects(final InputStream is, final String password)
      throws IOException, OperatorCreationException, PKCSException {
    final List<Object> pemObjList = new ArrayList<>();
    final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
    final Reader rdr = new BufferedReader(new InputStreamReader(is));
    final PEMParser parser = new PEMParser(rdr);
    Object o;
    while ((o = parser.readObject()) != null) {
      if (o instanceof KeyPair) {
        pemObjList.add(o);
      }
      if (o instanceof PrivateKeyInfo) {
        final PrivateKey privateKey = converter.getPrivateKey(PrivateKeyInfo.getInstance(o));
        pemObjList.add(privateKey);
      }
      if (o instanceof PKCS8EncryptedPrivateKeyInfo && password != null) {
        final InputDecryptorProvider pkcs8Prov =
            new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());
        final PrivateKey privateKey =
            converter.getPrivateKey(((PKCS8EncryptedPrivateKeyInfo) o).decryptPrivateKeyInfo(pkcs8Prov));
        pemObjList.add(privateKey);
      }
      if (o instanceof X509CertificateHolder) {
        pemObjList.add(o);
      }
    }
    return pemObjList;
  }

  /**
   * Get a certificate from byte input
   *
   * @param certBytes certificate bytes
   * @return certificate object
   * @throws CertificateException exception creating certificate
   * @throws IOException exception parsing data
   */
  public static X509Certificate getCertificate(final byte[] certBytes) throws CertificateException, IOException {
    InputStream inStream = null;
    try {
      inStream = new ByteArrayInputStream(certBytes);
      final CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(inStream);
    }
    finally {
      if (inStream != null) {
        inStream.close();
      }
    }
  }

  /**
   * Get a certificate or null
   *
   * @param bytes certificate bytes
   * @return a certificate object, or null if certificate creation failed
   */
  public static X509Certificate getCertOrNull(final byte[] bytes) {
    try {
      final CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
    }
    catch (final Exception ex) {
      return null;
    }
  }

  /**
   * Get PEM certificate
   *
   * @param cert certificate bytes
   * @return PEM certificate
   * @throws IOException data parsing error
   * @throws CertificateException certificate encoding exception
   */
  public static String getPemCert(final byte[] cert) throws IOException, CertificateException {
    return getPemCert(getCertificate(cert));
  }

  /**
   * Get PEM certificate
   *
   * @param cert X.509 certificate
   * @return PEM certificate
   * @throws IOException error parsing data
   */
  public static String getPemCert(final X509Certificate cert) throws IOException {
    final StringWriter sw = new StringWriter();
    try (JcaPEMWriter jpw = new JcaPEMWriter(sw)) {
      jpw.writeObject(cert);
    }
    return sw.toString();
  }

  /**
   * Get ordered list of certificates
   *
   * @param unorderedCertList unordered certificate list
   * @param leaf the starting certificate in the chain
   * @return chain order list with the leaf first and root last
   */
  public static List<X509CertificateHolder> getOrderedCertList(final List<X509CertificateHolder> unorderedCertList,
      final X509CertificateHolder leaf) {
    try {
      final List<X509Certificate> chain = new ArrayList<>();
      for (final X509CertificateHolder unorderedCertHolder : unorderedCertList) {
        chain.add(getCertificate(unorderedCertHolder.getEncoded()));
      }
      final X509Certificate cert = getCertificate(leaf.getEncoded());
      // now get the ordered chain
      final List<X509Certificate> orderedCertList = getOrderedCertList(chain, cert);
      // Convert back to cert holder chain
      final List<X509CertificateHolder> certHolderOrderedChain = new ArrayList<>();
      for (final X509Certificate orderedCert : orderedCertList) {
        certHolderOrderedChain.add(new JcaX509CertificateHolder(orderedCert));
      }
      return certHolderOrderedChain;

    }
    catch (final Exception ex) {
      log.error("Unable to parse X509Certificate object", ex);
      throw new RuntimeException("Unable to parse X509Certificate object");
    }
  }

  /**
   * Get ordered list of certificates
   *
   * @param unorderedCertList unordered certificate list
   * @param leaf the starting certificate in the chain
   * @return chain order list with the leaf first and root last
   */
  public static List<X509Certificate> getOrderedCertList(final List<X509Certificate> unorderedCertList,
      final X509Certificate leaf) {
    final List<X509Certificate> orderedCertList = new ArrayList<>();

    for (final X509Certificate cert : unorderedCertList) {
      if (cert.equals(leaf)) {
        orderedCertList.add(leaf);
        break;
      }
    }

    if (orderedCertList.isEmpty()) {
      return orderedCertList;
    }

    if (isSelfSigned(leaf)) {
      return orderedCertList;
    }

    boolean noParent = false;
    boolean selfSigned = false;
    X509Certificate target = leaf;

    while (!noParent && !selfSigned) {
      for (final X509Certificate cert : unorderedCertList) {
        try {
          target.verify(cert.getPublicKey());
          orderedCertList.add(cert);
          target = cert;
          noParent = false;
          selfSigned = isSelfSigned(cert);
          break;
        }
        catch (final Exception e) {
          noParent = true;
        }
      }

    }
    return orderedCertList;

  }

  /**
   * Predicament if the certificate is self-signed
   *
   * @param cert certificate
   * @return true if the certificate is self-signed (self issued).
   */
  public static boolean isSelfSigned(final X509Certificate cert) {
    try {
      cert.verify(cert.getPublicKey());
      return true;
    }
    catch (final Exception e) {
    }
    return false;
  }

  /**
   * Predicament if the certificate is a leaf certificate
   *
   * @param cert certificate
   * @return true if the certificate is not a CA certificate
   */
  public static boolean isEECert(final X509Certificate cert) {
    return cert.getBasicConstraints() == -1;
  }

  /**
   * Get the key length of a public key
   *
   * @param publicKey public key
   * @return key length in bits
   * @throws PublicKeyPolicyException error parsing key length data
   */
  public static int getKeyLength(final PublicKey publicKey) throws PublicKeyPolicyException {
    if (publicKey instanceof RSAPublicKey) {
      final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
      final int keyLen = rsaPublicKey.getModulus().bitLength();
      return keyLen;
    }

    if (publicKey instanceof ECPublicKey) {
      final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
      final ECParameterSpec spec = ecPublicKey.getParams();
      final int keyLen = spec.getOrder().bitLength();
      return keyLen;
    }
    throw new PublicKeyPolicyException("Unsupported public key type");
  }

}
