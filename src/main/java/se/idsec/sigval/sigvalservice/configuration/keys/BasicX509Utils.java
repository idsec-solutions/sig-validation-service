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

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class BasicX509Utils {

    private BasicX509Utils() {
    }

    public static X509Certificate generateV1Certificate(KeyPair pair, X500Name subjectDN) throws OperatorCreationException, IOException, CertificateException, KeyStoreException {
        BigInteger certSerial = BigInteger.valueOf(System.currentTimeMillis());
        Calendar startTime = Calendar.getInstance();
        startTime.setTime(new Date());
        startTime.add(10, -2);
        Calendar expiryTime = Calendar.getInstance();
        expiryTime.setTime(new Date());
        expiryTime.add(1, 5);
        Date notBefore = startTime.getTime();
        Date notAfter = expiryTime.getTime();
        PublicKey pubKey = pair.getPublic();
        X509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(subjectDN, certSerial, notBefore, notAfter, subjectDN, pubKey);
        ContentSigner signer = (new JcaContentSignerBuilder("SHA512WITHRSA")).build(pair.getPrivate());
        byte[] encoded = certGen.build(signer).getEncoded();
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(encoded);
        X509Certificate certificate = (X509Certificate) fact.generateCertificate(is);
        is.close();
        return certificate;
    }

    public static X500Name getDn(Map<X509DnNameType, String> nameMap) {
        Set<X509DnNameType> keySet = nameMap.keySet();
        RDN[] rdnArray = new RDN[keySet.size()];
        int i = 0;

        AttributeTypeAndValue atav;
        for (Iterator var5 = keySet.iterator(); var5.hasNext(); rdnArray[i++] = new RDN(atav)) {
            X509DnNameType nt = (X509DnNameType) var5.next();
            String value = (String) nameMap.get(nt);
            atav = nt.getAttribute(value);
        }

        X500Name dn = new X500Name(rdnArray);
        return dn;
    }

    /**
     * Retrieve a list of PEM objects found in the provided input stream that are of the types PrivateKey (Plaintext), KeyPair or certificate*
     * @param is Inputstream with the PEM resources
     * @return A list of objects (PrivateKey, KeyPair or X509CertificateHolder)
     * @throws IOException
     * @throws OperatorCreationException
     * @throws PKCSException
     */
    public static List<Object> getPemObjects(InputStream is) throws IOException, OperatorCreationException, PKCSException {
        return  getPemObjects(is,null);
    }

    /**
     * Retrieve a list of PEM objects found in the provided input stream that are of the types PrivateKey (Encrypted or Plaintext), KeyPair or certificate
     * @param is Inputstream with the PEM resources
     * @param password Optional Password for decrypting PKCS8 private key
     * @return A list of objects (PrivateKey, KeyPair or X509CertificateHolder)
     * @throws IOException
     * @throws OperatorCreationException
     * @throws PKCSException
     */
    public static List<Object> getPemObjects(InputStream is, String password) throws IOException, OperatorCreationException, PKCSException {
        List<Object> pemObjList = new ArrayList<>();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        Reader rdr = new BufferedReader(new InputStreamReader(is));
        PEMParser parser = new PEMParser(rdr);
        Object o;
        while ((o = parser.readObject()) != null) {
            if (o instanceof KeyPair) {
                pemObjList.add(o);
            }
            if (o instanceof PrivateKeyInfo) {
                PrivateKey privateKey = converter.getPrivateKey(PrivateKeyInfo.getInstance(o));
                pemObjList.add(privateKey);
            }
            if (o instanceof PKCS8EncryptedPrivateKeyInfo && password !=null){
                InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());
                PrivateKey privateKey = converter.getPrivateKey(((PKCS8EncryptedPrivateKeyInfo) o).decryptPrivateKeyInfo(pkcs8Prov));
                pemObjList.add(privateKey);
            }
            if (o instanceof X509CertificateHolder){
                pemObjList.add(o);
            }
        }
        return pemObjList;
    }



}
