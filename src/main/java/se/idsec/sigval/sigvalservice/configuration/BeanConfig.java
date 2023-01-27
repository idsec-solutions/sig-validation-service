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

package se.idsec.sigval.sigvalservice.configuration;

import lombok.extern.log4j.Log4j2;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import se.idsec.sigval.sigvalservice.configuration.keys.KeySourceType;
import se.idsec.sigval.sigvalservice.configuration.keys.PkiCredentialFactory;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.CRLCacheImpl;
import se.swedenconnect.sigval.svt.issuer.SVTModel;

import java.io.File;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@Log4j2
@Configuration
public class BeanConfig {

  @Bean SVTModel svtModel(
    @Value("${sigval-service.svt.model.issuer-id}") String issuerId,
    @Value("${sigval-service.svt.model.validity-years:#{null}}") Integer validityYears,
    @Value("${sigval-service.svt.model.audience:#{null}}") String[] audience,
    @Value("${sigval-service.svt.model.cert-ref}") boolean certRef
  ){
    SVTModel.SVTModelBuilder builder = SVTModel.builder();
    builder
      .svtIssuerId(issuerId)
      .certRef(certRef);

    if (validityYears != null){
      Calendar expireTime = Calendar.getInstance();
      expireTime.add(Calendar.YEAR, validityYears);
      builder.validityPeriod(expireTime.getTimeInMillis() - System.currentTimeMillis());
    }
    if (audience != null && audience.length>0) {
      builder.audience(Arrays.asList(audience));
    }
    return builder.build();
  }

  @Bean
  public CRLCache crlCache(
    @Value("${sigval-service.crl.cache-folder:#{null}}") String cacheFolder,
    @Value("${sigval-service.crl.recache-grace-period}") long recacheGracePeiod
  ) {
    File cacheFolderFile = cacheFolder == null
      ? new File(System.getProperty("user.dir"), "target/crl-cache")
      : new File(cacheFolder);

    log.info("Setup CRL cache storage at: {}", cacheFolderFile.getAbsolutePath());
    log.info("CRL cache grace period set to (milliseconds): {}", recacheGracePeiod);
    return new CRLCacheImpl(cacheFolderFile, recacheGracePeiod);
  }

  @Bean
  public FileSize maxFileSize(
    @Value("${spring.servlet.multipart.max-file-size}") String maxFileSize
  ) {
    return new FileSize(maxFileSize);
  }

  /**
   * Create the PKI Credential factory
   *
   * @param hsmExternalCfgLocations the locations of external PKCS11 configuration files
   * @return {@link PkiCredentialFactory}
   */
  @Bean
  PkiCredentialFactory pkiCredentialFactory(
    @Value("${sigval-service.pkcs11.external-config-locations:#{null}}") final List<String> hsmExternalCfgLocations) {

    if (hsmExternalCfgLocations != null && hsmExternalCfgLocations.size() != 1) {
      throw new RuntimeException("Only one PKCS11 config file is allowed");
    }

    final PkiCredentialFactory pkiCredentialFactory = new PkiCredentialFactory(
      hsmExternalCfgLocations == null ? null : hsmExternalCfgLocations.get(0));
    pkiCredentialFactory.setMockKeyLen(3072);
    return pkiCredentialFactory;
  }


  @Bean
  public Map<String, PkiCredential> pkiCredentialMap(
    @Value("${sigval-service.svt.keySourceType}")  String keySourceType,
    @Value("${sigval-service.svt.keySourceLocation}")  String keySourceLocation,
    @Value("${sigval-service.svt.keySourceCertLocation}")  String keySourceCertLocation,
    @Value("${sigval-service.svt.keySourceAlias}")  String keySourceAlias,
    @Value("${sigval-service.svt.keySourcePass}")  String keySourcePass,
    @Value("${sigval-service.report.keySourceType}")  String reportKeySourceType,
    @Value("${sigval-service.report.keySourceLocation}")  String reportKeySourceLocation,
    @Value("${sigval-service.report.keySourceCertLocation}")  String reportKeySourceCertLocation,
    @Value("${sigval-service.report.keySourceAlias}")  String reportKeySourceAlias,
    @Value("${sigval-service.report.keySourcePass}")  String reportKeySourcePass,
    @Autowired PkiCredentialFactory pkiCredentialFactory
  ) throws Exception {
    log.info("SVT key source type: {}", keySourceType);

    Map<String, PkiCredential> credentialMap = new HashMap<>();
    credentialMap.put("svt", getCredential(
      pkiCredentialFactory,
      keySourceType,
      keySourceLocation,
      keySourceCertLocation,
      keySourceAlias,
      keySourcePass));

    credentialMap.put("report", getCredential(
      pkiCredentialFactory,
      reportKeySourceType,
      reportKeySourceLocation,
      reportKeySourceCertLocation,
      reportKeySourceAlias,
      reportKeySourcePass));
    return credentialMap;
  }

  private PkiCredential getCredential(PkiCredentialFactory pkiCredentialFactory, String keySourceType,
    String keySourceLocation, String keySourceCertLocation, String keySourceAlias, String keySourcePass)
    throws Exception {
    File keySourceFile = StringUtils.isNotBlank(keySourceLocation) ? new File(keySourceLocation) : null;
    File certificateFile = StringUtils.isNotBlank(keySourceCertLocation) ? new File(keySourceCertLocation) : null;
    KeySourceType type = KeySourceType.valueOf(keySourceType);
    char[] password = keySourcePass != null ? keySourcePass.toCharArray() : null;
    return pkiCredentialFactory.getCredential(
      type, keySourceFile, keySourceAlias, password, certificateFile);
  }

  @Bean(name = "httpClientBean")
  HttpClient httpClient(HttpProxyProperties httpProxyProperties)
    throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

    final HttpClientBuilder builder = HttpClientBuilder.create();
    if (httpProxyProperties != null && httpProxyProperties.getHost() != null) {
      final HttpHost proxy = new HttpHost(httpProxyProperties.getHost(), httpProxyProperties.getPort());
      builder
        .setProxy(proxy)
        .setDefaultRequestConfig(RequestConfig.custom()
          .setConnectTimeout(1000)
          .setConnectionRequestTimeout(1000)
          .setSocketTimeout(5000)
          .build());
      if (httpProxyProperties.getUserName() != null) {
        CredentialsProvider credentialsPovider = new BasicCredentialsProvider();
        credentialsPovider.setCredentials(new AuthScope(proxy), new UsernamePasswordCredentials(
          httpProxyProperties.getUserName(), httpProxyProperties.getPassword()));
        builder.setDefaultCredentialsProvider(credentialsPovider);
      }
    }
    return builder
      .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
      .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
      .build();
  }

}
