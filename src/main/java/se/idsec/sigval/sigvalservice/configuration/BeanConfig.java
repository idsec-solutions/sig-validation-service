package se.idsec.sigval.sigvalservice.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgorithmRegistry;
import se.idsec.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.idsec.sigval.cert.validity.crl.CRLCache;
import se.idsec.sigval.cert.validity.crl.impl.CRLCacheImpl;
import se.idsec.sigval.commons.algorithms.DigestAlgorithm;
import se.idsec.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.idsec.sigval.commons.algorithms.JWSAlgorithmRegistry;
import se.idsec.sigval.commons.algorithms.PublicKeyType;
import se.idsec.sigval.commons.data.PubKeyParams;
import se.idsec.sigval.commons.timestamp.TimeStampPolicyVerifier;
import se.idsec.sigval.commons.timestamp.impl.BasicTimstampPolicyVerifier;
import se.idsec.sigval.commons.utils.GeneralCMSUtils;
import se.idsec.sigval.commons.utils.SVAUtils;
import se.idsec.sigval.pdf.pdfstruct.impl.DefaultPDFSignatureContextFactory;
import se.idsec.sigval.pdf.svt.PDFSVTSigValClaimsIssuer;
import se.idsec.sigval.pdf.svt.PDFSVTValidator;
import se.idsec.sigval.pdf.utils.CMSVerifyUtils;
import se.idsec.sigval.pdf.verify.ExtendedPDFSignatureValidator;
import se.idsec.sigval.pdf.verify.PDFSingleSignatureValidator;
import se.idsec.sigval.pdf.verify.impl.PDFSingleSignatureValidatorImpl;
import se.idsec.sigval.pdf.verify.impl.SVTenabledPDFDocumentSigVerifier;
import se.idsec.sigval.pdf.verify.policy.PDFSignaturePolicyValidator;
import se.idsec.sigval.pdf.verify.policy.impl.PkixPdfSignaturePolicyValidator;
import se.idsec.sigval.sigvalservice.configuration.keys.LocalKeySource;
import se.idsec.sigval.svt.algorithms.SVTAlgoRegistry;
import se.idsec.sigval.svt.issuer.SVTModel;
import se.idsec.sigval.xml.policy.XMLSignaturePolicyValidator;
import se.idsec.sigval.xml.policy.impl.PkixXmlSignaturePolicyValidator;
import se.idsec.sigval.xml.svt.XMLDocumentSVTIssuer;
import se.idsec.sigval.xml.svt.XMLSVTSigValClaimsIssuer;
import se.idsec.sigval.xml.svt.XMLSVTValidator;
import se.idsec.sigval.xml.verify.ExtendedXMLSignedDocumentValidator;
import se.idsec.sigval.xml.verify.XMLSignatureElementValidator;
import se.idsec.sigval.xml.verify.impl.XMLSignatureElementValidatorImpl;
import se.idsec.sigval.xml.verify.impl.XMLSignedDocumentValidator;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.PKCS11ProviderFactory;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProvidedCfgConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11SoftHsmProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.SoftHsmCredentialConfiguration;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.*;
import java.util.stream.Collectors;

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
  public PDFSVTSigValClaimsIssuer pdfsvtSigValClaimsIssuer(
    @Autowired LocalKeySource svtKeySource,
    @Autowired ExtendedPDFSignatureValidator pdfValidator,
    @Autowired JWSAlgorithm jwsAlgorithm
  ) throws NoSuchAlgorithmException, JOSEException {
    return new PDFSVTSigValClaimsIssuer(
      jwsAlgorithm,
      svtKeySource.getCredential().getPrivateKey(),
      Arrays.asList(svtKeySource.getCredential().getEntityCertificate()),
      pdfValidator);
  }

  @Bean
  public ExtendedPDFSignatureValidator extendedPDFSignatureValidator(
    @Autowired CertificateValidators certificateValidators,
    @Autowired TimeStampPolicyVerifier timeStampPolicyVerifier
  ) {
    PDFSignaturePolicyValidator signaturePolicyValidator = new PkixPdfSignaturePolicyValidator();
    PDFSingleSignatureValidator pdfSignatureVerifier = new PDFSingleSignatureValidatorImpl(
      certificateValidators.getSignatureCertificateValidator(), signaturePolicyValidator,
      timeStampPolicyVerifier);

    // Setup SVA validator
    PDFSVTValidator pdfsvtValidator = new PDFSVTValidator(certificateValidators.getSvtCertificateValidator(), timeStampPolicyVerifier);

    // Get the pdf validator
    ExtendedPDFSignatureValidator pdfValidator = new SVTenabledPDFDocumentSigVerifier(pdfSignatureVerifier, pdfsvtValidator, new DefaultPDFSignatureContextFactory());
    return pdfValidator;
  }

  @Bean
  public XMLDocumentSVTIssuer xmlDocumentSVTIssuer(
    @Autowired LocalKeySource svtKeySource,
    @Autowired XMLSignatureElementValidator xmlSignatureElementValidator,
    @Autowired JWSAlgorithm jwsAlgorithm
  ) throws JOSEException, NoSuchAlgorithmException, IOException {

    XMLSVTSigValClaimsIssuer claimsIssuer = new XMLSVTSigValClaimsIssuer(
      jwsAlgorithm,
      svtKeySource.getCredential().getPrivateKey(),
      Arrays.asList(svtKeySource.getCredential().getEntityCertificate()),
      xmlSignatureElementValidator
    );
    return new XMLDocumentSVTIssuer(claimsIssuer);
  }

  @Bean JWSAlgorithm svtAlgorithm(
    @Autowired LocalKeySource svtKeySource,
    @Value("${sigval-service.svt.model.hash-algo:#{null}}") String hashAlgo) throws IOException, NoSuchAlgorithmException {
    DigestAlgorithm digestAlgorithm = StringUtils.isNotEmpty(hashAlgo)
      ? DigestAlgorithmRegistry.get(DigestAlgorithm.ID_SHA512)
      : DigestAlgorithmRegistry.get(hashAlgo);

    Map<JWSAlgorithm, SVTAlgoRegistry.AlgoProperties> supportedAlgoMap = SVTAlgoRegistry.getSupportedAlgoMap();
    Set<JWSAlgorithm> jwsAlgorithms = supportedAlgoMap.keySet();
    PublicKeyType pkType = GeneralCMSUtils.getPkParams(svtKeySource.getCertificate().getPublicKey()).getPkType();
    Optional<JWSAlgorithm> jwsAlgorithmOptional = jwsAlgorithms.stream()
      .filter(jwsAlgorithm -> {
        JWSAlgorithm.Family family = supportedAlgoMap.get(jwsAlgorithm).getType();
        switch (pkType) {

        case EC:
          return family.equals(JWSAlgorithm.Family.EC) && jwsAlgorithm.getName().startsWith("E");
        case RSA:
          return family.equals(JWSAlgorithm.Family.RSA) && jwsAlgorithm.getName().startsWith("P");
        case Unknown:
          return false;
        }
        return false;
      })
      .filter(jwsAlgorithm -> supportedAlgoMap.get(jwsAlgorithm).getDigestAlgoId().equalsIgnoreCase(digestAlgorithm.getUri()))
      .findFirst();
    if (!jwsAlgorithmOptional.isPresent()){
      log.error("Non supported SVT hash algorithm and SVT key combination");
      throw new IOException("Non supported SVT hash algorithm and SVT key combination");
    }
    log.info("Setting JWS algorithm for SVT issuance to: {}", jwsAlgorithmOptional.get());
    return jwsAlgorithmOptional.get();
  }

  @Bean
  public ExtendedXMLSignedDocumentValidator getXMLValidator(@Autowired XMLSignatureElementValidator xmlSignatureElementValidator) {
    return new XMLSignedDocumentValidator(xmlSignatureElementValidator);
  }

  @Bean
  public XMLSignatureElementValidator xmlSignatureElementValidator(
    @Autowired TimeStampPolicyVerifier timeStampPolicyVerifier,
    @Autowired CertificateValidators certificateValidators
  ){
    XMLSignaturePolicyValidator xmlSignaturePolicyValidator = new PkixXmlSignaturePolicyValidator();

    return new XMLSignatureElementValidatorImpl(
      certificateValidators.getSignatureCertificateValidator(), xmlSignaturePolicyValidator, timeStampPolicyVerifier,
      new XMLSVTValidator(certificateValidators.getSvtCertificateValidator())
    );
  }

  @Bean
  public TimeStampPolicyVerifier timeStampPolicyVerifier(@Autowired CertificateValidators validators) {
    return new BasicTimstampPolicyVerifier(validators.getTimestampCertificateValidator());
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

  @Bean
  public LocalKeySource svtKeySource(
    @Value("${sigval-service.svt.keySourceType}")  String keySourceType,
    @Value("${sigval-service.svt.keySourceLocation}")  String keySourceLocation,
    @Value("${sigval-service.svt.keySourceCertLocation}")  String keySourceCertLocation,
    @Value("${sigval-service.svt.keySourceAlias}")  String keySourceAlias,
    @Value("${sigval-service.svt.keySourcePass}")  String keySourcePass,
    @Value("${sigval-service.pkcs11.reloadable-keys}") boolean pkcs11ReloadableKeys,
    @Autowired PKCS11Provider pkcs11Provider
  ){
    log.info("SVT key source type: {}", keySourceType);
    return new LocalKeySource(keySourceType, keySourceLocation, keySourcePass, keySourceAlias, keySourceCertLocation,pkcs11Provider, pkcs11ReloadableKeys);
  }

  @Bean
  PKCS11Provider pkcs11Provider(
    @Value("${sigval-service.pkcs11.external-config-locations:#{null}}") String hsmExternalCfgLocations,
    @Value("${sigval-service.pkcs11.lib:#{null}}") String hsmLib,
    @Value("${sigval-service.pkcs11.name:#{null}}") String hsmProviderName,
    @Value("${sigval-service.pkcs11.slot:#{null}}") String hsmSlot,
    @Value("${sigval-service.pkcs11.slotListIndex:#{null}}") Integer hsmSlotListIndex,
    @Value("${sigval-service.pkcs11.slotListIndexMaxRange:#{null}}") Integer hsmSlotListIndexMaxRange,
    @Value("${sigval-service.pkcs11.softhsm.keylocation:#{null}}") String hsmKeyLocation,
    @Value("${sigval-service.pkcs11.softhsm.pass:#{null}}") String hsmPin

  ) throws Exception {
    PKCS11ProviderConfiguration configuration;
    if (hsmExternalCfgLocations != null) {
      configuration = new PKCS11ProvidedCfgConfiguration(Collections.singletonList(hsmExternalCfgLocations));
      log.info("Setting up PKCS11 configuration based on externally provided PKCS11 config files");
    }
    else {
      if (hsmKeyLocation != null && hsmPin != null) {
        PKCS11SoftHsmProviderConfiguration softHsmConfig = new PKCS11SoftHsmProviderConfiguration();
        softHsmConfig.setCredentialConfigurationList(getCredentialConfiguration(hsmKeyLocation));
        softHsmConfig.setPin(hsmPin);
        configuration = softHsmConfig;
        log.info("Setting up PKCS11 configuration based on SoftHSM");
      }
      else {
        configuration = new PKCS11ProviderConfiguration();
        log.info("Setting up generic PKCS11 configuration");
      }
      configuration.setLibrary(hsmLib);
      configuration.setName(hsmProviderName);
      configuration.setSlot(hsmSlot);
      configuration.setSlotListIndex(hsmSlotListIndex);
      configuration.setSlotListIndexMaxRange(hsmSlotListIndexMaxRange);
    }

    PKCS11ProviderFactory factory = new PKCS11ProviderFactory(configuration, configString -> {
      Provider sunPKCS11 = Security.getProvider("SunPKCS11");
      // In Java 9+ the config string is either a file path (providing the config data) or the actual config data preceded with "--".
      sunPKCS11 = sunPKCS11.configure("--" + configString);
      return sunPKCS11;
    });
    return factory.createInstance();
  }

  private List<SoftHsmCredentialConfiguration> getCredentialConfiguration(String hsmKeyLocation) {
    File keyDir = new File(hsmKeyLocation);
    File[] files = keyDir.listFiles((dir, name) -> name.endsWith(".key") || name.endsWith(".crt"));
    assert files != null;
    List<File> keyList = Arrays.stream(files)
      .filter(file -> file.getName().endsWith(".key"))
      .collect(Collectors.toList());
    List<String> certList = Arrays.stream(files)
      .filter(file -> file.getName().endsWith(".crt"))
      .filter(file -> isKeyMatch(file, keyList))
      .map(file -> file.getName().substring(0, file.getName().length() - 4))
      .collect(Collectors.toList());

    List<SoftHsmCredentialConfiguration> credentialConfigurationList = new ArrayList<>();
    certList.forEach(keyName -> {
      SoftHsmCredentialConfiguration cc = new SoftHsmCredentialConfiguration();
      cc.setName(keyName);
      cc.setKeyLocation(new File(hsmKeyLocation, keyName + ".key").getAbsolutePath());
      cc.setCertLocation(new File(hsmKeyLocation, keyName + ".crt").getAbsolutePath());
      credentialConfigurationList.add(cc);
    });
    return credentialConfigurationList;
  }

  private boolean isKeyMatch(File file, List<File> keyList) {
    String name = file.getName().substring(0, file.getName().length() - 4);
    return keyList.stream()
      .anyMatch(f -> f.getName().equalsIgnoreCase(name + ".key"));
  }

}
