package se.idsec.sigval.sigvalservice.configuration;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.CRLCacheImpl;
import se.idsec.sigval.sigvalservice.configuration.keys.LocalKeySource;
import se.swedenconnect.sigval.svt.issuer.SVTModel;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.PKCS11ProviderFactory;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProvidedCfgConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11SoftHsmProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.SoftHsmCredentialConfiguration;

import java.io.File;
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
  public Map<String, LocalKeySource> keySourceMap(
    @Value("${sigval-service.svt.keySourceType}")  String keySourceType,
    @Value("${sigval-service.svt.keySourceLocation}")  String keySourceLocation,
    @Value("${sigval-service.svt.keySourceCertLocation}")  String keySourceCertLocation,
    @Value("${sigval-service.svt.keySourceAlias}")  String keySourceAlias,
    @Value("${sigval-service.svt.keySourcePass}")  String keySourcePass,
    @Value("${sigval-service.svt.keySourceType}")  String reportKeySourceType,
    @Value("${sigval-service.svt.keySourceLocation}")  String reportKeySourceLocation,
    @Value("${sigval-service.svt.keySourceCertLocation}")  String reportKeySourceCertLocation,
    @Value("${sigval-service.svt.keySourceAlias}")  String reportKeySourceAlias,
    @Value("${sigval-service.svt.keySourcePass}")  String reportKeySourcePass,
    @Value("${sigval-service.pkcs11.reloadable-keys}") boolean pkcs11ReloadableKeys,
    @Autowired PKCS11Provider pkcs11Provider
  ){
    log.info("SVT key source type: {}", keySourceType);

    LocalKeySource svtKeySource = new LocalKeySource(keySourceType, keySourceLocation, keySourcePass,
      keySourceAlias, keySourceCertLocation,pkcs11Provider, pkcs11ReloadableKeys);
    LocalKeySource reportKeySource = new LocalKeySource(reportKeySourceType, reportKeySourceLocation, reportKeySourcePass,
      reportKeySourceAlias, reportKeySourceCertLocation,pkcs11Provider, pkcs11ReloadableKeys);

    Map<String, LocalKeySource> keySourceMap = new HashMap<>();
    keySourceMap.put("svt", svtKeySource);
    keySourceMap.put("report", reportKeySource);

    return keySourceMap;
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
