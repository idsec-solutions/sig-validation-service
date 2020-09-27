package se.idsec.sigval.sigvalservice.daemon;

import com.nimbusds.jose.JOSEException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import se.idsec.sigval.cert.validity.crl.CRLCache;
import se.idsec.sigval.sigvalservice.configuration.SignatureValidatorProvider;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Component
@Slf4j
public class TimedTasks implements InitializingBean {

  private final CRLCache crlCache;
  private final SignatureValidatorProvider signatureValidatorProvider;

  @Autowired
  public TimedTasks(CRLCache crlCache, SignatureValidatorProvider signatureValidatorProvider,
    @Value("${sigval-service.crl.recache-delay-seconds:3600}") String configuredCrlCacheDelaySeconds,
    @Value("${sigval-service.validators.reload-interval-seconds:600}") String validatorReloadSeconds) {
    this.crlCache = crlCache;
    log.info("Setup CRL re-cache delay (seconds): {}", configuredCrlCacheDelaySeconds);
    this.signatureValidatorProvider = signatureValidatorProvider;
    log.info("Setup Validator reload interval (seconds): {}", validatorReloadSeconds);
  }

  @Scheduled(initialDelayString = "${sigval-service.crl.recache-delay-seconds:3600}" + "000", fixedDelayString =
    "${sigval-service.crl.recache-delay-seconds:3600}" + "000")
  public synchronized void recacheCRLs() {
    log.info("Initiated CRL re-cache");
    crlCache.recache();
    log.debug("Finished CRL re-cache");
  }

  @Scheduled(initialDelayString = "${sigval-service.validators.reload-interval-seconds:600}" + "000", fixedDelayString =
    "${sigval-service.validators.reload-interval-seconds}" + "000")
  public synchronized void reloadValidators() throws IOException, NoSuchAlgorithmException, CertificateException, JOSEException {
    signatureValidatorProvider.loadValidators();
  }


  @Override public void afterPropertiesSet() throws Exception {
    recacheCRLs();
    reloadValidators();
  }
}
