package se.idsec.sigval.sigvalservice.daemon;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import se.idsec.sigval.cert.validity.crl.CRLCache;

@Component
@Slf4j
public class TimedTasks implements InitializingBean {

  private final CRLCache crlCache;

  @Autowired
  public TimedTasks(CRLCache crlCache, @Value("${sigval-service.crl.recache-delay-seconds:3600}") String configuredCrlCacheDelaySeconds) {
    this.crlCache = crlCache;
    log.info("Setup CRL re-cache delay (seconds): {}", configuredCrlCacheDelaySeconds);
  }

  @Scheduled(initialDelayString = "${sigval-service.crl.recache-delay-seconds:3600}" + "000", fixedDelayString =
    "${sigval-service.crl.recache-delay-seconds:3600}" + "000")
  public synchronized void recacheCRLs() {
    log.info("Initiated CRL re-cache");
    crlCache.recache();
    log.debug("Finished CRL re-cache");
  }

  @Override public void afterPropertiesSet() throws Exception {
    recacheCRLs();
  }
}
