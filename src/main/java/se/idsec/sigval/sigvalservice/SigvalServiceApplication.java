package se.idsec.sigval.sigvalservice;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.security.Security;

@SpringBootApplication
@EnableScheduling
public class SigvalServiceApplication {

  public static void main(String[] args) {
    System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
    Security.insertProviderAt(new BouncyCastleProvider(), 2);
    org.apache.xml.security.Init.init();
    SpringApplication.run(SigvalServiceApplication.class, args);
  }

}
