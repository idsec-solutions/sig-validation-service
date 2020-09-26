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
    org.apache.xml.security.Init.init();
    Security.addProvider(new BouncyCastleProvider());
    SpringApplication.run(SigvalServiceApplication.class, args);
  }

}
