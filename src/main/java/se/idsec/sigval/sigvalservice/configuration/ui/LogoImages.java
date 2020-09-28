package se.idsec.sigval.sigvalservice.configuration.ui;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class LogoImages {

  @Getter private String logoUrl;
  @Getter private String secondaryLogoUrl;

  public LogoImages(
    @Value("${sigval-service.ui.logoImage.main}") String logoSource,
    @Value("${sigval-service.ui.logoImage.secondary}") String secondaryLogoSource
  ) {
    logoUrl = new LogoImage(logoSource).getDataUrl();
    secondaryLogoUrl = new LogoImage(secondaryLogoSource).getDataUrl();
  }
}
