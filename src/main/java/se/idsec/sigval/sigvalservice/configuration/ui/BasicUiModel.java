package se.idsec.sigval.sigvalservice.configuration.ui;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class BasicUiModel {

  @Getter private final String bootstrapCss;
  @Getter private final String htmlTitle;
  @Getter private final String htmlTitleResult;
  @Getter private final String htmlTitleError;
  @Getter private final String logoUrl;
  @Getter private final String secondaryLogoUrl;
  @Getter private final boolean devmode;

  @Autowired
  public BasicUiModel(
    LogoImages logoImages,
    @Value("${sigval-service.ui.html-title.upload}") String htmlTitle,
    @Value("${sigval-service.ui.html-title.result}") String htmlTitleResult,
    @Value("${sigval-service.ui.html-title.error}") String htmlTitleError,
    @Value("${sigval-service.ui.style}") String style,
    @Value("${sigval-service.ui.devmode}") boolean devmode
  ) {
    this.bootstrapCss = UIStyle.valueOf(style).getBootrapSrc();
    this.htmlTitle = htmlTitle;
    this.htmlTitleResult = htmlTitleResult;
    this.htmlTitleError = htmlTitleError;
    this.logoUrl=logoImages.getLogoUrl();
    this.secondaryLogoUrl = logoImages.getSecondaryLogoUrl();
    this.devmode = devmode;
  }
}
