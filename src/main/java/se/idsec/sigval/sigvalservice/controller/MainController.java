package se.idsec.sigval.sigvalservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.idsec.sigval.sigvalservice.configuration.ui.LogoImages;
import se.idsec.sigval.sigvalservice.configuration.ui.UIStyle;
import se.idsec.sigval.sigvalservice.configuration.ui.UIText;

import javax.servlet.http.HttpSession;

@Controller
public class MainController {

  @Value("${sigval-service.ui.html-title.upload}") String htmlTitleUpload;
  @Value("${sigval-service.ui.style}") String style;
  @Value("${sigval-service.ui.devmode}") boolean devmode;

  private final UIText uiText;
  private final FileSize maxFileSize;
  private final HttpSession httpSession;
  private final LogoImages logoImages;

  @Autowired
  public MainController(UIText uiText, FileSize maxFileSize, HttpSession httpSession, LogoImages logoImages) {
    this.uiText = uiText;
    this.maxFileSize = maxFileSize;
    this.httpSession = httpSession;
    this.logoImages = logoImages;
  }

  @RequestMapping("/")
  public String getMainPage(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang){

    // Clear http session
    httpSession.removeAttribute(SessionAttr.signedDoc.name());
    httpSession.removeAttribute(SessionAttr.docName.name());
    httpSession.removeAttribute(SessionAttr.docMimeType.name());
    httpSession.removeAttribute(SessionAttr.docType.name());
    httpSession.removeAttribute(SessionAttr.validationResult.name());
    httpSession.removeAttribute(SessionAttr.resultPageData.name());
    httpSession.removeAttribute(SessionAttr.uploadErrorMessage.name());
    httpSession.removeAttribute(SessionAttr.svtDocument.name());

    // Set view model
    model.addAttribute("htmlTitle", htmlTitleUpload);
    model.addAttribute("bootstrapCss", UIStyle.valueOf(style).getBootrapSrc());
    model.addAttribute("logoUrl", logoImages.getLogoUrl());
    model.addAttribute("secondaryLogoUrl", logoImages.getSecondaryLogoUrl());
    model.addAttribute("devmode", devmode);
    model.addAttribute("lang", lang);
    model.addAttribute("text", uiText.getBundle(UIText.UiBundle.resultText, lang));
    model.addAttribute("maxmaxFileSizeKb", maxFileSize.getKbValue());

    return "sigval";
  }





}
