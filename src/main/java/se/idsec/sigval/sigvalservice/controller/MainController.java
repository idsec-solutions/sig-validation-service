package se.idsec.sigval.sigvalservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.idsec.sigval.sigvalservice.configuration.ui.BasicUiModel;
import se.idsec.sigval.sigvalservice.configuration.ui.LogoImages;
import se.idsec.sigval.sigvalservice.configuration.ui.UIStyle;
import se.idsec.sigval.sigvalservice.configuration.ui.UIText;

import javax.servlet.http.HttpSession;

@Controller
public class MainController {

  private final UIText uiText;
  private final FileSize maxFileSize;
  private final HttpSession httpSession;
  private final BasicUiModel basicUiModel;

  @Autowired
  public MainController(UIText uiText, FileSize maxFileSize, HttpSession httpSession, BasicUiModel basicUiModel) {
    this.uiText = uiText;
    this.maxFileSize = maxFileSize;
    this.httpSession = httpSession;
    this.basicUiModel = basicUiModel;
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
    model.addAttribute("basicModel", basicUiModel);
    model.addAttribute("lang", lang);
    model.addAttribute("text", uiText.getBundle(UIText.UiBundle.resultText, lang));
    model.addAttribute("maxmaxFileSizeKb", maxFileSize.getKbValue());

    return "sigval";
  }





}
