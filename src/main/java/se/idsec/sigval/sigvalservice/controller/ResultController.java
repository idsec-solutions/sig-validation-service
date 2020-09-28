package se.idsec.sigval.sigvalservice.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import se.idsec.sigval.commons.data.ExtendedSigValResult;
import se.idsec.sigval.commons.data.SignedDocumentValidationResult;
import se.idsec.sigval.commons.document.DocType;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.idsec.sigval.sigvalservice.configuration.ui.LogoImages;
import se.idsec.sigval.sigvalservice.configuration.ui.UIStyle;
import se.idsec.sigval.sigvalservice.configuration.ui.UIText;
import se.idsec.sigval.sigvalservice.result.data.ResultPageData;

import javax.servlet.http.HttpSession;

@Slf4j
@Controller
public class ResultController {

  @Value("${sigval-service.ui.html-title.result}") String htmlTitleResult;
  @Value("${sigval-service.ui.style}") String style;
  @Value("${sigval-service.ui.devmode}") boolean devmode;

  private final UIText uiText;
  private final FileSize maxFileSize;
  private final HttpSession httpSession;
  private final LogoImages logoImages;


  public ResultController(UIText uiText, FileSize maxFileSize, HttpSession httpSession, LogoImages logoImages) {
    this.uiText = uiText;
    this.maxFileSize = maxFileSize;
    this.httpSession = httpSession;
    this.logoImages = logoImages;
  }

  @RequestMapping("/result")
  public String getResultPage(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang) {

    //byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    //String docMimeType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    //String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());
    DocType docType = (DocType) httpSession.getAttribute(SessionAttr.docType.name());
    SignedDocumentValidationResult<? extends ExtendedSigValResult> validationResult =
      (SignedDocumentValidationResult<? extends ExtendedSigValResult>) httpSession.getAttribute(SessionAttr.validationResult.name());
    ResultPageData resultPageData = (ResultPageData) httpSession.getAttribute(SessionAttr.resultPageData.name());

    if (resultPageData == null || validationResult == null) return "redirect:/";

    // Set view model
    model.addAttribute("bootstrapCss", UIStyle.valueOf(style).getBootrapSrc());
    model.addAttribute("htmlTitle", htmlTitleResult);
    model.addAttribute("resultPageData", resultPageData);
    model.addAttribute("validationResult", validationResult);
    model.addAttribute("logoUrl", logoImages.getLogoUrl());
    model.addAttribute("secondaryLogoUrl", logoImages.getSecondaryLogoUrl());
    model.addAttribute("devmode", devmode);
    model.addAttribute("lang", lang);
    model.addAttribute("text", uiText.getBundle(UIText.UiBundle.resultText, lang));
    model.addAttribute("docType", docType);
    model.addAttribute("showLoa", true);

    //
    int sdfds = 0;

    return "sigvalresult";
  }


}
