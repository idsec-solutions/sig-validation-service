package se.idsec.sigval.sigvalservice.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.xml.sax.SAXException;
import se.idsec.sigval.commons.data.ExtendedSigValResult;
import se.idsec.sigval.commons.data.SignedDocumentValidationResult;
import se.idsec.sigval.commons.document.DocType;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.idsec.sigval.sigvalservice.configuration.ui.LogoImages;
import se.idsec.sigval.sigvalservice.configuration.ui.UIStyle;
import se.idsec.sigval.sigvalservice.configuration.ui.UIText;
import se.idsec.sigval.sigvalservice.result.ResultPageDataGenerator;
import se.idsec.sigval.sigvalservice.result.data.ResultPageData;
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;

import javax.servlet.http.HttpSession;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Controller
public class ResultController {

  @Value("${sigval-service.ui.html-title.result}") String htmlTitleResult;
  @Value("${sigval-service.ui.style}") String style;
  @Value("${sigval-service.ui.devmode}") boolean devmode;
  @Value("${sigval-service.ui.issue-svt-if-svt-exist}") boolean issueSvtIfExists;
  @Value("${sigval-service.ui.enalbe-signed-data-view}") boolean enableSignedDataView;
  @Value("${sigval-service.ui.show-loa}") boolean showLoa;

  private final UIText uiText;
  private final FileSize maxFileSize;
  private final HttpSession httpSession;
  private final LogoImages logoImages;
  private final ResultPageDataGenerator resultPageDataGenerator;


  public ResultController(UIText uiText, FileSize maxFileSize, HttpSession httpSession, LogoImages logoImages, ResultPageDataGenerator resultPageDataGenerator) {
    this.uiText = uiText;
    this.maxFileSize = maxFileSize;
    this.httpSession = httpSession;
    this.logoImages = logoImages;
    this.resultPageDataGenerator = resultPageDataGenerator;
  }

  @RequestMapping("/result")
  public String getResultPage(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang)
    throws ParserConfigurationException, SAXException, IOException {

    byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    String docMimeType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());
    DocType docType = (DocType) httpSession.getAttribute(SessionAttr.docType.name());
    SignedDocumentValidationResult<? extends ExtendedSigValResult> validationResult =
      (SignedDocumentValidationResult<? extends ExtendedSigValResult>) httpSession.getAttribute(SessionAttr.validationResult.name());

    if (validationResult == null) return "redirect:/";
    ResultPageData resultPageData = resultPageDataGenerator.getResultPageData(validationResult, docName, docMimeType, lang);

    String xmlPrettyPrint = docType.equals(DocType.XML) ? XMLDocumentBuilder.getDocText(XMLDocumentBuilder.getDocument(signedDoc)) : null;

    List<? extends ExtendedSigValResult> signatureValidationResults = validationResult.getSignatureValidationResults();
    List<String> signedDocumentList = new ArrayList<>();
    for (int i=0; i<signatureValidationResults.size(); i++){
      if (docType.equals(DocType.XML)){
        try {
          signedDocumentList.add(XMLDocumentBuilder.getDocText(XMLDocumentBuilder.getDocument(signatureValidationResults.get(i).getSignedDocument())));
        }
        catch (Exception e) {
          signedDocumentList.add("No document available");
        }
      } else {
        signedDocumentList.add("inlinepdf?id="+i);
      }
    }

    // Determine if SVT is available.
    boolean svtAvailable = signatureValidationResults.stream().anyMatch(sigValResult -> sigValResult.getSvtJWT() == null);

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
    model.addAttribute("showLoa", showLoa);
    model.addAttribute("xmlPrettyPrint", xmlPrettyPrint);
    model.addAttribute("signedDocs", signedDocumentList);
    model.addAttribute("svtAvailable", svtAvailable || issueSvtIfExists);
    model.addAttribute("enableSignedDataView", enableSignedDataView);

    return "sigvalresult";
  }


}
