package se.idsec.sigval.sigvalservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import se.idsec.sigval.commons.data.SignedDocumentValidationResult;
import se.idsec.sigval.commons.document.DocType;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.verify.ExtendedPDFSignatureValidator;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.idsec.sigval.sigvalservice.configuration.UIText;
import se.idsec.sigval.xml.data.ExtendedXmlSigvalResult;
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;
import se.idsec.sigval.xml.verify.ExtendedXMLSignedDocumentValidator;

import javax.servlet.http.HttpSession;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.security.SignatureException;

@Controller
public class MainSigvalController {

  private final UIText uiText;
  private final FileSize maxFileSize;
  private final HttpSession httpSession;
  private final ExtendedPDFSignatureValidator pdfSignatureValidator;
  private final ExtendedXMLSignedDocumentValidator xmlSignatureValidator;

  @Autowired
  public MainSigvalController(UIText uiText, FileSize maxFileSize, HttpSession httpSession,
    ExtendedPDFSignatureValidator pdfSignatureValidator, ExtendedXMLSignedDocumentValidator xmlSignatureValidator) {
    this.uiText = uiText;
    this.maxFileSize = maxFileSize;
    this.httpSession = httpSession;
    this.pdfSignatureValidator = pdfSignatureValidator;
    this.xmlSignatureValidator = xmlSignatureValidator;
  }

  @RequestMapping("/")
  public String getMainPage(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang){

    model.addAttribute("htmlTitle", "Validering Underskrifter - Dev");
    model.addAttribute("bootstrapCss", "css/bootstrap-edusign.min.css");
//    model.addAttribute("logoUrl", "img/sweden-connect.svg");
    model.addAttribute("logoUrl", "img/eduSign.svg");
    model.addAttribute("devmode", false);
    model.addAttribute("secondaryLogoUrl", "img/sunet_gray_logo.svg");
//    model.addAttribute("secondaryLogoUrl", null);
    model.addAttribute("lang", lang);
    model.addAttribute("text", uiText.getBundle(UIText.UiBundle.resultText, lang));
    model.addAttribute("maxmaxFileSizeKb", maxFileSize.getKbValue());

    return "sigval";
  }

  @RequestMapping("/home")
  public String langSelect(){
    return "redirect:/";
  }


  @RequestMapping("/result")
  public String validateUploadedFile(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang)
    throws ParserConfigurationException, SignatureException, SAXException, IOException {

    byte[] signedDoc = (byte[]) httpSession.getAttribute("signedDoc");
    String tbsType = (String) httpSession.getAttribute("tbsType");
    String tbsName = (String) httpSession.getAttribute("tbsName");

    DocType docType = DocType.getDocType(signedDoc);
    switch (docType){

    case XML:
      validateXmlDoc(signedDoc);
      break;
    case PDF:
      validatePdfDoc(signedDoc);
      break;
    }

    return "redirect:/test";
  }

  private void validatePdfDoc(byte[] signedDoc) throws SignatureException {
    SignedDocumentValidationResult<ExtendedPdfSigValResult> validationResult = pdfSignatureValidator.extendedResultValidation(signedDoc);

    int sdfs=0;
  }

  private void validateXmlDoc(byte[] signedDoc) throws ParserConfigurationException, SAXException, IOException, SignatureException {
    Document document = XMLDocumentBuilder.getDocument(signedDoc);
    SignedDocumentValidationResult<ExtendedXmlSigvalResult> validationResult = xmlSignatureValidator.extendedResultValidation(
      document);

    int sdfs=0;
  }

}
