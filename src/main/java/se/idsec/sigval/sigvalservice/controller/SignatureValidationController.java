package se.idsec.sigval.sigvalservice.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;
import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.commons.document.DocType;
import se.swedenconnect.sigval.pdf.verify.ExtendedPDFSignatureValidator;
import se.idsec.sigval.sigvalservice.configuration.SignatureValidatorProvider;
import se.idsec.sigval.sigvalservice.result.ResultPageDataGenerator;
import se.idsec.sigval.sigvalservice.result.data.ResultPageData;
import se.swedenconnect.sigval.xml.utils.XMLDocumentBuilder;
import se.swedenconnect.sigval.xml.verify.ExtendedXMLSignedDocumentValidator;

import javax.servlet.http.HttpSession;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.security.SignatureException;

@Slf4j
@Controller
public class SignatureValidationController {

  private final HttpSession httpSession;
  private final SignatureValidatorProvider signatureValidatorProvider;
  private final ResultPageDataGenerator resultPageDataGenerator;

  @Autowired
  public SignatureValidationController(HttpSession httpSession,
    SignatureValidatorProvider signatureValidatorProvider,
    ResultPageDataGenerator resultPageDataGenerator) {
    this.httpSession = httpSession;
    this.signatureValidatorProvider = signatureValidatorProvider;
    this.resultPageDataGenerator = resultPageDataGenerator;
  }

  @RequestMapping("/validate")
  public String validateUploadedFile(@CookieValue(name = "langSelect", defaultValue = "sv") String lang)
    throws ParserConfigurationException, SignatureException, SAXException, IOException {

    byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    String docMimeType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());

    SignedDocumentValidationResult<? extends ExtendedSigValResult> validationResult;

    DocType docType = DocType.getDocType(signedDoc);
    switch (docType){
    case XML:
      ExtendedXMLSignedDocumentValidator xmlValidator = signatureValidatorProvider.getXmlSignedDocumentValidator();
      Document document = XMLDocumentBuilder.getDocument(signedDoc);
      validationResult = xmlValidator.extendedResultValidation(
        document);
      break;
    case PDF:
      ExtendedPDFSignatureValidator pdfValidator = signatureValidatorProvider.getPdfSignatureValidator();
      validationResult = pdfValidator.extendedResultValidation(signedDoc);
      break;
    default:
      throw new IOException("Unable to handle uploaded document - illegal document content");
    }
    ResultPageData resultPageData = resultPageDataGenerator.getResultPageData(validationResult, docName, docMimeType, lang);
    httpSession.setAttribute(SessionAttr.docType.name(), docType);
    httpSession.setAttribute(SessionAttr.validationResult.name(), validationResult);
    httpSession.setAttribute(SessionAttr.resultPageData.name(), resultPageData);

    return "redirect:/result";
  }
}
