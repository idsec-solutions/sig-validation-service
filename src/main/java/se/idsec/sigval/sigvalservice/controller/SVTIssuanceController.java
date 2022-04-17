package se.idsec.sigval.sigvalservice.controller;

import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.w3c.dom.Document;
import se.swedenconnect.sigval.pdf.timestamp.issue.impl.PDFDocTimstampProcessor;
import se.idsec.sigval.sigvalservice.configuration.SignatureValidatorProvider;
import se.idsec.sigval.sigvalservice.configuration.ui.BasicUiModel;
import se.swedenconnect.sigval.svt.issuer.SVTModel;
import se.swedenconnect.sigval.xml.svt.XMLDocumentSVTMethod;
import se.swedenconnect.sigval.xml.utils.XMLDocumentBuilder;

import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@RestController
@Slf4j
public class SVTIssuanceController {

  @Value("${sigval-service.svt.issuer-enabled}") boolean enableSvtIssuer;
  @Value("${sigval-service.ui.display-downloaded-svt-pdf}") boolean displayPdf;
  @Value("${sigval-service.ui.display-downloaded-svt-xml}") boolean displayXml;
  @Value("${sigval-service.ui.downloaded-svt-suffix}") String svtSuffix;

  private final HttpSession httpSession;
  private final SignatureValidatorProvider signatureValidatorProvider;
  private final SVTModel svtModel;
  private final BasicUiModel basicUiModel;

  @Autowired
  public SVTIssuanceController(HttpSession httpSession,
    SignatureValidatorProvider signatureValidatorProvider, SVTModel svtModel, BasicUiModel basicUiModel) {
    this.httpSession = httpSession;
    this.signatureValidatorProvider = signatureValidatorProvider;
    this.svtModel = svtModel;
    this.basicUiModel = basicUiModel;
  }

  @RequestMapping(value = "/pdfsvt", method = RequestMethod.GET, produces = "application/pdf")
  public ResponseEntity<InputStreamResource> getPdfDocument() throws IOException, RuntimeException {

    if (!enableSvtIssuer) throw new IllegalArgumentException("SVT issuer disabled - received SVT issuing request");

    byte[] svtDocBytes = (byte[]) httpSession.getAttribute(SessionAttr.svtDocument.name());
    String docType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());

    if (svtDocBytes == null) {
      byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
      docName = getSvtFileName(docName.replaceAll("\\s*,\\s*", "-"), docType);

      try {
        SignedJWT signedSvtJWT = signatureValidatorProvider.getPdfsvtSigValClaimsIssuer().getSignedSvtJWT(signedDoc, svtModel);
        PDFDocTimstampProcessor.Result result = PDFDocTimstampProcessor.createSVTSealedPDF(
          signedDoc, signedSvtJWT.serialize(), signatureValidatorProvider.getSvtTsSigner());
        svtDocBytes = result.getDocument();
        httpSession.setAttribute(SessionAttr.svtDocument.name(), svtDocBytes);
      } catch (Exception ex){
        log.error("Error issuing SVT token {}", ex.getMessage());
        throw new IOException(ex.getMessage());
      }

    }

    if (svtDocBytes == null || !docType.equalsIgnoreCase("application/pdf")) {
      throw new IllegalArgumentException("No PDF file is uploaded");
    }

    return ResponseEntity
      .ok()
      .headers(getHeaders(docName))
      .contentLength(svtDocBytes.length)
      .contentType(MediaType.parseMediaType(displayPdf ? "application/pdf" : "application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(svtDocBytes)));
  }


  @RequestMapping(value = "/xmlsvt", method = RequestMethod.GET, produces = "text/xml")
  public ResponseEntity<InputStreamResource> getXmlDocument()
    throws IOException, RuntimeException {
    if (!enableSvtIssuer) throw new IllegalArgumentException("SVT issuer disabled - received SVT issuing request");

    byte[] svtDocBytes = (byte[]) httpSession.getAttribute(SessionAttr.svtDocument.name());
    String docType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());

    if (svtDocBytes == null) {
      byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
      docName = getSvtFileName(docName.replaceAll("\\s*,\\s*", "-"), docType);

      try {
        Document document = XMLDocumentBuilder.getDocument(signedDoc);
        svtDocBytes = signatureValidatorProvider.getXmlDocumentSVTIssuer().issueSvt(document, svtModel, XMLDocumentSVTMethod.EXTEND);
        httpSession.setAttribute(SessionAttr.svtDocument.name(), svtDocBytes);
      } catch (Exception ex){
        log.error("Error issuing SVT token {}", ex.getMessage());
        throw new IOException(ex.getMessage());
      }
    }

    if (svtDocBytes == null || !docType.equalsIgnoreCase("text/xml")) {
      throw new IOException("No XML file is uploaded");
    }

    return ResponseEntity
      .ok()
      .headers(getHeaders(docName))
      .contentLength(svtDocBytes.length)
      .contentType(MediaType.parseMediaType(displayXml ? "text/xml" : "application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(svtDocBytes)));
  }

  @ExceptionHandler({IOException.class, RuntimeException.class})
  public ModelAndView handleIOException(Exception ex){
    ModelAndView mav = new ModelAndView();
    mav.addObject("message", ex.getMessage());
    mav.addObject("basicModel", basicUiModel);
    mav.setViewName("error");
    return mav;
  }

  private HttpHeaders getHeaders(String fileName) {
    HttpHeaders headers = new HttpHeaders();
    headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headers.add("Content-disposition", "inline; filename=" + fileName);
    headers.add("Pragma", "no-cache");
    headers.add("Expires", "0");
    return headers;
  }

  private String getSvtFileName(String fileName, String tbsType) {

    if (fileName.toLowerCase().endsWith(".xml") && tbsType.equalsIgnoreCase("text/xml")) {
      return stripFileName(fileName) + svtSuffix +".xml";
    }
    if (fileName.toLowerCase().endsWith(".pdf") && tbsType.equalsIgnoreCase("application/pdf")) {
      return stripFileName(fileName) + svtSuffix +".pdf";
    }
    return fileName;
  }

  private String stripFileName(String fileName) {
    return fileName.substring(0, fileName.length() - 4);
  }


}
