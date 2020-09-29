package se.idsec.sigval.sigvalservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.idsec.sigval.sigvalservice.configuration.SignatureValidatorProvider;
import se.idsec.sigval.svt.issuer.SVTModel;
import se.idsec.sigval.xml.svt.XMLDocumentSVTMethod;
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;

import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@RestController
public class SVTIssuanceController {

  private final HttpSession httpSession;
  private final SignatureValidatorProvider signatureValidatorProvider;
  private final SVTModel svtModel;

  @Autowired
  public SVTIssuanceController(HttpSession httpSession,
    SignatureValidatorProvider signatureValidatorProvider, SVTModel svtModel) {
    this.httpSession = httpSession;
    this.signatureValidatorProvider = signatureValidatorProvider;
    this.svtModel = svtModel;
  }

  @RequestMapping(value = "/pdfsvt", method = RequestMethod.GET, produces = "application/pdf")
  public ResponseEntity<InputStreamResource> getPdfDocument() throws IOException {

    byte[] svtDocBytes = (byte[]) httpSession.getAttribute(SessionAttr.svtDocument.name());
    String docType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());

    if (svtDocBytes == null) {
      byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
      docName = getSvtFileName(docName.replaceAll("\\s*,\\s*", "-"), docType);

      //TODO Issue PDF SVT
      //svtDocBytes = Issue SVT from signedDoc;

      httpSession.setAttribute(SessionAttr.svtDocument.name(), svtDocBytes);
    }

    if (svtDocBytes == null || !docType.equalsIgnoreCase("application/pdf")) {
      throw new IllegalArgumentException("No PDF file is uploaded");
    }

    return ResponseEntity
      .ok()
      .headers(getHeaders(docName))
      .contentLength(svtDocBytes.length)
      .contentType(MediaType.parseMediaType("application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(svtDocBytes)));
  }


  @RequestMapping(value = "/xmlsvt", method = RequestMethod.GET, produces = "text/xml")
  public ResponseEntity<InputStreamResource> getXmlDocument()
    throws Exception {

    byte[] svtDocBytes = (byte[]) httpSession.getAttribute(SessionAttr.svtDocument.name());
    String docType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());

    if (svtDocBytes == null) {
      byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
      docName = getSvtFileName(docName.replaceAll("\\s*,\\s*", "-"), docType);

      Document document = XMLDocumentBuilder.getDocument(signedDoc);
      svtDocBytes = signatureValidatorProvider.getXmlDocumentSVTIssuer().issueSvt(document, svtModel, XMLDocumentSVTMethod.EXTEND);
      httpSession.setAttribute(SessionAttr.svtDocument.name(), svtDocBytes);
    }

    if (svtDocBytes == null || !docType.equalsIgnoreCase("text/xml")) {
      throw new IOException("No XML file is uploaded");
    }

    return ResponseEntity
      .ok()
      .headers(getHeaders(docName))
      .contentLength(svtDocBytes.length)
      .contentType(MediaType.parseMediaType("application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(svtDocBytes)));
  }

  private HttpHeaders getHeaders(String fileName) {
    HttpHeaders headers = new HttpHeaders();
    headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headers.add("content-disposition", "inline; filename=" + fileName);
    headers.add("Pragma", "no-cache");
    headers.add("Expires", "0");
    return headers;
  }

  private String getSvtFileName(String fileName, String tbsType) {

    if (fileName.toLowerCase().endsWith(".xml") && tbsType.equalsIgnoreCase("text/xml")) {
      return stripFileName(fileName) + "_svt.xml";
    }
    if (fileName.toLowerCase().endsWith(".pdf") && tbsType.equalsIgnoreCase("application/pdf")) {
      return stripFileName(fileName) + "_svt.pdf";
    }
    return fileName;
  }

  private String stripFileName(String fileName) {
    return fileName.substring(0, fileName.length() - 4);
  }


}
