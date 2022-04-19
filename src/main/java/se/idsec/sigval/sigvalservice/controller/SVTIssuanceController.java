package se.idsec.sigval.sigvalservice.controller;

import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import se.idsec.sigval.sigvalservice.configuration.SignatureValidatorProvider;
import se.swedenconnect.sigval.commons.document.DocType;
import se.swedenconnect.sigval.commons.svt.SVTExtendpolicy;
import se.swedenconnect.sigval.pdf.timestamp.issue.impl.PDFDocTimstampProcessor;
import se.swedenconnect.sigval.svt.issuer.SVTModel;
import se.swedenconnect.sigval.xml.utils.XMLDocumentBuilder;

import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@RestController
@Slf4j
public class SVTIssuanceController {

  @Value("${sigval-service.svt.issuer-enabled}") boolean enableSvtIssuer;
  @Value("${sigval-service.svt.default-replace}") boolean defaultReplaceSvt;
  @Value("${sigval-service.ui.downloaded-svt-suffix}") String svtSuffix;

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

  @RequestMapping(value = "/issue-svt", method = RequestMethod.POST)
  public ResponseEntity<InputStreamResource> issueSvtApi(
    @RequestParam(name = "name", required = false) String name,
    @RequestParam(name = "document", required = false) String document) throws IOException, RuntimeException {

    byte[] documentBytes = null;
    if (document != null) {
      try {
        documentBytes = Base64.decode(document);
      }
      catch (Exception ex) {
        log.debug("Illegal document data");
      }
    }

    if (documentBytes == null) {
      log.debug("Bad request - no document provided in the request");
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    SVTExtendpolicy svtExtendpolicy = defaultReplaceSvt
      ? SVTExtendpolicy.REPLACE
      : SVTExtendpolicy.EXTEND;

    byte[] svtEnhancedDocument;
    MediaType mediaType;

    // Generate report based on document type
    DocType docType = DocType.getDocType(documentBytes);
    switch (docType) {
    case XML:
      try {
        Document xmlDocument = XMLDocumentBuilder.getDocument(documentBytes);
        svtEnhancedDocument = signatureValidatorProvider.getXmlDocumentSVTIssuer().issueSvt(xmlDocument, svtModel, svtExtendpolicy);
        mediaType = MediaType.TEXT_XML;
      }
      catch (Exception ex) {
        log.error("Error issuing XML SVT token {}", ex.getMessage());
        throw new IOException(ex.getMessage());
      }
      break;
    case PDF:
      try {
        SignedJWT signedSvtJWT = signatureValidatorProvider.getPdfsvtSigValClaimsIssuer().getSignedSvtJWT(documentBytes, svtModel);
        PDFDocTimstampProcessor.Result result = PDFDocTimstampProcessor.createSVTSealedPDF(
          documentBytes, signedSvtJWT.serialize(), signatureValidatorProvider.getSvtTsSigner());
        svtEnhancedDocument = result.getDocument();
        mediaType = MediaType.APPLICATION_PDF;
      }
      catch (Exception ex) {
        log.error("Error issuing PDF SVT token {}", ex.getMessage());
        throw new IOException(ex.getMessage());
      }
      break;
    case JOSE:
    case JOSE_COMPACT:
      try {
        svtEnhancedDocument = signatureValidatorProvider.getJoseDocumentSVTIssuer().issueSvt(documentBytes, svtModel, svtExtendpolicy);
        mediaType = MediaType.APPLICATION_JSON;
      }
      catch (Exception ex) {
        log.error("Error issuing JOSE SVT token {}", ex.getMessage());
        throw new IOException(ex.getMessage());
      }
      break;
    default:
      log.debug("Bad request - data type not recognized");
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    if (svtEnhancedDocument == null) {
      throw new IOException("No SVT document was created");
    }

    // Get filename
    name = StringUtils.isBlank(name) ? "svt_enhanced_signed_document" : name;
    name = name.replaceAll("\\s*,\\s*", "-");
    String fileName = getSvtFileName(name, mediaType);

    return ResponseEntity
      .ok()
      .headers(getHeaders(fileName))
      .contentLength(svtEnhancedDocument.length)
      .contentType(mediaType)
      .body(new InputStreamResource(new ByteArrayInputStream(svtEnhancedDocument)));
  }

/*  @RequestMapping(value = "/pdfsvt", method = RequestMethod.GET, produces = "application/pdf")
  public ResponseEntity<InputStreamResource> getPdfDocument() throws IOException, RuntimeException {

    if (!enableSvtIssuer)
      throw new IllegalArgumentException("SVT issuer disabled - received SVT issuing request");

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
      }
      catch (Exception ex) {
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
    if (!enableSvtIssuer)
      throw new IllegalArgumentException("SVT issuer disabled - received SVT issuing request");

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
      }
      catch (Exception ex) {
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

  @RequestMapping(value = "/josesvt", method = RequestMethod.GET, produces = "application/json")
  public ResponseEntity<InputStreamResource> getJoseDocument()
    throws IOException, RuntimeException {
    if (!enableSvtIssuer)
      throw new IllegalArgumentException("SVT issuer disabled - received SVT issuing request");

    byte[] svtDocBytes = (byte[]) httpSession.getAttribute(SessionAttr.svtDocument.name());
    String docType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());

    if (svtDocBytes == null) {
      byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
      docName = getSvtFileName(docName.replaceAll("\\s*,\\s*", "-"), docType);

      try {
        svtDocBytes = signatureValidatorProvider.getJoseDocumentSVTIssuer().issueSvt(signedDoc, svtModel, SVTExtendpolicy.EXTEND);
        httpSession.setAttribute(SessionAttr.svtDocument.name(), svtDocBytes);
      }
      catch (Exception ex) {
        log.error("Error issuing SVT token {}", ex.getMessage());
        throw new IOException(ex.getMessage());
      }
    }

    if (svtDocBytes == null) {
      throw new IOException("No JOSE file is uploaded");
    }

    return ResponseEntity
      .ok()
      .headers(getHeaders(docName))
      .contentLength(svtDocBytes.length)
      .contentType(MediaType.parseMediaType(displayJson ? "application/json" : "application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(svtDocBytes)));
  }*/

  private HttpHeaders getHeaders(String fileName) {
    HttpHeaders headers = new HttpHeaders();
    headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headers.add("Content-disposition", "inline; filename=" + fileName);
    headers.add("Pragma", "no-cache");
    headers.add("Expires", "0");
    return headers;
  }

  private String getSvtFileName(String fileName, MediaType tbsType) {

    if (tbsType.equals(MediaType.TEXT_XML)) {
      return fileName.toLowerCase().endsWith(".xml")
        ? stripFileName(fileName, 4) + svtSuffix + ".xml"
        : fileName + svtSuffix + ".xml";
    }
    if (tbsType.equals(MediaType.APPLICATION_PDF)) {
      return fileName.toLowerCase().endsWith(".pdf")
        ? stripFileName(fileName, 4) + svtSuffix + ".pdf"
        : fileName + svtSuffix + ".pdf";
    }
    if (tbsType.equals(MediaType.APPLICATION_JSON)) {
      return fileName.toLowerCase().endsWith(".json")
        ? stripFileName(fileName, 5) + svtSuffix + ".json"
        : fileName + svtSuffix + ".json";
    }
    return fileName;
  }

  private String stripFileName(String fileName, int len) {
    return fileName.substring(0, fileName.length() - len);
  }

}
