package se.idsec.sigval.sigvalservice.controller;

import lombok.extern.log4j.Log4j2;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import se.idsec.sigval.commons.document.DocType;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.idsec.sigval.sigvalservice.configuration.SignatureValidatorProvider;
import se.idsec.sigval.svt.issuer.SVTModel;
import se.idsec.sigval.xml.svt.XMLDocumentSVTMethod;
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;

import javax.servlet.http.HttpSession;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@Log4j2
@RestController
public class UploadController {

  private final HttpSession httpSession;
  private final FileSize maxFileSize;
  private final SignatureValidatorProvider signatureValidatorProvider;
  private final SVTModel svtModel;

  @Autowired
  public UploadController(HttpSession httpSession, FileSize maxFileSize,SignatureValidatorProvider signatureValidatorProvider,  SVTModel svtModel) {
    this.httpSession = httpSession;
    this.maxFileSize = maxFileSize;
    this.signatureValidatorProvider = signatureValidatorProvider;
    this.svtModel = svtModel;
  }

  @PostMapping("/sigupload")
  public String metadataUpload(@RequestParam("uploadedFile") MultipartFile file) throws IOException {
    long size = file.getSize();
    int maxUploadSize = maxFileSize.getIntValue();
    if (size > maxUploadSize) {
      log.warn("Uppload rejected - too large file {}. Max size {}", size, maxUploadSize);
      throw new IllegalArgumentException("Too large upload file to sign");
    }

    byte[] signedDoc = file.getBytes();
    String uploadErrorMessage = null;
    try {
      checkFileValidity(file.getBytes());
    }
    catch (Exception ex) {
      uploadErrorMessage = ex.getMessage();
    }

    httpSession.setAttribute(SessionAttr.signedDoc.name(), signedDoc);
    httpSession.setAttribute(SessionAttr.uploadErrorMessage.name(), uploadErrorMessage);
    httpSession.setAttribute(SessionAttr.docMimeType.name(), file.getContentType());
    httpSession.setAttribute(SessionAttr.docName.name(), file.getOriginalFilename());
    return "[]";
  }

  @RequestMapping(value = "/inlinepdf", method = RequestMethod.GET, produces = "application/pdf")
  public byte[] getInlinePdfDocument(@RequestParam(value = "target", required = false) String target) throws IOException {
    byte[] docBytes = null;
    if (target != null && target.equalsIgnoreCase("signed")) {
      docBytes = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    }
    else {
      docBytes = (byte[]) httpSession.getAttribute("tbsBytes");
    }
    String docMimeType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());

    if (docBytes == null || !docMimeType.equalsIgnoreCase("application/pdf")) {
      throw new IllegalArgumentException("Target PDF file is not available");
    }
    return docBytes;
  }

  @RequestMapping(value = "/pdfdoc", method = RequestMethod.GET, produces = "application/pdf")
  public ResponseEntity<InputStreamResource> getPdfDocument(@RequestParam(value = "target", required = false) String target) throws IOException {

    byte[] docBytes = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    String docType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());
    docName = docName.replaceAll("\\s*,\\s*", "-");

    if (target == null) {
      docBytes = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    }
    if (target.equalsIgnoreCase("svt")){
      docBytes = issuePdfSvt();
      docName = getSvtFileName(docName, docType);
    }

    if (docBytes == null || !docType.equalsIgnoreCase("application/pdf")) {
      throw new IllegalArgumentException("No PDF file is uploaded");
    }

    return ResponseEntity
      .ok()
      .headers(getHeaders(docName))
      .contentLength(docBytes.length)
      .contentType(MediaType.parseMediaType("application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(docBytes)));
  }

  private byte[] issuePdfSvt() {
    return null;
  }

  @RequestMapping(value = "/xmldoc", method = RequestMethod.GET, produces = "text/xml")
  public ResponseEntity<InputStreamResource> getXmlDocument(@RequestParam(value = "target", required = false) String target)
    throws Exception {

    byte[] docbytes = new byte[]{};
    String docType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());
    docName = docName.replaceAll("\\s*,\\s*", "-");

    if (target == null){
      docbytes = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    }
    if (target.equalsIgnoreCase("svt")){
      docbytes =issueXmlSvt();
      docName = getSvtFileName(docName, docType);
    }

    if (docbytes == null || !docType.equalsIgnoreCase("text/xml")) {
      throw new IllegalArgumentException("No XML file is uploaded");
    }

    return ResponseEntity
      .ok()
      .headers(getHeaders(docName))
      .contentLength(docbytes.length)
      .contentType(MediaType.parseMediaType("application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(docbytes)));
  }

  private byte[] issueXmlSvt() throws Exception {
    byte[] docbytes = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    Document document = XMLDocumentBuilder.getDocument(docbytes);
    byte[] svtDocBytes = signatureValidatorProvider.getXmlDocumentSVTIssuer().issueSvt(document, svtModel, XMLDocumentSVTMethod.EXTEND);
    return svtDocBytes;
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

  /**
   * Determines if the uploaded file is eligible for signing
   *
   * @param bytes bytes of the file to sign
   * @return true if the uploaded file is eligible for signing
   */
  private void checkFileValidity(byte[] bytes) throws RuntimeException {

    DocType docType = DocType.getDocType(bytes);
    switch (docType) {
    case XML:
      //No further checks on xml
      break;
    case PDF:
      checkPdfFileValidity(bytes);
      break;
    default:
      log.warn("Upload rejected - Unrecognized file content");
      throw new IllegalArgumentException("Upload rejected - Illegal file content");
    }
  }

  private void checkPdfFileValidity(byte[] bytes) throws RuntimeException {
    try {
      PDDocument document = PDDocument.load(bytes);
      // We are not modifying the document, so we close it directly to avoid memory leak
      document.close();
    }
    catch (Exception e) {
      log.warn("Error processing the uploaded PDF document");
      throw new IllegalArgumentException("Fel vid utvärdering av tidigare underskivet dokument (" + e.getMessage() + ").");
    }
  }

}
