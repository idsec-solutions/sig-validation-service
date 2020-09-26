package se.idsec.sigval.sigvalservice.controller;

import lombok.extern.log4j.Log4j2;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import se.idsec.sigval.commons.document.DocType;
import se.idsec.sigval.sigvalservice.configuration.FileSize;

import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@Log4j2
@RestController
public class UploadController {

  private final HttpSession httpSession;
  private final FileSize maxFileSize;

  @Autowired
  public UploadController(HttpSession httpSession, FileSize maxFileSize) {
    this.httpSession = httpSession;
    this.maxFileSize = maxFileSize;
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

    httpSession.setAttribute("signedDoc", signedDoc);
    httpSession.setAttribute("uploadErrorMessage", uploadErrorMessage);
    httpSession.setAttribute("tbsType", file.getContentType());
    httpSession.setAttribute("tbsName", file.getOriginalFilename());
    return "[]";
  }

  @RequestMapping(value = "/inlinepdf", method = RequestMethod.GET, produces = "application/pdf")
  public byte[] getInlinePdfDocument(@RequestParam(value = "target", required = false) String target) throws IOException {
    byte[] docBytes = null;
    if (target != null && target.equalsIgnoreCase("signed")) {
      docBytes = (byte[]) httpSession.getAttribute("signedDoc");
    }
    else {
      docBytes = (byte[]) httpSession.getAttribute("tbsBytes");
    }
    String tbsType = (String) httpSession.getAttribute("tbsType");

    if (docBytes == null || !tbsType.equalsIgnoreCase("application/pdf")) {
      throw new IllegalArgumentException("Target PDF file is not available");
    }
    return docBytes;
  }

  @RequestMapping(value = "/pdfdoc", method = RequestMethod.GET, produces = "application/pdf")
  public ResponseEntity<InputStreamResource> getPdfDocument() throws IOException {

    byte[] signedDoc = (byte[]) httpSession.getAttribute("signedDoc");
    String tbsType = (String) httpSession.getAttribute("tbsType");
    String tbsName = (String) httpSession.getAttribute("tbsName");
    tbsName = tbsName.replaceAll("\\s*,\\s*", "-");

    if (signedDoc == null || !tbsType.equalsIgnoreCase("application/pdf")) {
      throw new IllegalArgumentException("No PDF file is uploaded");
    }

    return ResponseEntity
      .ok()
      .headers(getHeaders(tbsName, tbsType))
      .contentLength(signedDoc.length)
      .contentType(MediaType.parseMediaType("application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(signedDoc)));
  }

  @RequestMapping(value = "/xmldoc", method = RequestMethod.GET, produces = "text/xml")
  public ResponseEntity<InputStreamResource> getXmlDocument() throws IOException {

    byte[] signedDoc = (byte[]) httpSession.getAttribute("signedDoc");
    String tbsType = (String) httpSession.getAttribute("tbsType");
    String tbsName = (String) httpSession.getAttribute("tbsName");
    tbsName = tbsName.replaceAll("\\s*,\\s*", "-");

    if (signedDoc == null || !tbsType.equalsIgnoreCase("text/xml")) {
      throw new IllegalArgumentException("No XML file is uploaded");
    }

    return ResponseEntity
      .ok()
      .headers(getHeaders(tbsName, tbsType))
      .contentLength(signedDoc.length)
      .contentType(MediaType.parseMediaType("application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(signedDoc)));
  }

  private HttpHeaders getHeaders(String fileName, String docType) {
    HttpHeaders headers = new HttpHeaders();
    headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headers.add("content-disposition", "inline; filename=" + getSignedFileName(fileName, docType));
    headers.add("Pragma", "no-cache");
    headers.add("Expires", "0");
    return headers;
  }

  private String getSignedFileName(String fileName, String tbsType) {

    if (fileName.toLowerCase().endsWith(".xml") && tbsType.equalsIgnoreCase("text/xml")) {
      return stripFileName(fileName) + "_signed.xml";
    }
    if (fileName.toLowerCase().endsWith(".pdf") && tbsType.equalsIgnoreCase("application/pdf")) {
      return stripFileName(fileName) + "_signed.pdf";
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
