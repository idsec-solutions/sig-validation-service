package se.idsec.sigval.sigvalservice.controller;

import lombok.extern.log4j.Log4j2;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import se.idsec.sigval.commons.data.ExtendedSigValResult;
import se.idsec.sigval.commons.data.SignedDocumentValidationResult;
import se.idsec.sigval.commons.document.DocType;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;

import javax.servlet.http.HttpSession;
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
    checkFileValidity(file.getBytes());

    httpSession.setAttribute(SessionAttr.signedDoc.name(), signedDoc);
    httpSession.setAttribute(SessionAttr.docMimeType.name(), file.getContentType());
    httpSession.setAttribute(SessionAttr.docName.name(), file.getOriginalFilename());
    return "[]";
  }

  /**
   * Just returns the bytes of a PDF document for display on the web page
   * @param id indicator of id of the signed document or null to get the uploaded validated document
   * @return the bytes of the referenced document
   * @throws IOException on failure to obtain the requested document
   */
  @RequestMapping(value = "/inlinepdf", method = RequestMethod.GET, produces = "application/pdf")
  public byte[] getInlinePdfDocument(
    @RequestParam(value = "id", required = false) String id) throws IOException{
    byte[] docBytes = null;
    if (id == null) {
      docBytes = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    }
    else {
      try {
        docBytes =((SignedDocumentValidationResult<? extends ExtendedSigValResult>) httpSession.getAttribute(SessionAttr.validationResult.name()))
          .getSignatureValidationResults().get(Integer.valueOf(id)).getSignedDocument();
      } catch (Exception ex){
        log.info("unable to locate the signed PDF document bytes of signature with id: {}", id);
      }
    }
    String docMimeType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());

    if (docBytes == null || !docMimeType.equalsIgnoreCase("application/pdf")) {
      throw new IOException("Target PDF file is not available");
    }
    return docBytes;
  }

  @ExceptionHandler({IOException.class, RuntimeException.class})
  public String handleIOException(Exception ex){
    return "{\"message\": \""+ex.getMessage()+"\"}";
  }

  /**
   * Determines if the uploaded file is a valid document
   *
   * @param bytes bytes of the file
   * @throws IOException on errors parsing the uploaded document
   */
  private void checkFileValidity(byte[] bytes) throws IOException {

    DocType docType = DocType.getDocType(bytes);
    switch (docType) {
    case XML:
      checkXmlFileValidity(bytes);
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

  private void checkXmlFileValidity(byte[] bytes) throws IOException{
    try {
      XMLDocumentBuilder.getDocument(bytes);
    } catch (Exception ex) {
      log.warn("Error processing the uploaded XML document");
      throw new IOException("Error parsing uploaded XML document (" + ex.getMessage() + ").");
    }
  }

  private void checkPdfFileValidity(byte[] bytes) throws IOException {
    try {
      PDDocument document = PDDocument.load(bytes);
      // We are not modifying the document, so we close it directly to avoid memory leak
      document.close();
    }
    catch (Exception ex) {
      log.warn("Error processing the uploaded PDF document");
      throw new IOException("Error parsing uploaded PDF document (" + ex.getMessage() + ").");
    }
  }

}
