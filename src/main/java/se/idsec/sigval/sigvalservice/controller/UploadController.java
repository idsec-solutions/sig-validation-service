/*
 * Copyright 2022-2025 IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.idsec.sigval.sigvalservice.controller;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSObjectJSON;
import jakarta.servlet.http.HttpSession;
import lombok.extern.log4j.Log4j2;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;
import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.commons.document.DocType;
import se.swedenconnect.sigval.xml.utils.XMLDocumentBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

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
    case JOSE:
    case JOSE_COMPACT:
      checkJoseValidity(bytes);
      break;
    default:
      log.warn("Upload rejected - Unrecognized file content");
      throw new IllegalArgumentException("Upload rejected - Illegal file content");
    }
  }

  private void checkJoseValidity(byte[] bytes) throws IOException {
    try {
      JWSObject.parse(new String(bytes, StandardCharsets.UTF_8));
      log.debug("Found compact serialized JWS");
      return;
    }
    catch (ParseException e) {
      log.debug("No compact serialized JWS signature");
    }

    try {
      JWSObjectJSON.parse(new String(bytes, StandardCharsets.UTF_8));
      log.debug("Found JSON serialized JWS");
      return;
    }
    catch (ParseException e) {
      log.debug("No JSON serialized JWS signature");
    }
    log.warn("Error processing the uploaded JOSE document");
    throw new IOException("Error parsing uploaded JOSE document");
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
      PDDocument document = Loader.loadPDF(bytes);
      // We are not modifying the document, so we close it directly to avoid memory leak
      document.close();
    }
    catch (Exception ex) {
      log.warn("Error processing the uploaded PDF document");
      throw new IOException("Error parsing uploaded PDF document (" + ex.getMessage() + ").");
    }
  }

}
