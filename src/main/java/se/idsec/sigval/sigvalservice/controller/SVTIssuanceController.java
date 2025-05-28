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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
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
import se.swedenconnect.sigval.commons.svt.SVTUtils;
import se.swedenconnect.sigval.pdf.timestamp.issue.impl.PDFDocTimstampProcessor;
import se.swedenconnect.sigval.svt.issuer.SVTModel;
import se.swedenconnect.sigval.xml.utils.XMLDocumentBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@RestController
@Slf4j
public class SVTIssuanceController {

  @Value("${sigval-service.svt.issuer-enabled}") boolean enableSvtIssuer;
  @Value("${sigval-service.svt.default-replace}") boolean defaultReplaceSvt;
  @Value("${sigval-service.ui.downloaded-svt-suffix}") String svtSuffix;
  @Value("${sigval-service.svt.download-attachment:true}") boolean svtAsAttachment;
  @Value("${sigval-service.svt.issue-on-failed-validation:false}") boolean issueSvtOnFailedValidation;

  private final HttpSession httpSession;
  private final SignatureValidatorProvider signatureValidatorProvider;
  private final SVTModel svtModel;
  private final ObjectMapper objectMapper;

  @Autowired
  public SVTIssuanceController(HttpSession httpSession,
    SignatureValidatorProvider signatureValidatorProvider, SVTModel svtModel, ObjectMapper objectMapper) {
    this.httpSession = httpSession;
    this.signatureValidatorProvider = signatureValidatorProvider;
    this.svtModel = svtModel;
    this.objectMapper = objectMapper;
  }

  @RequestMapping("/issue-svt-internal")
  public ResponseEntity<InputStreamResource> issueSvtInternal(
    @RequestParam(name = "replace", required = false) String replace) throws IOException, RuntimeException {
    byte[] documentBytes = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    String name = (String) httpSession.getAttribute(SessionAttr.docName.name());
    return issueSvtFunction(documentBytes, name, replace, svtAsAttachment);
  }

  @RequestMapping(value = "/issue-svt", method = RequestMethod.POST)
  public ResponseEntity<InputStreamResource> issueSvtApi(
    InputStream postedDocumentStream,
    @RequestParam(name = "name", required = false) String name,
    @RequestParam(name = "replace", required = false) String replace) {
    try {
      byte[] documentBytes = postedDocumentStream == null
        ? null
        : IOUtils.toByteArray(postedDocumentStream);
      return issueSvtFunction(documentBytes, name, replace, false);
    }
    catch (IOException e) {
      return ResponseEntity
        .badRequest()
        .body(new InputStreamResource(new ByteArrayInputStream(
          e.getMessage().getBytes(StandardCharsets.UTF_8)
        )));
    }
  }

  public ResponseEntity<InputStreamResource> issueSvtFunction(byte[] documentBytes,
    String name, String replace, boolean attachment) throws IOException, RuntimeException {

    if (documentBytes == null) {
      log.debug("Bad request - no document provided in the request");
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    SVTExtendpolicy svtExtendpolicy;
    if (StringUtils.isNotBlank(replace)) {
      svtExtendpolicy = replace.equalsIgnoreCase("true")
        ? SVTExtendpolicy.REPLACE
        : SVTExtendpolicy.EXTEND;
    }
    else {
      svtExtendpolicy = defaultReplaceSvt
        ? SVTExtendpolicy.REPLACE
        : SVTExtendpolicy.EXTEND;
    }

    byte[] svtEnhancedDocument;
    MediaType mediaType;

    // Generate a report based on document type
    DocType docType = DocType.getDocType(documentBytes);
    switch (docType) {
    case XML:
      try {
        Document xmlDocument = XMLDocumentBuilder.getDocument(documentBytes);
        svtEnhancedDocument = signatureValidatorProvider.getXmlDocumentSVTIssuer()
          .issueSvt(xmlDocument, svtModel, svtExtendpolicy, issueSvtOnFailedValidation);
        mediaType = MediaType.TEXT_XML;
      }
      catch (Exception ex) {
        log.error("Error issuing XML SVT token {}", ex.getMessage());
        throw new IOException(ex.getMessage());
      }
      break;
    case PDF:
      try {
        SignedJWT signedSvtJWT = signatureValidatorProvider.getPdfsvtSigValClaimsIssuer()
          .getSignedSvtJWT(documentBytes, svtModel);
        if (!SVTUtils.checkIfSVTShouldBeIssued(signedSvtJWT, issueSvtOnFailedValidation)) {
          throw new IOException("SVT request for document with invalid signatures");
        }
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
        svtEnhancedDocument = signatureValidatorProvider.getJoseDocumentSVTIssuer()
          .issueSvt(documentBytes, svtModel, svtExtendpolicy, issueSvtOnFailedValidation);
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
      .headers(getHeaders(fileName, attachment))
      .contentLength(svtEnhancedDocument.length)
      .contentType(mediaType)
      .body(new InputStreamResource(new ByteArrayInputStream(svtEnhancedDocument)));
  }

  private HttpHeaders getHeaders(String fileName, boolean attachment) {
    String contentDispHeaderVal = attachment ? "attachment; filename=" : "inline; filename=";
    HttpHeaders headers = new HttpHeaders();
    headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headers.add("content-disposition", contentDispHeaderVal + fileName);
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
