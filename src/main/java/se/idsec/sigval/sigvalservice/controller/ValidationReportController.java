package se.idsec.sigval.sigvalservice.controller;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.sigval.sigvalservice.configuration.SignatureValidatorProvider;
import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.commons.document.DocType;
import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.jose.verify.JOSESignedDocumentValidator;
import se.swedenconnect.sigval.pdf.data.ExtendedPdfSigValResult;
import se.swedenconnect.sigval.pdf.verify.ExtendedPDFSignatureValidator;
import se.swedenconnect.sigval.report.data.SignedDataRepresentation;
import se.swedenconnect.sigval.report.data.SigvalReportOptions;
import se.swedenconnect.sigval.xml.data.ExtendedXmlSigvalResult;
import se.swedenconnect.sigval.xml.verify.ExtendedXMLSignedDocumentValidator;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.SignatureException;

/**
 * Controller for returning signature validation report
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@RestController
public class ValidationReportController {

  private static final MultiValueMap<String,String> headerMap;

  static {
    headerMap = new LinkedMultiValueMap<>();
    headerMap.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headerMap.add("Pragma", "no-cache");
    headerMap.add("Expires", "0");
  }

  @Value("${sigval-service.report.default-include-tschain}") boolean defaultIncludeTsChain;
  @Value("${sigval-service.report.default-include-chain}") boolean defaultIncludeChain;
  @Value("${sigval-service.report.default-include-siged-doc}") boolean defaultIncludeSignedDoc;

  private final SignatureValidatorProvider signatureValidatorProvider;

  @Autowired
  public ValidationReportController(SignatureValidatorProvider signatureValidatorProvider) {
    this.signatureValidatorProvider = signatureValidatorProvider;
  }

  @RequestMapping("/report")
  public ResponseEntity<InputStreamResource> getValidationReport(
    @RequestParam(name = "certpath", required = false) String certpath,
    @RequestParam(name = "include-docs", required = false) String includeDocs,
    @RequestParam(name = "id", required = false) String id,
    @RequestParam(name = "document", required = false) String document,
    HttpEntity<byte[]> requestPayload,
    HttpServletRequest request
  ) throws SignatureException, IOException {
    byte[] documentBytes = null;
/*
    if (requestPayload != null && requestPayload.getBody() != null && requestPayload.getBody().length > 0){
      documentBytes = requestPayload.getBody();
    } else {
    }
*/
    if (document != null) {
      try {
        documentBytes = Base64.decode(document);
      } catch (Exception ex) {
        log.debug("Illegal document data");
      }
    }

    if (documentBytes == null){
      log.debug("Bad request - no document provided in the request");
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    SigvalReportOptions sigvalReportOptions = getSigValReportOptions(certpath, includeDocs);
    String requestId = id;
    byte[] signedValidationReport;

    // Generate report based on document type
    DocType docType = DocType.getDocType(documentBytes);
    switch (docType) {
    case XML:
      ExtendedXMLSignedDocumentValidator xmlSignedDocumentValidator = signatureValidatorProvider.getXmlSignedDocumentValidator();
      SignedDocumentValidationResult<ExtendedXmlSigvalResult> xmlResult = xmlSignedDocumentValidator.extendedResultValidation(
        DOMUtils.bytesToDocument(documentBytes));
      signedValidationReport = signatureValidatorProvider.getXmlSigValReportGenerator().getSignedValidationReport(
        xmlResult, sigvalReportOptions, requestId, signatureValidatorProvider.getReportSigner());
      break;
    case PDF:
      ExtendedPDFSignatureValidator pdfSignatureValidator = signatureValidatorProvider.getPdfSignatureValidator();
      SignedDocumentValidationResult<ExtendedPdfSigValResult> pdfResult = pdfSignatureValidator.extendedResultValidation(
        documentBytes);
      signedValidationReport = signatureValidatorProvider.getPdfSigValReportGenerator().getSignedValidationReport(
        pdfResult, sigvalReportOptions, requestId, signatureValidatorProvider.getReportSigner());
      break;
    case JOSE:
    case JOSE_COMPACT:
      JOSESignedDocumentValidator joseSignedDocumentValidator = signatureValidatorProvider.getJoseSignedDocumentValidator();
      SignedDocumentValidationResult<ExtendedJOSESigvalResult> joseResult = joseSignedDocumentValidator.extendedResultValidation(
        documentBytes);
      signedValidationReport = signatureValidatorProvider.getJoseSigValReportGenerator().getSignedValidationReport(
        joseResult, sigvalReportOptions, requestId, signatureValidatorProvider.getReportSigner());
      break;
    default:
      log.debug("Bad request - data type not recognized");
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    return ResponseEntity
      .ok()
      .headers(new HttpHeaders(headerMap))
      .contentLength(signedValidationReport.length)
      .contentType(MediaType.parseMediaType("text/xml"))
      .body(new InputStreamResource(new ByteArrayInputStream(signedValidationReport)));
  }

  private SigvalReportOptions getSigValReportOptions(String certpath, String includeDocs) {

    boolean includeCertPath = defaultIncludeChain;
    boolean includeTsChain = defaultIncludeTsChain;
    boolean includeSignedData = defaultIncludeSignedDoc;

    if (certpath != null) {
      if (certpath.equalsIgnoreCase("true")){
        includeCertPath = true;
      }
      if (certpath.equalsIgnoreCase("false")){
        includeCertPath = false;
      }
    }

    if (includeDocs != null) {
      if (includeDocs.equalsIgnoreCase("true")){
        includeSignedData = true;
      }
      if (includeDocs.equalsIgnoreCase("fasle")){
        includeSignedData = false;
      }
    }

    SignedDataRepresentation signedDataRepresentation = includeSignedData
      ? SignedDataRepresentation.DIRECT
      : SignedDataRepresentation.DIGEST;

    return new SigvalReportOptions(includeTsChain, includeCertPath, signedDataRepresentation);
  }

}
