package se.idsec.sigval.sigvalservice.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import se.swedenconnect.sigval.commons.algorithms.JWSAlgorithmRegistry;
import se.swedenconnect.sigval.commons.algorithms.PublicKeyType;
import se.swedenconnect.sigval.commons.timestamp.TimeStampPolicyVerifier;
import se.swedenconnect.sigval.commons.timestamp.impl.BasicTimstampPolicyVerifier;
import se.swedenconnect.sigval.commons.utils.GeneralCMSUtils;
import se.swedenconnect.sigval.jose.policy.JOSESignaturePolicyValidator;
import se.swedenconnect.sigval.jose.policy.impl.PkixJOSESignaturePolicyValidator;
import se.swedenconnect.sigval.jose.svt.JOSEDocumentSVTIssuer;
import se.swedenconnect.sigval.jose.svt.JOSESVTSigValClaimsIssuer;
import se.swedenconnect.sigval.jose.svt.JOSESVTValidator;
import se.swedenconnect.sigval.jose.verify.DefalutJOSESigValReportGenerator;
import se.swedenconnect.sigval.jose.verify.JOSESignatureDataValidator;
import se.swedenconnect.sigval.jose.verify.JOSESignatureDataValidatorImpl;
import se.swedenconnect.sigval.jose.verify.JOSESignedDocumentValidator;
import se.swedenconnect.sigval.pdf.pdfstruct.impl.DefaultPDFSignatureContextFactory;
import se.swedenconnect.sigval.pdf.svt.PDFSVTSigValClaimsIssuer;
import se.swedenconnect.sigval.pdf.svt.PDFSVTValidator;
import se.swedenconnect.sigval.pdf.timestamp.issue.impl.DefaultPDFDocTimestampSignatureInterface;
import se.swedenconnect.sigval.pdf.verify.ExtendedPDFSignatureValidator;
import se.swedenconnect.sigval.pdf.verify.PDFSingleSignatureValidator;
import se.swedenconnect.sigval.pdf.verify.impl.DefalutPDFSigValReportGenerator;
import se.swedenconnect.sigval.pdf.verify.impl.PDFSingleSignatureValidatorImpl;
import se.swedenconnect.sigval.pdf.verify.impl.SVTenabledPDFDocumentSigVerifier;
import se.swedenconnect.sigval.pdf.verify.policy.PDFSignaturePolicyValidator;
import se.swedenconnect.sigval.pdf.verify.policy.impl.PkixPdfSignaturePolicyValidator;
import se.idsec.sigval.sigvalservice.configuration.keys.LocalKeySource;
import se.swedenconnect.sigval.report.xml.ReportSigner;
import se.swedenconnect.sigval.svt.algorithms.SVTAlgoRegistry;
import se.swedenconnect.sigval.xml.policy.XMLSignaturePolicyValidator;
import se.swedenconnect.sigval.xml.policy.impl.PkixXmlSignaturePolicyValidator;
import se.swedenconnect.sigval.xml.svt.XMLDocumentSVTIssuer;
import se.swedenconnect.sigval.xml.svt.XMLSVTSigValClaimsIssuer;
import se.swedenconnect.sigval.xml.svt.XMLSVTValidator;
import se.swedenconnect.sigval.xml.verify.ExtendedXMLSignedDocumentValidator;
import se.swedenconnect.sigval.xml.verify.XMLSignatureElementValidator;
import se.swedenconnect.sigval.xml.verify.impl.DefalutXMLSigValReportGenerator;
import se.swedenconnect.sigval.xml.verify.impl.XMLSignatureElementValidatorImpl;
import se.swedenconnect.sigval.xml.verify.impl.XMLSignedDocumentValidator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

@Component
@Slf4j
public class SignatureValidatorProvider {

  public static final String SVT_KEYSOURCE = "svt";
  public static final String REPORT_KEYSOURCE = "report";

  private final CertificateValidators certValidators;
  private final Map<String, LocalKeySource> keySourceMap;

  @Value("${sigval-service.svt.model.sig-algo}") String svtSigAlgo;
  @Value("${sigval-service.svt.timestamp.policy:#{null}}") String timestampPolicy;
  @Value("${sigval-service.svt.validator-enabled}") boolean enableSvtValidation;
  @Value("${sigval-service.validator.strict-pdf-context}") boolean strictPdfContextFactory;
  @Value("${sigval-service.report.default-digest-algorithm}") String defaultSigValReportDigestAlgorithm;

  @Getter private DefaultPDFDocTimestampSignatureInterface svtTsSigner;
  @Getter private PDFSVTSigValClaimsIssuer pdfsvtSigValClaimsIssuer;
  @Getter private ExtendedPDFSignatureValidator pdfSignatureValidator;
  @Getter private DefalutPDFSigValReportGenerator pdfSigValReportGenerator;
  @Getter private XMLDocumentSVTIssuer xmlDocumentSVTIssuer;
  @Getter private ExtendedXMLSignedDocumentValidator xmlSignedDocumentValidator;
  @Getter private XMLSignatureElementValidator xmlSignatureElementValidator;
  @Getter private DefalutXMLSigValReportGenerator xmlSigValReportGenerator;
  @Getter private JOSEDocumentSVTIssuer joseDocumentSVTIssuer;
  @Getter private JOSESignedDocumentValidator joseSignedDocumentValidator;
  @Getter private JOSESignatureDataValidator joseSignatureDataValidator;
  @Getter private DefalutJOSESigValReportGenerator joseSigValReportGenerator;

  @Getter ReportSigner reportSigner;

  private TimeStampPolicyVerifier timeStampPolicyVerifier;
  private JWSAlgorithm svtJWSAlgorithm;


  @Autowired
  public SignatureValidatorProvider(CertificateValidators certValidators, Map<String, LocalKeySource> keySourceMap) {
    this.certValidators = certValidators;
    this.keySourceMap = keySourceMap;
  }

  public void loadValidators() throws JOSEException, NoSuchAlgorithmException, IOException, CertificateException {
    certValidators.loadValidators();
    svtJWSAlgorithm = jwsAlgorithm();
    timeStampPolicyVerifier = timeStampPolicyVerifier();
    xmlSignatureElementValidator = xmlSignatureElementValidator();
    xmlSignedDocumentValidator = xmlSignedDocumentValidator();
    xmlDocumentSVTIssuer = xmlDocumentSVTIssuer();
    pdfSignatureValidator = pdfSignatureValidator();
    pdfsvtSigValClaimsIssuer = pdfsvtSigValClaimsIssuer();
    joseSignatureDataValidator = joseSignatureDataValidator();
    joseSignedDocumentValidator = joseSignedDocumentValidator();
    joseDocumentSVTIssuer = joseDocumentSVTIssuer();
    pdfSigValReportGenerator = pdfSigValReportGenerator();
    xmlSigValReportGenerator = xmlSigValReportGenerator();
    joseSigValReportGenerator = joseSigValReportGenerator();
    svtTsSigner = svtTsSigner();
    reportSigner = reportSigner();
  }

  private ReportSigner reportSigner() {
    return new ReportSigner(keySourceMap.get(REPORT_KEYSOURCE).getCredential().getPrivateKey(),
      new ArrayList<>(keySourceMap.get(REPORT_KEYSOURCE).getCredential().getEntityCertificateChain()));
  }

  private DefalutXMLSigValReportGenerator xmlSigValReportGenerator() {
    return new DefalutXMLSigValReportGenerator(defaultSigValReportDigestAlgorithm);
  }

  private DefalutJOSESigValReportGenerator joseSigValReportGenerator() {
    return new DefalutJOSESigValReportGenerator(defaultSigValReportDigestAlgorithm);
  }

  private DefalutPDFSigValReportGenerator pdfSigValReportGenerator() {
    return new DefalutPDFSigValReportGenerator(defaultSigValReportDigestAlgorithm);
  }

  private JOSESignatureDataValidator joseSignatureDataValidator() {
    JOSESignaturePolicyValidator joseSignaturePolicyValidator = new PkixJOSESignaturePolicyValidator();

    return new JOSESignatureDataValidatorImpl(
      certValidators.getSignatureCertificateValidator(),
      joseSignaturePolicyValidator,
      timeStampPolicyVerifier,
      enableSvtValidation ? new JOSESVTValidator(certValidators.getSvtCertificateValidator()) : null
    );

  }

  private JOSESignedDocumentValidator joseSignedDocumentValidator() {
    return new JOSESignedDocumentValidator(joseSignatureDataValidator);
  }

  private JOSEDocumentSVTIssuer joseDocumentSVTIssuer() throws NoSuchAlgorithmException, JOSEException {
    JOSESVTSigValClaimsIssuer claimsIssuer = new JOSESVTSigValClaimsIssuer(
      svtJWSAlgorithm,
      Objects.requireNonNull(keySourceMap.get(SVT_KEYSOURCE).getCredential().getPrivateKey()),
      Collections.singletonList(keySourceMap.get(SVT_KEYSOURCE).getCredential().getEntityCertificate()),
      joseSignatureDataValidator
    );
    return new JOSEDocumentSVTIssuer(claimsIssuer);
  }

  private DefaultPDFDocTimestampSignatureInterface svtTsSigner() {
    DefaultPDFDocTimestampSignatureInterface timeStampSigner = new DefaultPDFDocTimestampSignatureInterface(
      keySourceMap.get(SVT_KEYSOURCE).getCredential().getPrivateKey(),
      Collections.singletonList(keySourceMap.get(SVT_KEYSOURCE).getCredential().getEntityCertificate()),
      SVTAlgoRegistry.getAlgoParams(svtJWSAlgorithm).getSigAlgoId());
    if (StringUtils.isNotEmpty(timestampPolicy)){
      timeStampSigner.setTimeStampPolicyOid(new ASN1ObjectIdentifier(timestampPolicy));
    }
    return timeStampSigner;
  }

  PDFSVTSigValClaimsIssuer pdfsvtSigValClaimsIssuer() throws NoSuchAlgorithmException, JOSEException {
    return new PDFSVTSigValClaimsIssuer(
      svtJWSAlgorithm,
      Objects.requireNonNull(keySourceMap.get(SVT_KEYSOURCE).getCredential().getPrivateKey()),
      Collections.singletonList(keySourceMap.get(SVT_KEYSOURCE).getCredential().getEntityCertificate()),
      pdfSignatureValidator);
  }


  private ExtendedPDFSignatureValidator pdfSignatureValidator() {
    PDFSignaturePolicyValidator signaturePolicyValidator = new PkixPdfSignaturePolicyValidator();
    PDFSingleSignatureValidator pdfSignatureVerifier = new PDFSingleSignatureValidatorImpl(
      certValidators.getSignatureCertificateValidator(), signaturePolicyValidator,
      timeStampPolicyVerifier);

    // Setup SVA validator
    PDFSVTValidator pdfsvtValidator = new PDFSVTValidator(certValidators.getSvtCertificateValidator(), timeStampPolicyVerifier);

    DefaultPDFSignatureContextFactory pdfContextFactory = new DefaultPDFSignatureContextFactory();
    pdfContextFactory.setStrict(strictPdfContextFactory);

    // Get the pdf validator
    return new SVTenabledPDFDocumentSigVerifier(
      pdfSignatureVerifier,
      enableSvtValidation ? pdfsvtValidator : null,
      pdfContextFactory);
  }


  public XMLDocumentSVTIssuer xmlDocumentSVTIssuer() throws JOSEException, NoSuchAlgorithmException {
    XMLSVTSigValClaimsIssuer claimsIssuer = new XMLSVTSigValClaimsIssuer(
      svtJWSAlgorithm,
      Objects.requireNonNull(keySourceMap.get(SVT_KEYSOURCE).getCredential().getPrivateKey()),
      Collections.singletonList(keySourceMap.get(SVT_KEYSOURCE).getCredential().getEntityCertificate()),
      xmlSignatureElementValidator
    );
    return new XMLDocumentSVTIssuer(claimsIssuer);
  }

  private JWSAlgorithm jwsAlgorithm() throws IOException, NoSuchAlgorithmException {
    JWSAlgorithm svtJWSSigAlgorithm = JWSAlgorithmRegistry.get(svtSigAlgo);
    SVTAlgoRegistry.AlgoProperties svtAlgoParams = SVTAlgoRegistry.getAlgoParams(svtJWSSigAlgorithm);
    PublicKeyType pkType = GeneralCMSUtils.getPkParams(keySourceMap.get(SVT_KEYSOURCE).getCertificate().getPublicKey()).getPkType();

    // Check consistency with SVT key type
    switch (pkType){
    case EC:
      if (svtAlgoParams.getType().equals(JWSAlgorithm.Family.EC)) return svtJWSSigAlgorithm;
      break;
    case RSA:
      if (svtAlgoParams.getType().equals(JWSAlgorithm.Family.RSA)) return svtJWSSigAlgorithm;
    }

    throw new NoSuchAlgorithmException("The selected algorithm does not match the provided SVT signing key");
  }


  public ExtendedXMLSignedDocumentValidator xmlSignedDocumentValidator() {
    return new XMLSignedDocumentValidator(xmlSignatureElementValidator);
  }

  private XMLSignatureElementValidator xmlSignatureElementValidator(){
    XMLSignaturePolicyValidator xmlSignaturePolicyValidator = new PkixXmlSignaturePolicyValidator();

    return new XMLSignatureElementValidatorImpl(
      certValidators.getSignatureCertificateValidator(),
      xmlSignaturePolicyValidator,
      timeStampPolicyVerifier,
      enableSvtValidation ? new XMLSVTValidator(certValidators.getSvtCertificateValidator(), certValidators.getKidMatchCerts()) : null
    );
  }

  private TimeStampPolicyVerifier timeStampPolicyVerifier() {
    return new BasicTimstampPolicyVerifier(certValidators.getTimestampCertificateValidator());
  }

}
