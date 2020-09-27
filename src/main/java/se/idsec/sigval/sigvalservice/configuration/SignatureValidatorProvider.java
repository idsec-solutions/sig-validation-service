package se.idsec.sigval.sigvalservice.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import se.idsec.sigval.commons.algorithms.JWSAlgorithmRegistry;
import se.idsec.sigval.commons.algorithms.PublicKeyType;
import se.idsec.sigval.commons.timestamp.TimeStampPolicyVerifier;
import se.idsec.sigval.commons.timestamp.impl.BasicTimstampPolicyVerifier;
import se.idsec.sigval.commons.utils.GeneralCMSUtils;
import se.idsec.sigval.pdf.pdfstruct.impl.DefaultPDFSignatureContextFactory;
import se.idsec.sigval.pdf.svt.PDFSVTSigValClaimsIssuer;
import se.idsec.sigval.pdf.svt.PDFSVTValidator;
import se.idsec.sigval.pdf.verify.ExtendedPDFSignatureValidator;
import se.idsec.sigval.pdf.verify.PDFSingleSignatureValidator;
import se.idsec.sigval.pdf.verify.impl.PDFSingleSignatureValidatorImpl;
import se.idsec.sigval.pdf.verify.impl.SVTenabledPDFDocumentSigVerifier;
import se.idsec.sigval.pdf.verify.policy.PDFSignaturePolicyValidator;
import se.idsec.sigval.pdf.verify.policy.impl.PkixPdfSignaturePolicyValidator;
import se.idsec.sigval.sigvalservice.configuration.keys.LocalKeySource;
import se.idsec.sigval.svt.algorithms.SVTAlgoRegistry;
import se.idsec.sigval.xml.policy.XMLSignaturePolicyValidator;
import se.idsec.sigval.xml.policy.impl.PkixXmlSignaturePolicyValidator;
import se.idsec.sigval.xml.svt.XMLDocumentSVTIssuer;
import se.idsec.sigval.xml.svt.XMLSVTSigValClaimsIssuer;
import se.idsec.sigval.xml.svt.XMLSVTValidator;
import se.idsec.sigval.xml.verify.ExtendedXMLSignedDocumentValidator;
import se.idsec.sigval.xml.verify.XMLSignatureElementValidator;
import se.idsec.sigval.xml.verify.impl.XMLSignatureElementValidatorImpl;
import se.idsec.sigval.xml.verify.impl.XMLSignedDocumentValidator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Objects;

@Component
@Slf4j
public class SignatureValidatorProvider {

  private final CertificateValidators certValidators;
  private final LocalKeySource svtKeySource;

  @Value("${sigval-service.svt.model.sig-algo}") String svtSigAlgo;

  @Getter private PDFSVTSigValClaimsIssuer pdfsvtSigValClaimsIssuer;
  @Getter private ExtendedPDFSignatureValidator pdfSignatureValidator;
  @Getter private XMLDocumentSVTIssuer xmlDocumentSVTIssuer;
  @Getter private ExtendedXMLSignedDocumentValidator xmlSignedDocumentValidator;
  @Getter private XMLSignatureElementValidator xmlSignatureElementValidator;

  private TimeStampPolicyVerifier timeStampPolicyVerifier;
  private JWSAlgorithm svtJWSAlgorithm;


  @Autowired
  public SignatureValidatorProvider(CertificateValidators certValidators, LocalKeySource svtKeySource) {
    this.certValidators = certValidators;
    this.svtKeySource = svtKeySource;
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
  }

  PDFSVTSigValClaimsIssuer pdfsvtSigValClaimsIssuer() throws NoSuchAlgorithmException, JOSEException {
    return new PDFSVTSigValClaimsIssuer(
      svtJWSAlgorithm,
      Objects.requireNonNull(svtKeySource.getCredential().getPrivateKey()),
      Collections.singletonList(svtKeySource.getCredential().getEntityCertificate()),
      pdfSignatureValidator);
  }


  private ExtendedPDFSignatureValidator pdfSignatureValidator() {
    PDFSignaturePolicyValidator signaturePolicyValidator = new PkixPdfSignaturePolicyValidator();
    PDFSingleSignatureValidator pdfSignatureVerifier = new PDFSingleSignatureValidatorImpl(
      certValidators.getSignatureCertificateValidator(), signaturePolicyValidator,
      timeStampPolicyVerifier);

    // Setup SVA validator
    PDFSVTValidator pdfsvtValidator = new PDFSVTValidator(certValidators.getSvtCertificateValidator(), timeStampPolicyVerifier);

    // Get the pdf validator
    return new SVTenabledPDFDocumentSigVerifier(pdfSignatureVerifier, pdfsvtValidator, new DefaultPDFSignatureContextFactory());
  }


  public XMLDocumentSVTIssuer xmlDocumentSVTIssuer() throws JOSEException, NoSuchAlgorithmException {
    XMLSVTSigValClaimsIssuer claimsIssuer = new XMLSVTSigValClaimsIssuer(
      svtJWSAlgorithm,
      Objects.requireNonNull(svtKeySource.getCredential().getPrivateKey()),
      Collections.singletonList(svtKeySource.getCredential().getEntityCertificate()),
      xmlSignatureElementValidator
    );
    return new XMLDocumentSVTIssuer(claimsIssuer);
  }

  private JWSAlgorithm jwsAlgorithm() throws IOException, NoSuchAlgorithmException {
    JWSAlgorithm svtJWSSigAlgorithm = JWSAlgorithmRegistry.get(svtSigAlgo);
    SVTAlgoRegistry.AlgoProperties svtAlgoParams = SVTAlgoRegistry.getAlgoParams(svtJWSSigAlgorithm);
    PublicKeyType pkType = GeneralCMSUtils.getPkParams(svtKeySource.getCertificate().getPublicKey()).getPkType();

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
      certValidators.getSignatureCertificateValidator(), xmlSignaturePolicyValidator, timeStampPolicyVerifier,
      new XMLSVTValidator(certValidators.getSvtCertificateValidator(), certValidators.getKidMatchCerts())
    );
  }

  private TimeStampPolicyVerifier timeStampPolicyVerifier() {
    return new BasicTimstampPolicyVerifier(certValidators.getTimestampCertificateValidator());
  }

}
