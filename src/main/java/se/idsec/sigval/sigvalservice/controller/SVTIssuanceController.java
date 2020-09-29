package se.idsec.sigval.sigvalservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;
import se.idsec.sigval.sigvalservice.configuration.FileSize;
import se.idsec.sigval.sigvalservice.configuration.SignatureValidatorProvider;
import se.idsec.sigval.svt.issuer.SVTModel;

import javax.servlet.http.HttpSession;

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




}
