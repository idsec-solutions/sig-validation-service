package se.idsec.sigval.sigvalservice.controller;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.idsec.sigval.sigvalservice.controller.form.FormParameter;

import javax.servlet.http.HttpSession;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * This controller is used by the view pages to request a POST form to send an API request to the service
 *
 * This is used to send an API request that normally is sent directly from a requesting client. Two types of request forms
 * can be requested: Validation report request and SVT enhanced signed document request.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Controller
@Slf4j
public class FormPostController {

  private final HttpSession httpSession;
  private static final Random RNG = new SecureRandom();

  public FormPostController(HttpSession httpSession) {
    this.httpSession = httpSession;
  }

  @RequestMapping("/report-request-form")
  public String getReportRequestForm(Model model,
    @RequestParam(name = "certpath", required = false) String certpath,
    @RequestParam(name = "include-docs", required = false) String includeDocs
    ) {
    byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());

    List<FormParameter> formParameterList = new ArrayList<>();
    if (certpath != null){
      formParameterList.add(new FormParameter("certpath",certpath));
    }
    if (includeDocs != null) {
      formParameterList.add(new FormParameter("include-docs",includeDocs));
    }
    formParameterList.add(new FormParameter("id", new BigInteger(128, RNG).toString(16)));

    model.addAttribute("targetUrl", "report");
    model.addAttribute("dataObjectName","document");
    model.addAttribute("b64Data", Base64.toBase64String(signedDoc));
    model.addAttribute("formParams", formParameterList);

    return "post-form";

  }


}
