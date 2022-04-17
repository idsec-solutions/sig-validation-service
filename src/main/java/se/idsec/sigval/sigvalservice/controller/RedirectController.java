package se.idsec.sigval.sigvalservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import se.swedenconnect.sigval.commons.document.DocType;

import javax.servlet.http.HttpSession;

@Controller
public class RedirectController {

  private final HttpSession httpSession;

  @Autowired
  public RedirectController(HttpSession httpSession) {
    this.httpSession = httpSession;
  }

  @RequestMapping("/issue-svt")
  public String redirectToSvtIssuingService(){

    DocType docType = (DocType) httpSession.getAttribute(SessionAttr.docType.name());
    if  (docType == null) return "redirect:/";
    switch (docType) {

    case XML:
      return "redirect:/xmlsvt";
    case PDF:
      return "redirect:/pdfsvt";
    }
    return "redirect:/";
  }

  @RequestMapping("/home")
  public String langSelect(){
    return "redirect:/";
  }

}
