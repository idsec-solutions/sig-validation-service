package se.idsec.sigval.sigvalservice.controller;

import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import se.swedenconnect.sigval.commons.document.DocType;

import javax.servlet.http.HttpSession;

@Controller
@NoArgsConstructor
public class RedirectController {

  //private final HttpSession httpSession;


/*
  @RequestMapping("/issue-svt-legacy")
  public String redirectToSvtIssuingService(){

    DocType docType = (DocType) httpSession.getAttribute(SessionAttr.docType.name());
    if  (docType == null) return "redirect:/";
    switch (docType) {

    case XML:
      return "redirect:/xmlsvt";
    case PDF:
      return "redirect:/pdfsvt";
    case JOSE:
    case JOSE_COMPACT:
      return "redirect:/josesvt";
    }
    return "redirect:/";
  }
*/

  @RequestMapping("/home")
  public String langSelect(){
    return "redirect:/";
  }

}
