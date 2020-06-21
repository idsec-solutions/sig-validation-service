package se.idsec.sigval.sigvalservice.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class MainController {

  @RequestMapping("/main")
  public String getMainPage(){
    return "main";
  }

}
