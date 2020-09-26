package se.idsec.sigval.sigvalservice.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class TestController {

  @RequestMapping("/test")
  public String getMainPage(){
    return "main";
  }

}
