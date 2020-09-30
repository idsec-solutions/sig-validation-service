package se.idsec.sigval.sigvalservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import se.idsec.sigval.sigvalservice.configuration.ui.BasicUiModel;
import se.idsec.sigval.sigvalservice.configuration.ui.UIText;

@Controller
public class ErrorController {

    @Value("${server.servlet.context-path}") String contextPath;

    private final UIText uiText;
    private final BasicUiModel basicUiModel;

    @Autowired
    public ErrorController(BasicUiModel basicUiModel, UIText uiText) {
        this.basicUiModel = basicUiModel;
        this.uiText = uiText;
    }

    @RequestMapping("/404-redirect")
    public String errorRedirect(){
        return "redirect:/404";
    }

    @RequestMapping("/404")
    public String get404Error(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang) {
        model.addAttribute("message", "Begärd tjänst eller sida är ej tillgänglig");
        model.addAttribute("errorCode", "404");
        addModelAttributes(model, lang);
        return "error";
    }

    @RequestMapping("/400")
    public String get400Error(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang) {
        model.addAttribute("message", "Ogitiltig begäran om tjänst");
        model.addAttribute("errorCode", "400");
        addModelAttributes(model, lang);
        return "error";
    }

    @RequestMapping("/500")
    public String get500Error(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang, Exception ex) {
        model.addAttribute("message", "Internt serverfel");
        model.addAttribute("errorCode", "500");
        addModelAttributes(model, lang);
        return "error";
    }

    private void addModelAttributes(Model model, String lang) {
        model.addAttribute("basicModel", basicUiModel);
        model.addAttribute("lang", lang);
        model.addAttribute("text", uiText.getBundle(UIText.UiBundle.resultText, lang));
    }



}
