package se.idsec.sigval.sigvalservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import se.idsec.sigval.sigvalservice.configuration.ui.LogoImages;
import se.idsec.sigval.sigvalservice.configuration.ui.UIStyle;
import se.idsec.sigval.sigvalservice.configuration.ui.UIText;

import javax.servlet.http.HttpServletRequest;

@Controller
public class ErrorController {

    @Value("${server.servlet.context-path}") String contextPath;
    @Value("${sigval-service.ui.html-title.error}") String htmlTitleError;
    @Value("${sigval-service.ui.style}") String style;
    @Value("${sigval-service.ui.devmode}") boolean devmode;

    private final LogoImages logoImages;
    private final UIText uiText;

    @Autowired
    public ErrorController(LogoImages logoImages, UIText uiText) {
        this.logoImages = logoImages;
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
    public String get500Error(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang) {
        model.addAttribute("message", "Uppladdat dokument kunde inte hanteras");
        model.addAttribute("errorCode", "500");
        addModelAttributes(model, lang);
        return "error";
    }

    private void addModelAttributes(Model model, String lang) {
        model.addAttribute("bootstrapCss", UIStyle.valueOf(style).getBootrapSrc());
        model.addAttribute("htmlTitle", htmlTitleError);
        model.addAttribute("logoUrl", logoImages.getLogoUrl());
        model.addAttribute("secondaryLogoUrl", logoImages.getSecondaryLogoUrl());
        model.addAttribute("devmode", devmode);
        model.addAttribute("lang", lang);
        model.addAttribute("text", uiText.getBundle(UIText.UiBundle.resultText, lang));
    }



}
