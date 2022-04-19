/*
 * Copyright (c) 2022. IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.idsec.sigval.sigvalservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import se.idsec.sigval.sigvalservice.configuration.ui.BasicUiModel;
import se.idsec.sigval.sigvalservice.configuration.ui.UIText;

import java.io.IOException;

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
