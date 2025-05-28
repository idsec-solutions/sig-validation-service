/*
 * Copyright 2022-2025 IDsec Solutions AB
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
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import se.idsec.sigval.sigvalservice.configuration.ui.BasicUiModel;

import java.io.IOException;

/**
 * Handling exceptions
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@RestController
public class ExceptionController {

  private final BasicUiModel basicUiModel;

  @Autowired
  public ExceptionController(BasicUiModel basicUiModel) {
    this.basicUiModel = basicUiModel;
  }

  @ExceptionHandler({ IOException.class, RuntimeException.class})
  public ModelAndView handleIOException(Exception ex){
    ModelAndView mav = new ModelAndView();
    mav.addObject("message", ex.getMessage());
    mav.addObject("basicModel", basicUiModel);
    mav.setViewName("error");
    return mav;
  }


}
