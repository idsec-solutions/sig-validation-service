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
