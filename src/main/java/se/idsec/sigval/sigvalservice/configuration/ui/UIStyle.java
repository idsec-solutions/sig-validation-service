package se.idsec.sigval.sigvalservice.configuration.ui;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum UIStyle {

  main("css/bootstrap.min.css"),
  edusign("css/bootstrap-edusign.min.css"),
  sunet("css/bootstrap-sunet.min.css");

  String bootrapSrc;

}
