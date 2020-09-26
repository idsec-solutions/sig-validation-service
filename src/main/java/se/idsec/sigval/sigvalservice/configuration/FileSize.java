package se.idsec.sigval.sigvalservice.configuration;

import lombok.Data;
import lombok.extern.log4j.Log4j2;

@Data
@Log4j2
public class FileSize {

  /** The Spring configuration value, E.g. set by spring.servlet.multipart.max-file-size */
  private final String springConfigValue;
  /** The corresponding integer value */
  private int intValue;
  /** The kilobyte value used by javascript bootstrap-fileinput */
  private int kbValue;

  public FileSize(String springConfigValue) {
    this.springConfigValue = springConfigValue;
    this.intValue = getSize(springConfigValue);
    this.kbValue = intValue/1000;
    log.info("Max file size configuration set to: {}", springConfigValue);
  }

  private int getSize(String springConfigVal) {
    if (springConfigVal.endsWith("GB")) {
      return Integer.valueOf(springConfigVal.substring(0, springConfigVal.length()-2)) * 1000000000;
    }
    if (springConfigVal.endsWith("MB")) {
      return Integer.valueOf(springConfigVal.substring(0, springConfigVal.length()-2)) * 1000000;
    }
    if (springConfigVal.endsWith("KB")) {
      return Integer.valueOf(springConfigVal.substring(0, springConfigVal.length()-2)) * 1000;
    }
    return Integer.valueOf(springConfigVal);
  }
}
