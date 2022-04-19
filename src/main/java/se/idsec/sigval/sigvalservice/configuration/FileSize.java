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
