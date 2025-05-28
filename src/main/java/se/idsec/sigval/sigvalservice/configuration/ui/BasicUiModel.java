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

package se.idsec.sigval.sigvalservice.configuration.ui;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class BasicUiModel {

  @Getter private final String bootstrapCss;
  @Getter private final String htmlTitle;
  @Getter private final String htmlTitleResult;
  @Getter private final String htmlTitleError;
  @Getter private final String logoUrl;
  @Getter private final String secondaryLogoUrl;
  @Getter private final boolean devmode;

  @Autowired
  public BasicUiModel(
    LogoImages logoImages,
    @Value("${sigval-service.ui.html-title.upload}") String htmlTitle,
    @Value("${sigval-service.ui.html-title.result}") String htmlTitleResult,
    @Value("${sigval-service.ui.html-title.error}") String htmlTitleError,
    @Value("${sigval-service.ui.style}") String style,
    @Value("${sigval-service.ui.devmode}") boolean devmode
  ) {
    this.bootstrapCss = UIStyle.valueOf(style).getBootrapSrc();
    this.htmlTitle = htmlTitle;
    this.htmlTitleResult = htmlTitleResult;
    this.htmlTitleError = htmlTitleError;
    this.logoUrl=logoImages.getLogoUrl();
    this.secondaryLogoUrl = logoImages.getSecondaryLogoUrl();
    this.devmode = devmode;
  }
}
