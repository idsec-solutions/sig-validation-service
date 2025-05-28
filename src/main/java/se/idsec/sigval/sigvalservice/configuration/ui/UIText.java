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

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.ResourceBundle;

@Component
public class UIText extends ResourceBundleMessageSource{

  public UIText() {
    this.setBasenames(
      UiBundle.infoText.getBaseName(),
      UiBundle.reportText.getBaseName(),
      UiBundle.resultText.getBaseName(),
      UiBundle.samlAttr.getBaseName(),
      UiBundle.x509Attr.getBaseName()
    );
  }

  public UTF8Bundle getBundle(UiBundle bundle, String lang){
    return new UTF8Bundle(getResourceBundle(bundle.baseName, new Locale(lang)));
  }

  @AllArgsConstructor
  @Getter
  public enum UiBundle {

    infoText("lang/infoText"),
    reportText("lang/reportText"),
    resultText("lang/resultPageText"),
    samlAttr("lang/samlAttrName"),
    x509Attr("lang/x509AttrName");

    String baseName;
  }

  @AllArgsConstructor
  public static class UTF8Bundle{

    private final ResourceBundle bundle;

    public String getString(String key){
      return UIUtils.fromIso(bundle.getString(key));
    }

  }

}
