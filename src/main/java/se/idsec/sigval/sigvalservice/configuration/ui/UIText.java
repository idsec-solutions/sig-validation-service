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
