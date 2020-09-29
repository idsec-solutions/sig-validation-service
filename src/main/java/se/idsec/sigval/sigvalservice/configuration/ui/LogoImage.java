package se.idsec.sigval.sigvalservice.configuration.ui;

import lombok.Getter;
import lombok.extern.java.Log;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.logging.Level;

@Log
public class LogoImage {

  @Getter
  private String dataUrl;

  public LogoImage(String source) {
    if (source == null) return;
    if (source.toLowerCase().startsWith("classpath:")){
      init (new File(getClass().getClassLoader().getResource("static/" + source.substring(10)).getFile()));
      return;
    }
    if (source.toLowerCase().startsWith("file://")){
      init (new File(source.substring(7)));
      return;
    }
    init (new File(source));
  }

  public LogoImage(File logoFile) {
    init(logoFile);
  }

  public void init(File logoFile) {
    try {
      byte[] logoBytes = IOUtils.toByteArray(new FileInputStream(logoFile));
      String logoFileName = logoFile.getName();
      String ext = logoFileName.substring(logoFileName.lastIndexOf(".") +1);
      switch (ext.toLowerCase()){
      case "png":
        dataUrl = "data:image/png;base64," + Base64.toBase64String(logoBytes);
        break;
      case "svg":
        dataUrl = "data:image/svg+xml;base64," + Base64.toBase64String(logoBytes);
      }
    }
    catch (IOException e) {
      log.log(Level.SEVERE, "Unable to read logo file at: " + logoFile.getAbsolutePath(), e);
    }

  }
}
