package se.idsec.sigval.sigvalservice.result.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.sigval.sigvalservice.result.DisplayAttribute;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResultSignatureData {

  private SigValidStatus status;
  private boolean coversAllData;
  private boolean svt;
  private String idp;
  private String signingTime;
  private String loa;
  private String assertionRef;
  private String serviceProvider;
  List<DisplayAttribute> signerAttribute;

}
