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
  private String errorMessage;
  private boolean coversAllData;
  private boolean svt;
  private boolean signedDataAvailable;
  private String idp;
  private String signingTime;
  private String loa;
  private String assertionRef;
  private String serviceProvider;
  private String timeStampTime;
  private String timeStampType;
  List<DisplayAttribute> signerAttribute;

}
