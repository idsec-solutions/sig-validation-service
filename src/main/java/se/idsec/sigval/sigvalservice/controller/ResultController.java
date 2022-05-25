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

package se.idsec.sigval.sigvalservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.xml.sax.SAXException;
import se.idsec.sigval.sigvalservice.configuration.ui.BasicUiModel;
import se.idsec.sigval.sigvalservice.configuration.ui.UIText;
import se.idsec.sigval.sigvalservice.result.ResultPageDataGenerator;
import se.idsec.sigval.sigvalservice.result.data.ResultPageData;
import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;
import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.commons.document.DocType;
import se.swedenconnect.sigval.xml.utils.XMLDocumentBuilder;

import javax.servlet.http.HttpSession;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Controller
public class ResultController {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  @Value("${sigval-service.ui.issue-svt-if-svt-exist}") boolean issueSvtIfExists;
  @Value("${sigval-service.ui.enalbe-signed-data-view}") boolean enableSignedDataView;
  @Value("${sigval-service.ui.show-loa}") boolean showLoa;
  @Value("${sigval-service.svt.issuer-enabled}") boolean enableSvtIssuer;
  @Value("${sigval-service.ui.show-report-options}") boolean showReportOptions;

  private final UIText uiText;
  private final HttpSession httpSession;
  private final ResultPageDataGenerator resultPageDataGenerator;
  private final BasicUiModel basicUiModel;


  public ResultController(UIText uiText, HttpSession httpSession, BasicUiModel basicUiModel, ResultPageDataGenerator resultPageDataGenerator) {
    this.uiText = uiText;
    this.httpSession = httpSession;
    this.basicUiModel = basicUiModel;
    this.resultPageDataGenerator = resultPageDataGenerator;
  }

  @RequestMapping("/result")
  public String getResultPage(Model model, @CookieValue(name = "langSelect", defaultValue = "sv") String lang)
    throws ParserConfigurationException, SAXException, IOException {

    byte[] signedDoc = (byte[]) httpSession.getAttribute(SessionAttr.signedDoc.name());
    String docMimeType = (String) httpSession.getAttribute(SessionAttr.docMimeType.name());
    String docName = (String) httpSession.getAttribute(SessionAttr.docName.name());
    DocType docType = (DocType) httpSession.getAttribute(SessionAttr.docType.name());
    SignedDocumentValidationResult<? extends ExtendedSigValResult> validationResult =
      (SignedDocumentValidationResult<? extends ExtendedSigValResult>) httpSession.getAttribute(SessionAttr.validationResult.name());

    if (validationResult == null) return "redirect:/";
      ResultPageData resultPageData = resultPageDataGenerator.getResultPageData(validationResult, docName, docMimeType, lang);

    String xmlPrettyPrint = docType.equals(DocType.XML) ? XMLDocumentBuilder.getDocText(XMLDocumentBuilder.getDocument(signedDoc)) : null;

    String jsonPrettyPrint = getJsonPrettyPrint(docType, signedDoc);
    String joseCompact = docType.equals(DocType.JOSE_COMPACT) ? new String(signedDoc, StandardCharsets.UTF_8) : null;


    List<? extends ExtendedSigValResult> signatureValidationResults = validationResult.getSignatureValidationResults();
    List<String> signedDocumentList = new ArrayList<>();
    for (int i=0; i<signatureValidationResults.size(); i++){
      if (docType.equals(DocType.XML)){
        try {
          signedDocumentList.add(XMLDocumentBuilder.getDocText(XMLDocumentBuilder.getDocument(signatureValidationResults.get(i).getSignedDocument())));
        }
        catch (Exception e) {
          signedDocumentList.add("No document available");
        }
      } else {
        signedDocumentList.add("inlinepdf?id="+i);
      }
    }

    // Determine if SVT is available.
    boolean svtAvailable = signatureValidationResults.stream().anyMatch(sigValResult -> sigValResult.getSvtJWT() == null);

    // Set view model
    model.addAttribute("basicModel", basicUiModel);
    model.addAttribute("resultPageData", resultPageData);
    model.addAttribute("validationResult", validationResult);
    model.addAttribute("lang", lang);
    model.addAttribute("text", uiText.getBundle(UIText.UiBundle.resultText, lang));
    model.addAttribute("docType", docType);
    model.addAttribute("showLoa", showLoa);
    model.addAttribute("xmlPrettyPrint", xmlPrettyPrint);
    model.addAttribute("josePrettyPrint", jsonPrettyPrint);
    model.addAttribute("joseCompact", joseCompact);
    model.addAttribute("signedDocs", signedDocumentList);
    model.addAttribute("svtAvailable", (svtAvailable || issueSvtIfExists) && enableSvtIssuer);
    model.addAttribute("enableSignedDataView", enableSignedDataView);
    model.addAttribute("showReportOptions", showReportOptions);

    return "sigvalresult";
  }

  private String getJsonPrettyPrint(DocType docType, byte[] signedDocument) {
    if (docType.equals(DocType.JOSE)){
      try {
        Object sigDocObj = OBJECT_MAPPER.readValue(signedDocument, Object.class);
        return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(sigDocObj);
      } catch (Exception ex) {
        log.debug("Document believed to be a JSON signed document does not contain valid JSON");
      }
    }
    return null;
  }

  @ExceptionHandler(Exception.class)
  public String handleException(Exception ex, Model model){
    model.addAttribute("basicModel", basicUiModel);
    model.addAttribute("message", ex.getMessage());
    return "error";
  }


}
