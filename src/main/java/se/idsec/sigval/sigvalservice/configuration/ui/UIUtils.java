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

import java.nio.charset.StandardCharsets;

public class UIUtils {

  public static String fromIso(String isoStr){
    return new String(isoStr.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
  }
  public static String fromUtf(String utfStr){
    return new String(utfStr.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
  }

}
