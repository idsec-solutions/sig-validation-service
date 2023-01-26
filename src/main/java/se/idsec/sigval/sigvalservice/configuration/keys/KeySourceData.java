/*
 * Copyright (c) 2023. IDsec Solutions AB
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

package se.idsec.sigval.sigvalservice.configuration.keys;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Key source configuration
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class KeySourceData {
  /** Key source type */
  KeySourceType type;
  /** Identifier of the resource holding the key data */
  String resource;
  /** The alias of the key */
  String alias;
  /** Password */
  String pass;
}
