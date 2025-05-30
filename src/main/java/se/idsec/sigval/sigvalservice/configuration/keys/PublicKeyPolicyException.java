/*
 * Copyright 2025 IDsec Solutions AB
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

import java.io.IOException;

/**
 * Violations of public key policy.
 */
public class PublicKeyPolicyException extends IOException {

  private static final long serialVersionUID = 1703464085045114640L;

  /**
   * Constructor.
   *
   * @param message the error message
   */
  public PublicKeyPolicyException(final String message) {
    super(message);
  }

  /**
   * Constructor.
   *
   * @param message the error message
   * @param cause the cause of the error
   */
  public PublicKeyPolicyException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
