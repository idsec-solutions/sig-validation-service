# Signature Validation Service versions

**Latest Current version: 1.2.9**

| Version | Comment                                                                                                                        | Date       |
|---------|--------------------------------------------------------------------------------------------------------------------------------|------------|
| 1.0.0   | Initial release                                                                                                                | 2020-10-01 |
| 1.0.1   | Support for signature validation date limit                                                                                    | 2020-10-02 |
| 1.0.2   | Fixed file size issue                                                                                                          | 2020-10-06 |
| 1.0.3   | Fixed chain_hash bug in svt lib                                                                                                | 2020-10-23 |
| 1.0.4   | Updated PDF context checking to allow legitimate changes to PDF documents afters signing                                       | 2021-02-02 |
| 1.1.0   | Support for JSON validation, ETSI 110 102-2 validation report and REST API for validation and SVT issuing                      | 2022-05-04 |
| 1.2.0   | Move to use of Credential Support from Sweden Connect.                                                                         | 2023-01-30 |
| 1.2.1   | Updating signature validation base lib to 1.2.3                                                                                | 2023-09-13 |
| 1.2.3   | Updating signature validation base lib to 1.2.4                                                                                | 2023-10-25 |
| 1.2.4   | Fix HSM certificate loading                                                                                                    | 2023-11-21 |
| 1.2.5   | Fix XML parsing bug of time not expressed in CET                                                                               | 2023-11-22 |
| 1.2.6   | Configuration options for inline or attached SVT in web UI                                                                     | 2023-09-13 |
| 1.2.7   | UI updates                                                                                                                     | 2023-12-11 |
| 1.2.8   | Corrected display of validation result with SVT                                                                                | 2024-02-09 |
| 1.2.9   | Corrected display of authentication LoA level                                                                                  | 2024-04-16 |
| 1.3.1   | Java 21, Spring boot 3.4.3, Extended PDF document update validation, Bootstrap 5, Bootstrap css builder, Indeterminate display | 2025-03-28 |
| 1.3.2   | Spring Boot 3.4.4, credential support 2.0.5, publication to maven central                                                      | 2025-05-28 |


## version 1.2.8

This version adds two new configuration options in `application.properties`

> sigval-service.ui.hide-attribute

and 

> sigval-service.ui.hide-loa-uri

The `sigval-service.ui.hide-attribute` property holds an optional comma-separated list of certificate attribute OID:s.
Any OID found in this list will not be displayed as an ID attribute of the user.
This option is intended
to be used when the certificate subject name contains attributes that are not representing the identity of the subject,
such as if an attribute holding the "level of assurance" of the authentication process is present as an attribute.

The `sigval-service.ui.hide-loa-uri` property holds an optional comma-separated list of AuthenticationContextClassRef URI:s that should not be displayed
as the level of assurance achieved on the result page.
This option may be used if a generic non informative URI is present in the certificate
(e.g. `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`).

**NOTE:** For LoA URI to be shown at all in the result UI, the property `sigval-service.ui.show-loa` must be set to true.


## version 1.2.8

This version adds a new configuration option in `application.properties`

> sigval-service.svt.issue-on-failed-validation=false

If not set, this property defaults to the value `false`.
If this is the preferred choice, 
no changes to configuration are necessary from previous versions.

When this property is set to `false`,
the validation service will not issue an SVT enhanced document unless all signatures on the document validates successfully.

Setting this option to `true` will allow the validation service to issue an SVT if possible, regardless of validation result.
Note that if validation was not successful, the SVT will indicate that the validation was not successful, but it will still be issued.

## version 1.2.6

This version includes two new configuration settings for delivery of SVT as an inline document or as an attachment.

```
sigval-service.svt.download-attachment=true
sigval-service.svt.new-svt-tab=true
```

These are the default settings of the property parameters. `download-attachment` set to `true` causes the SVT document to be downloaded
and saved to disk. The value of `false` causes the document to be shown in the browser.
`new-svt-tab` set to `true` opens a new tab for returning the svt document. Setting this to `false` returns the document in the current tab.



## version 1.1.0

This version introduces new property settings in application.properties:

A report generator now creates signed ETSI 119 102-2 validation reports. This requires the service to assign a signing key. 
The following default settings apply:

```
# Sigval Report Key source. This key source is used to sign signature validation reports.
sigval-service.report.keySourceType=create
sigval-service.report.keySourceLocation=#{null}
sigval-service.report.keySourcePass=#{null}
sigval-service.report.keySourceAlias=#{null}
sigval-service.report.keySourceCertLocation=#{null}
```

The report generator has the following default settings that may be modified:

```
# Report Generator
sigval-service.report.default-digest-algorithm=http://www.w3.org/2001/04/xmlenc#sha256
sigval-service.report.default-include-chain=false
sigval-service.report.default-include-tschain=false
sigval-service.report.default-include-siged-doc=false
```

**default-digest-algorithm** sets the default digest algorithm to use to hash referenced data in the report. This value
is overridden by any hash algorithm enforced by data imported from a source using any other digest algorithm.

**default-include-chain** sets the default value whether signature validation reports should include the full signing 
certificate validation chain

**default-include-tschain** sets the default value whether time stamp signing certificates should be included in the report

General settings with defaults

```
sigval-service.svt.default-replace=true
sigval-service.ui.show-report-options=true
```

**default-replace** defines whether XML and JOSE documents that has a present SVT should have this SVT replaced if a new SVT is issued
or whether the new SVT should be amended to the existing SVT.

**show-report-options** should be set to `false` to remove the report options pop-up when a report is requested.

The following property settings are removed (no longer have any effect)

```
sigval-service.ui.display-downloaded-svt-pdf
sigval-service.ui.display-downloaded-svt-xml
```

## version 1.0.4
This version introduces a new property in application.properties `sigval-service.validator.strict-pdf-context`.
Setting this property to `true` means that the validator will not tolerate that the PDF document is updated through a re-save which may update the Document Security Store (DSS), metadata and document info. A setting to `false` will allow such chages after signing.


