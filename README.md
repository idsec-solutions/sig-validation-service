![Logo](documentation/img/idsec.png)

# sig-validation-service

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

This repository is a reference implementation that demonstrates usage of the Sweden Connect signature validation open source
implementations.

- [https://github.com/swedenconnect/signature-validation](https://github.com/swedenconnect/signature-validation)
- [https://github.com/swedenconnect/svt-core](https://github.com/swedenconnect/svt-core)


This reference implementation provides a Spring Boot web application for validation of signed documents:

![Validation application](documentation/img/appview_main.png)

The following main features are demonstrated:

- Validation of PDF, XML and JSON signed documents
- Manual upload of signed documents with a validation result UI
- Rest API for providing a document for validation using HTTP POST where the result is provided as a signature validation report according to ETSI TS 119 102-2.
- Issuance of "Signature Validation Token" (SVT) for validated signatures
- Enhancing signed documents by incorporating SVT into signed documents
- Validation of signed documents that has been enhanced with SVT.
- Rest API for requesting SVT enhanced signed document using HTTP POST

## Scope

The scope of this service is limited to demonstration of functionality. Its purpose is to help developers to implement their own service that supports their local validation procedures and trust policy.

## Trust configuration

This application further demonstrates use of the trust configuration service from DIGG (Swedish Agency for Digital Government) as source of trust:

![Trust config](documentation/img/trust_config.png)

This service provides a source of trusting EU service providers that can be found on Trusted Lists from EU member states. This service may also be used to add other services that are trusted by local policy.

The signature validation service implements a number of independent trust strategies:

- Using DIGG trust configuration service
- Specifying a local set of trusted certificate issuers, time-stamp issuers, and SVT issuers.

## Supported signature formats

This application supports validation of the following signature formats:

- XML DSig signed documents
- ETSI XAdES signed documents
- PDF signed documents
- ETSI PAdES signed documents
- JOSE signed documents (JSON signature)
- ETSI JAdES signed documents

## Archiving support

This service use the open source implementation of Signature Validation Tokens, currently under publication by the Internet Engineering Task force.

Current draft: [https://datatracker.ietf.org/doc/draft-santesson-svt](https://datatracker.ietf.org/doc/draft-santesson-svt)

The SVT is tool for preservation and archival of validation result. This means that the SVT is a simple format to store and archive a validation result as a result of a signature validation process. The signature validation result is bound to the signed document and the validated signature in a way that allows the signature validation result to be validated against the signed document into a distant future, allowing the signed document to be archived for a very long time where the signature validation result is preserved along with the signed document.

The SVT is a complementary technology to various solutions used to validate signatures, including complex solutions for validation of old signatures. Once the validation solution has been used to validate the signature, then that validation result can be preserved using SVT.

## Demo deployment

A demo deployment of this service is available here: [https://sandbox.swedenconnect.se/sigval/](https://sandbox.swedenconnect.se/sigval/).

IMPORTANT NOTE: This service MUST NOT be used to validate signatures on real documents for production purposes. This service is configured to trust various test keys and identities and a positive validation result provided by this service is no statement of validity beyond the scope of testing the technology itself.

---

Copyright &copy; 2020-2022, [IDsec Solutions AB](http://www.idsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
