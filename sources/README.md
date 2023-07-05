# Extensible Token Service

The _Extensible Token Service_ is an example implementation of a token service that
can be extended to support different authentication mechanisms.

## Deploying the application

The _Extensible Token Service_ runs on Cloud Run. The application is stateless and
uses the [Security Token Service API](https://cloud.google.com/iam/docs/reference/sts/rest)
and [IAM Service Account Credentials API](https://cloud.google.com/iam/docs/reference/credentials/rest)
to issue short-lived tokens.

For detailed instructions on deploying Just-In-Time Access, see [LINK]
on the Google Cloud website.

--- 

_Extensible Token Service is an open-source project and not an officially supported Google product._

_All files in this repository are under the
[Apache License, Version 2.0](LICENSE.txt) unless noted otherwise._
