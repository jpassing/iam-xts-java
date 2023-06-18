package com.google.solutions.tokenservice.oauth;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.oauth.client.ClientRepository;

/**
 * Flow that authenticates clients using mTLS.
 *
 * Based on RFC8705 (OAuth 2.0 Mutual-TLS Client Authentication
 * and Certificate-Bound Access Tokens).
 */
public abstract class MtlsClientCredentialsFlow extends ClientCredentialsFlow {
  private final ClientRepository clientRepository;

  public MtlsClientCredentialsFlow(
    ClientRepository clientRepository,
    TokenIssuer issuer
  ) {
    super(issuer);
    this.clientRepository = clientRepository;
  }

  /**
   * Extract mTLS client certificate information, and verify its authenticity.
   */
  protected abstract MtlsClientCertificate verifyClientCertificate(
    TokenRequest request
  );

  //---------------------------------------------------------------------------
  // Overrides.
  //---------------------------------------------------------------------------

  @Override
  public String authenticationMethod() {
    return "tls_client_auth";
  }

  @Override
  protected AuthenticatedClient authenticateClient(TokenRequest request) {
    var clientId = request.parameters().getFirst("client_id");

    Preconditions.checkArgument(!Strings.isNullOrEmpty(clientId), "client_id is required");

    //
    // Authenticate the client based on the attributes we've gathered.
    //
    var clientAttributes = verifyClientCertificate(request);
    return this.clientRepository.authenticateClient(clientId, clientAttributes);
  }
}
