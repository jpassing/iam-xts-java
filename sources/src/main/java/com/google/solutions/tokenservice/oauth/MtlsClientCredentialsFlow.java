package com.google.solutions.tokenservice.oauth;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.solutions.tokenservice.oauth.client.ClientRepository;
import com.google.solutions.tokenservice.platform.AccessException;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

// https://quarkus.io/guides/security-authentication-mechanisms-concept#mutual-tls

/**
 * Flow that authenticates clients using mTLS.
 *
 * Based on RFC8705 (OAuth 2.0 Mutual-TLS Client Authentication
 * and Certificate-Bound Access Tokens).
 */
public abstract class MtlsClientCredentialsFlow implements AuthenticationFlow {
  private final ClientRepository clientRepository;
  private final TokenIssuer issuer;

  public MtlsClientCredentialsFlow(
    ClientRepository clientRepository,
    TokenIssuer issuer
  ) {
    this.clientRepository = clientRepository;
    this.issuer = issuer;
  }

  /**
   * Extract mTLS attributes from HTTP headers, and verify their authenticity.
   */
  protected abstract MtlsClientAttributes verifyRequest(TokenRequest request);

  //---------------------------------------------------------------------------
  // AuthenticationFlow.
  //---------------------------------------------------------------------------

  @Override
  public String grantType() {
    return "client_credentials";
  }

  @Override
  public String authenticationMethod() {
    return "tls_client_auth";
  }

  @Override
  public boolean canAuthenticate(TokenRequest request) {
    return request.parameters().containsKey("client_id");
  }

  @Override
  public TokenResponse authenticate(
    TokenRequest request
  ) throws AccessException, IOException {
    var clientId = request.parameters().getFirst("client_id");

    Preconditions.checkArgument(Strings.isNullOrEmpty(clientId), "client_id is required");

    //
    // Authenticate the client based on the attributes we've gathered.
    //
    var clientAttributes = verifyRequest(request);
    var client = this.clientRepository.authenticateClient(clientId, clientAttributes);

    //
    // Issue a token.
    //

    // TODO: Other claims? RFC?

    var tokenPayload = new JsonWebToken.Payload();
    tokenPayload.putAll(client.additionalClaims());
    tokenPayload
      .setJwtId(UUID.randomUUID().toString())
      .setIssuedAtTimeSeconds(client.authenticationTime().getEpochSecond());

    var signedToken = this.issuer.issueToken(tokenPayload);
    return new TokenResponse(
      client,
      signedToken.token(),
      "Bearer",
      signedToken.expiryTime().getEpochSecond() - Instant.now().getEpochSecond(),
      null,
      null);
  }
}
