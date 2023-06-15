package com.google.solutions.tokenservice.oauth;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.common.base.Strings;
import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.platform.AccessException;

import javax.ws.rs.ForbiddenException;
import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

/**
 * Flow that authenticates clients.
 */
public abstract class ClientCredentialsFlow implements AuthenticationFlow {

  private final TokenIssuer issuer;

  public ClientCredentialsFlow(TokenIssuer issuer) {
    this.issuer = issuer;
  }

  /**
   * Identify and authenticate the client.
   */
  protected abstract AuthenticatedClient authenticateClient(TokenRequest request);

  //---------------------------------------------------------------------------
  // AuthenticationFlow.
  //---------------------------------------------------------------------------

  @Override
  public String grantType() {
    return "client_credentials";
  }

  @Override
  public boolean canAuthenticate(TokenRequest request) {
    return !Strings.isNullOrEmpty(request.parameters().getFirst("client_id"));
  }

  @Override
  public TokenResponse authenticate(
    TokenRequest request
  ) throws AccessException, IOException {

    //
    // Authenticate the client.
    //
    AuthenticatedClient client;
    try
    {
      client = authenticateClient(request);
    }
    catch (Exception e) {
      throw new ForbiddenException(
        "The client or its credentials are invalid", e);
    }

    //
    // Issue a token.
    //

    // TODO: Other claims? RFC?

    // TODO: consider response type

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
