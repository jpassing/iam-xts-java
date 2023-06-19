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

    // TODO: consider response type

    var payload = new JsonWebToken.Payload();

    //
    // Add all claims provided by the subclass first.
    //
    payload.putAll(client.additionalClaims());

    //
    // Add claims for a client-credentials flow, based on
    // https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    //
    // - amr: the name of the flow.
    // - aud: audience(s) that this ID Token is intended for. It MUST contain the
    //        OAuth 2.0 client_id of the relying party as an audience value.
    //
    // NB. Because this is a client-credentials flow, we don't set a 'sub' claim.
    // NB. We don't allow subclasses to override any of these claims.
    //

    payload.set("amr", name().toLowerCase());

    var signedToken = this.issuer.issueToken(
      client.clientId(),
      payload);

    return new TokenResponse(
      client,
      signedToken.token(),
      "Bearer",
      signedToken.expiryTime().getEpochSecond() - Instant.now().getEpochSecond(),
      null,
      null);
  }
}
