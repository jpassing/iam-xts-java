package com.google.solutions.tokenservice.oauth;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.auth.oauth2.TokenVerifier;
import com.google.solutions.tokenservice.platform.IntegrationTestEnvironment;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.wildfly.common.Assert.assertTrue;

public class TestTokenIssuer {

  // -------------------------------------------------------------------------
  // issueToken.
  // -------------------------------------------------------------------------

  @Test
  public void issueToken() throws Exception {
    var serviceAccount = IntegrationTestEnvironment.SERVICE_ACCOUNT;

    var issuer = new TokenIssuer(
      new TokenIssuer.Options(Duration.ofMinutes(1)),
      serviceAccount);

    var payload = new JsonWebToken.Payload()
      .set("test", "value");

    var token = issuer.issueToken(payload);

    var verifiedPayload = TokenVerifier
      .newBuilder()
      .setCertificatesLocation(serviceAccount.jwksUrl())
      .setIssuer(serviceAccount.id().email())
      .setAudience(serviceAccount.id().email())
      .build()
      .verify(token.token())
      .getPayload();

    assertEquals(serviceAccount.id().email(), verifiedPayload.getIssuer());
    assertEquals(serviceAccount.id().email(), verifiedPayload.getAudience());
    assertNotNull(verifiedPayload.getIssuedAtTimeSeconds());
    assertNotNull(verifiedPayload.getExpirationTimeSeconds());
    assertTrue(token.expiryTime().isAfter(Instant.now()));
    assertEquals("value", verifiedPayload.get("test"));
  }
}
