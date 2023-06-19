package com.google.solutions.tokenservice.oauth;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.auth.oauth2.TokenVerifier;
import com.google.solutions.tokenservice.URLHelper;
import com.google.solutions.tokenservice.platform.IntegrationTestEnvironment;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.wildfly.common.Assert.assertTrue;

public class TestTokenIssuer {
  private static final URL ISSUER_ID = URLHelper.fromString("http://example.com/");

  // -------------------------------------------------------------------------
  // issueToken.
  // -------------------------------------------------------------------------

  @Test
  public void issueToken() throws Exception {
    var serviceAccount = IntegrationTestEnvironment.SERVICE_ACCOUNT;

    var issuer = new TokenIssuer(
      new TokenIssuer.Options(ISSUER_ID, Duration.ofMinutes(1)),
      serviceAccount);

    var payload = new JsonWebToken.Payload()
      .set("test", "value");

    var token = issuer.issueToken(
      "audience-1",
      payload);

    var verifiedPayload = TokenVerifier
      .newBuilder()
      .setCertificatesLocation(serviceAccount.jwksUrl().toString())
      .setIssuer(ISSUER_ID.toString())
      .setAudience("audience-1")
      .build()
      .verify(token.token())
      .getPayload();

    assertEquals(ISSUER_ID.toString(), verifiedPayload.getIssuer());
    assertEquals("audience-1", verifiedPayload.getAudience());
    assertNotNull(verifiedPayload.getNotBeforeTimeSeconds());
    assertNotNull(verifiedPayload.getExpirationTimeSeconds());
    assertTrue(token.expiryTime().isAfter(Instant.now()));
    assertEquals("value", verifiedPayload.get("test"));
  }
}
