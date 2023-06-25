package com.google.solutions.tokenservice.oauth;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.auth.oauth2.TokenVerifier;
import com.google.solutions.tokenservice.URLHelper;
import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.platform.IntegrationTestEnvironment;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.wildfly.common.Assert.assertTrue;

public class TestTokenIssuer {
  private static final URL ISSUER_ID = URLHelper.fromString("http://example.com/");

  // -------------------------------------------------------------------------
  // issueToken.
  // -------------------------------------------------------------------------

  @Test
  public void whenNoAudienceConfigured_thenIssueTokenCreatesTokenForClient() throws Exception {
    var serviceAccount = IntegrationTestEnvironment.SERVICE_ACCOUNT;

    var issuer = new TokenIssuer(
      new TokenIssuer.Options(ISSUER_ID, null, Duration.ofMinutes(1)),
      serviceAccount);

    var payload = new JsonWebToken.Payload()
      .set("test", "value");

    var client = new AuthenticatedClient("client-1", Instant.now(), Map.of());
    var token = issuer.issueIdToken(
      client,
      payload);

    var verifiedPayload = TokenVerifier
      .newBuilder()
      .setCertificatesLocation(serviceAccount.jwksUrl().toString())
      .setIssuer(ISSUER_ID.toString())
      .setAudience("client-1")
      .build()
      .verify(token.value())
      .getPayload();

    assertEquals(ISSUER_ID.toString(), verifiedPayload.getIssuer());
    assertEquals("audience-1", verifiedPayload.getAudience());
    assertNotNull(verifiedPayload.getNotBeforeTimeSeconds());
    assertNotNull(verifiedPayload.getExpirationTimeSeconds());
    assertTrue(token.expiryTime().isAfter(Instant.now()));
    assertEquals("value", verifiedPayload.get("test"));
  }

  @Test
  public void whenAudienceConfigured_thenIssueTokenCreatesTokenForAudience() throws Exception {
    var serviceAccount = IntegrationTestEnvironment.SERVICE_ACCOUNT;

    var issuer = new TokenIssuer(
      new TokenIssuer.Options(
        ISSUER_ID,
        URLHelper.fromString("https://example.com/"),
        Duration.ofMinutes(1)),
      serviceAccount);

    var payload = new JsonWebToken.Payload()
      .set("test", "value");

    var client = new AuthenticatedClient("client-1", Instant.now(), Map.of());
    var token = issuer.issueIdToken(
      client,
      payload);

    var verifiedPayload = TokenVerifier
      .newBuilder()
      .setCertificatesLocation(serviceAccount.jwksUrl().toString())
      .setIssuer(ISSUER_ID.toString())
      .setAudience("https://example.com/")
      .build()
      .verify(token.value())
      .getPayload();

    assertEquals(ISSUER_ID.toString(), verifiedPayload.getIssuer());
    assertEquals("audience-1", verifiedPayload.getAudience());
    assertNotNull(verifiedPayload.getNotBeforeTimeSeconds());
    assertNotNull(verifiedPayload.getExpirationTimeSeconds());
    assertTrue(token.expiryTime().isAfter(Instant.now()));
    assertEquals("value", verifiedPayload.get("test"));
  }
}
