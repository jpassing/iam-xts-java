package com.google.solutions.tokenservice.platform;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.auth.oauth2.TokenVerifier;
import com.google.solutions.tokenservice.UserId;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class TestServiceAccount {
  private static final UserId SampleUser = new UserId("sample@project-1.iam.gserviceaccount.com");
  private static final String CLOUD_PLATFORM_SCOPE
    = "https://www.googleapis.com/auth/cloud-platform";

  // -------------------------------------------------------------------------
  // signJwt.
  // -------------------------------------------------------------------------

  @Test
  public void whenUnauthenticated_thenSignJwtThrowsException() {
    var serviceAccount = new ServiceAccount(
      SampleUser,
      IntegrationTestEnvironment.INVALID_CREDENTIAL);

    var payload = new JsonWebToken.Payload()
      .setAudience("test");

    assertThrows(
      NotAuthenticatedException.class,
      () -> serviceAccount.signJwt(payload));
  }

  @Test
  public void whenCallerHasPermission_thenSignJwtSucceeds() throws Exception {
    var serviceAccount = IntegrationTestEnvironment.SERVICE_ACCOUNT;

    var payload = new JsonWebToken.Payload()
      .setAudience(SampleUser.email())
      .setIssuer(SampleUser.email());

    var jwt = serviceAccount.signJwt(payload);
    assertNotNull(jwt);

    TokenVerifier
      .newBuilder()
      .setCertificatesLocation(serviceAccount.jwksUrl().toString())
      .setIssuer(SampleUser.email())
      .setAudience(SampleUser.email())
      .build()
      .verify(jwt);
  }

  // -------------------------------------------------------------------------
  // getJwksUrl.
  // -------------------------------------------------------------------------

  @Test
  public void getJwksUrlReturnsServiceAccountJwksUrl() {
    var serviceAccount = IntegrationTestEnvironment.SERVICE_ACCOUNT;

    assertEquals(
      String.format(
        "https://www.googleapis.com/service_accounts/v1/metadata/jwk/%s",
        serviceAccount.id().email()),
      serviceAccount.jwksUrl().toString());
  }

  // -------------------------------------------------------------------------
  // toString.
  // -------------------------------------------------------------------------

  @Test
  public void toStringReturnsEmail() {
    var serviceAccount = IntegrationTestEnvironment.SERVICE_ACCOUNT;

    assertEquals(
      IntegrationTestEnvironment.SERVICE_ACCOUNT.id().email(),
      serviceAccount.toString());
  }
}
