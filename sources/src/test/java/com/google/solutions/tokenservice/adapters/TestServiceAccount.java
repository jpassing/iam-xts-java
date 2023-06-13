//package com.google.solutions.tokenservice.adapters;
//
//import com.google.api.client.json.webtoken.JsonWebToken;
//import com.google.auth.oauth2.TokenVerifier;
//import org.junit.jupiter.api.Test;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//public class TestServiceAccount {
//
//  // -------------------------------------------------------------------------
//  // signJwt.
//  // -------------------------------------------------------------------------
//
//  @Test
//  public void whenUnauthenticated_ThenSignJwtThrowsException() {
//    var adapter = new ServiceAccount(
//      IntegrationTestEnvironment.NO_ACCESS_USER,
//      IntegrationTestEnvironment.NO_ACCESS_CREDENTIALS);
//
//    var payload = new JsonWebToken.Payload()
//      .setAudience("test");
//
//    assertThrows(
//      AccessDeniedException.class,
//      () -> adapter.signJwt(payload));
//  }
//
//  @Test
//  public void whenCallerHasPermission_ThenSignJwtSucceeds() throws Exception {
//    var adapter = new ServiceAccount(IntegrationTestEnvironment.APPLICATION_CREDENTIALS);
//    var serviceAccount = IntegrationTestEnvironment.NO_ACCESS_USER;
//
//    var payload = new JsonWebToken.Payload()
//      .setAudience(serviceAccount.email)
//      .setIssuer(serviceAccount.email);
//
//    var jwt = adapter.signJwt(serviceAccount, payload);
//    assertNotNull(jwt);
//
//    TokenVerifier
//      .newBuilder()
//      .setCertificatesLocation(ServiceAccount.getJwksUrl(serviceAccount))
//      .setIssuer(serviceAccount.email)
//      .setAudience(serviceAccount.email)
//      .build()
//      .verify(jwt);
//  }
//
//  // -------------------------------------------------------------------------
//  // getJwksUrl.
//  // -------------------------------------------------------------------------
//
//  @Test
//  public void getJwksUrl() {
//    assertEquals(
//      String.format(
//        "https://www.googleapis.com/service_accounts/v1/metadata/jwk/%s",
//        IntegrationTestEnvironment.NO_ACCESS_USER.email),
//      ServiceAccount.getJwksUrl(IntegrationTestEnvironment.NO_ACCESS_USER));
//  }
//}