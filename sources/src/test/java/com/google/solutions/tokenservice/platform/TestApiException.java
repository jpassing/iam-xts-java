package com.google.solutions.tokenservice.platform;

import com.google.api.client.googleapis.json.GoogleJsonError;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpResponseException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestApiException {
  // -------------------------------------------------------------------------
  // issueToken.
  // -------------------------------------------------------------------------

  @Test
  public void whenJsonResponseHasDetails_thenFromReturnsException() {
    var error = new GoogleJsonError();
    error.setMessage("detail-message");

    error.setDetails(List.of(new GoogleJsonError.Details()));
    var e = ApiException.from(new GoogleJsonResponseException(
      new HttpResponseException.Builder(400, "", new HttpHeaders())
        .setMessage("message"),
      error));

    assertEquals("detail-message", e.getMessage());
  }

  @Test
  public void whenJsonResponseHasNoDetails_thenFromReturnsException() {
    var e = ApiException.from(new GoogleJsonResponseException(
      new HttpResponseException.Builder(400, "", new HttpHeaders())
        .setMessage("message"),
      null));

    assertEquals("message", e.getMessage());
  }
}
