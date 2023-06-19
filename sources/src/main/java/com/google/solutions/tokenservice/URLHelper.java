package com.google.solutions.tokenservice;

import java.net.MalformedURLException;
import java.net.URL;

public final class URLHelper {
  private URLHelper() {}

  public static URL fromString(String url) {
    try {
      return new URL(url);
    }
    catch (MalformedURLException e) {
      throw new RuntimeException(
        String.format("The URL is malformedL %s", url),
        e);
    }
  }
}
