//
// Copyright 2023 Google LLC
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//

package com.google.solutions.tokenservice.web;

import java.time.Duration;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class RuntimeConfiguration {
  private final Function<String, String> readSetting;

  public RuntimeConfiguration(Map<String, String> settings) {
    this(key -> settings.get(key));
  }

  public RuntimeConfiguration(Function<String, String> readSetting) {
    this.readSetting = readSetting;

    this.testSetting = new StringSetting(
      List.of("RESOURCE_SCOPE"),
      String.format("projects/%s", this.readSetting.apply("GOOGLE_CLOUD_PROJECT")));
  }

  // -------------------------------------------------------------------------
  // Settings.
  // -------------------------------------------------------------------------

  /**
   * TODO.
   */
  public final StringSetting testSetting;

  // -------------------------------------------------------------------------
  // Inner classes.
  // -------------------------------------------------------------------------

  public abstract class Setting<T> {
    private final Collection<String> keys;
    private final T defaultValue;

    protected abstract T parse(String value);

    protected Setting(Collection<String> keys, T defaultValue) {
      this.keys = keys;
      this.defaultValue = defaultValue;
    }

    public T getValue() {
      for (var key : this.keys) {
        var value = readSetting.apply(key);
        if (value != null) {
          value = value.trim();
          if (!value.isEmpty()) {
            return parse(value);
          }
        }
      }

      if (this.defaultValue != null) {
        return this.defaultValue;
      }
      else {
        throw new IllegalStateException("No value provided for " + this.keys);
      }
    }

    public boolean isValid() {
      try {
        getValue();
        return true;
      }
      catch (Exception ignored) {
        return false;
      }
    }
  }

  public class StringSetting extends Setting<String> {
    public StringSetting(Collection<String> keys, String defaultValue) {
      super(keys, defaultValue);
    }

    @Override
    protected String parse(String value) {
      return value;
    }
  }

  public class IntSetting extends Setting<Integer> {
    public IntSetting(Collection<String> keys, Integer defaultValue) {
      super(keys, defaultValue);
    }

    @Override
    protected Integer parse(String value) {
      return Integer.parseInt(value);
    }
  }

  public class BooleanSetting extends Setting<Boolean> {
    public BooleanSetting(Collection<String> keys, Boolean defaultValue) {
      super(keys, defaultValue);
    }

    @Override
    protected Boolean parse(String value) {
      return Boolean.parseBoolean(value);
    }
  }

  public class DurationSetting extends Setting<Duration> {
    public DurationSetting(Collection<String> keys, Duration defaultValue) {
      super(keys, defaultValue);
    }

    @Override
    protected Duration parse(String value) {
      return Duration.ofMinutes(Integer.parseInt(value));
    }
  }

  public class ZoneIdSetting extends Setting<ZoneId> {
    public ZoneIdSetting(Collection<String> keys) {
      super(keys, ZoneOffset.UTC);
    }

    @Override
    protected ZoneId parse(String value) {
      return ZoneId.of(value);
    }
  }
}
