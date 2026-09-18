/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package com.reproducer;

import jakarta.ejb.Stateless;
import java.io.InputStream;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;

@Stateless
public class S3Service {
  public String download(String bucket, String key) {
    ApacheHttpClient.Builder httpClient =
        ApacheHttpClient.builder()
            .connectionTimeout(Duration.ofSeconds(5))
            .socketTimeout(Duration.ofSeconds(10))
            .tlsTrustManagersProvider(() -> new TrustManager[] {new TrustAllManager()});

    try (S3Client s3 =
            S3Client.builder()
                .region(Region.of(env("AWS_REGION", "us-east-1")))
                .credentialsProvider(
                    StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(
                            env("AWS_ACCESS_KEY_ID", "minioadmin"),
                            env("AWS_SECRET_ACCESS_KEY", "minioadmin123"))))
                .serviceConfiguration(
                    S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .httpClientBuilder(httpClient)
                .endpointOverride(URI.create(env("S3_ENDPOINT", "https://minio:9000")))
                .build();
        InputStream input =
            s3.getObject(GetObjectRequest.builder().bucket(bucket).key(key).build())) {
      byte[] data = new byte[64];
      int read = input.read(data);
      return "SUCCESS: " + new String(data, 0, Math.max(read, 0)).trim();
    } catch (Exception error) {
      throw new IllegalStateException("S3 download failed", error);
    }
  }

  private static String env(String name, String fallback) {
    String value = System.getenv(name);
    return value == null || value.isBlank() ? fallback : value;
  }

  private static final class TrustAllManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
