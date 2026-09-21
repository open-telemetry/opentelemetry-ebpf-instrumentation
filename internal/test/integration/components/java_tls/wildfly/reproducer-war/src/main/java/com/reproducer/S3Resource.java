/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package com.reproducer;

import jakarta.ejb.EJB;
import jakarta.enterprise.context.RequestScoped;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/api/test-s3")
@RequestScoped
public class S3Resource {
  @EJB private S3Service s3Service;

  @GET
  @Produces(MediaType.TEXT_PLAIN)
  public Response download() {
    try {
      return Response.ok(s3Service.download("test-bucket", "test-file.txt")).build();
    } catch (Exception error) {
      return Response.serverError().entity(errorChain(error)).build();
    }
  }

  private static String errorChain(Throwable error) {
    StringBuilder result = new StringBuilder();
    for (Throwable current = error; current != null; current = current.getCause()) {
      if (result.length() > 0) {
        result.append(" caused by ");
      }
      result.append(current.getClass().getName()).append(": ").append(current.getMessage());
    }
    return result.toString();
  }
}
