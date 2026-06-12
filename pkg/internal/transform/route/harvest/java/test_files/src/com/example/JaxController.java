package com.example;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

@Path("/jax/")
public class JaxController {
    @GET
    @Path("/items/{id:[0-9]+}/")
    public String item() {
        return "";
    }

    @POST
    public String create() {
        return "";
    }
}
