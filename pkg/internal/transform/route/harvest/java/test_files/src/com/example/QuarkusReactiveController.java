package com.example;

import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;

@RouteBase(path = "/reactive/")
public class QuarkusReactiveController {
    @Route(path = "/items/:itemId/")
    public String item() {
        return "";
    }

    @Route(path = "/status")
    @Route(path = "/health/:probe")
    public String repeated() {
        return "";
    }

    @Route(path = "/files/*")
    public String wildcard() {
        return "";
    }

    @Route(regex = "/regex/.*")
    public String regex() {
        return "";
    }
}
