package com.example;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;

@Controller("/mn")
public class MicronautController {
    @Get({"/things", "/things/{name}"})
    public String things() {
        return "";
    }

    @Post(uri = "/submit/")
    public String submit() {
        return "";
    }
}
