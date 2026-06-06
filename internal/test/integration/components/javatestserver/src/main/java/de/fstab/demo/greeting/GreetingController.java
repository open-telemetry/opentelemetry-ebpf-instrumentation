package de.fstab.demo.greeting;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadLocalRandom;

@RestController
public class GreetingController {
	private final LookupService lookupService;
	private final ApiCallService apiCallService;

	RestClient commonClient = RestClient.create();

	public GreetingController(LookupService lookupService, ApiCallService apiCallService) {
		this.lookupService = lookupService;
		this.apiCallService = apiCallService;
	}

	public static void randomSleep(Duration averageDuration) throws InterruptedException {
		long sleepTime;
		do {
			sleepTime = averageDuration.toMillis() + (long) (ThreadLocalRandom.current().nextGaussian() * 200);
		} while (sleepTime <= 0.0);
		Thread.sleep(sleepTime);
	}

	@GetMapping("/smoke")
	public ResponseEntity<String> smoke() {
		return ResponseEntity.ok("OK");
	}

	@GetMapping("/json_logger")
	public ResponseEntity<String> jsonLogger() {
		String message = "this is a json log from java";
		System.out.println("{\"message\":\"" + message + "\",\"level\":\"INFO\"}");
		return ResponseEntity.ok(message);
	}

	@GetMapping("/greeting")
	public ResponseEntity<String> getGreeting123(
			@RequestParam(required = false, defaultValue = "10", name = "delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name = "response") Integer response)
			throws Exception {
		randomSleep(Duration.ofMillis(delay));
		return ResponseEntity.status(response).body("Hello, World!");
	}

	@GetMapping("/greeting123/{whatever}")
	public ResponseEntity<String> getGreeting(
			@PathVariable String whatever,
			@RequestParam(required = false, defaultValue = "10", name = "delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name = "response") Integer response)
			throws Exception {
		randomSleep(Duration.ofMillis(delay));
		return ResponseEntity.status(response).body("Hello, World! " + whatever);
	}

	@GetMapping("/sync-client")
	public ResponseEntity<String> syncClient(@RequestParam(name = "url") String url) throws Exception {
		HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
		conn.setRequestMethod("GET");
		conn.setConnectTimeout(10000);
		conn.setReadTimeout(10000);
		try {
			int code = conn.getResponseCode();
			try (InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream()) {
				if (is != null) {
					is.readAllBytes();
				}
			}
			return ResponseEntity.status(code).body("done");
		} finally {
			conn.disconnect();
		}
	}

	@GetMapping("/jtrace")
	public ResponseEntity<String> getDist(
			@RequestParam(required = false, defaultValue = "10", name = "delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name = "response") Integer response)
			throws Exception {
		randomSleep(Duration.ofMillis(delay));
		RestClient defaultClient = RestClient.create();
		String data = defaultClient.get()
				.uri("http://ntestserver:3030/traceme")
				.accept(MediaType.ALL)
				.retrieve()
				.body(String.class);
		return ResponseEntity.status(response).body(data);
	}

	@GetMapping("/jtrace2")
	public ResponseEntity<String> getDist2(
			@RequestParam(required = false, defaultValue = "10", name = "delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name = "response") Integer response)
			throws Exception {
		randomSleep(Duration.ofMillis(delay));
		CompletableFuture<String> aa = lookupService.callAsync();

		CompletableFuture.allOf(aa).join();
		return ResponseEntity.status(response).body(aa.get());
	}

	@GetMapping("/jtraceA")
	public ResponseEntity<String> getDistA(
			@RequestParam(required = false, defaultValue = "10", name = "delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name = "response") Integer response)
			throws Exception {
		randomSleep(Duration.ofMillis(delay));
		String data = commonClient.get()
				.uri("http://ntestserver:3030/traceme")
				.accept(MediaType.ALL)
				.retrieve()
				.body(String.class);
		return ResponseEntity.status(response).body(data);
	}

	@GetMapping("/jtraceB")
	public ResponseEntity<String> getDistB(
			@RequestParam(required = false, defaultValue = "10", name = "delay") Integer delay,
			@RequestParam(required = false, defaultValue = "200", name = "response") Integer response)
			throws Exception {
		randomSleep(Duration.ofMillis(delay));
		String data = apiCallService.makeApiCall("http://ntestserver:3030/traceme");
		return ResponseEntity.status(response).body(data);
	}

}