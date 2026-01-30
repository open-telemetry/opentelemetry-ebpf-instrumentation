import http from "k6/http";

export const options = {
  scenarios: {
    constant_load: {
      executor: "constant-arrival-rate",
      rate: 500, // 5 requests per second
      timeUnit: "1s", // per second
      duration: "30s", // run time
      preAllocatedVUs: 10, // pre-allocate VUs
      maxVUs: 20, // maximum VUs if needed
    },
  },
};

export default function () {
  const params = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  };
  
  http.post(
    "http://localhost:8081/shorten",
    "url=https://example.com",
    params
  );
}
