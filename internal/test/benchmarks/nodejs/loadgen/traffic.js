import http from "k6/http";

export const options = {
  scenarios: {
    constant_load: {
      executor: "constant-arrival-rate",
      rate: 5000, // 5 requests per second
      timeUnit: "1s", // per second
      duration: "60s", 
      preAllocatedVUs: 10, // pre-allocate VUs
      maxVUs: 100, // maximum VUs if needed
    },
  },
};

export default function () {
  http.get("http://localhost:5001/b");
}
