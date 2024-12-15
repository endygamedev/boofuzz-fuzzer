boofuzz-fuzzer
==============

Task
----

You should apply fuzzing to test RESTful APIs with [boofuzz](https://github.com/jtpereyda/boofuzz).

It will generate random requests, send them to the server, monitor the responses
and look for possible vulnerabilities.

1.  Install, configure the boofuzz ​​tool. Study the examples.

2.  Study the target API:

    - [JSONPlaceholder](https://jsonplaceholder.typicode.com/): Fake REST API for testing and prototyping.

    You need to study:

    - API endpoints.
    - Expected input parameters for each endpoint.
    - Request and response format (e.g. JSON).

    Possible errors or exceptions that may occur during the API operation.

3.  Generate random requests

    The fuzzer should generate random requests for each endpoint. This includes:

    -   GET requests to retrieve data.

    -   POST requests to send data.

    -   PUT/DELETE requests to change or delete data.

4.  Analyzing responses

    After sending requests, you need to monitor and analyze the server responses.

5. Identifying vulnerabilities

    You should try to look for vulnerabilities (at least one of them), such as:

    -   SQL injections: These can be attempts to insert SQL statements into request parameters.

    -   Cross-Site Scripting (XSS): Checking for the possibility of injecting scripts
        into request or response parameters.

    -   Buffer overflows: Sending data that can cause a buffer overflow on the server.

    -   Unhandled exceptions: Checking for proper error and exception handling.

Resources:

1.  boofuzz ​​— documentation and examples: https://github.com/jtpereyda/boofuzz
2.  JSONPlaceholder — API for testing: https://jsonplaceholder.typicode.com/