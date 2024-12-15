import logging
from json import dumps, loads
from boofuzz import Session, Target, SocketConnection, Request, Static, String
import re

# Setup logging for detailed debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_boofuzz():
    # Configure connection to the target
    connection = SocketConnection("jsonplaceholder.typicode.com", 80)
    target = Target(connection=connection)
    session = Session(target=target)
    return session

def generate_requests(session: Session) -> None:
    """
    Generate various requests for fuzzing.
    """
    # Fuzz GET request
    # get_request = Request(
    #     "GET_Request",
    #     children=[
    #         Static("GET /posts/"),
    #         String(name="id", default_value="1", fuzzable=True),  # Fuzz ID
    #         Static(" HTTP/1.1\r\nHost: jsonplaceholder.typicode.com\r\n\r\n"),
    #     ],
    # )
    # session.connect(get_request)

    # # Fuzz POST request
    # post_request = Request(
    #     "POST_Request",
    #     children=[
    #         Static("POST /posts HTTP/1.1\r\n"),
    #         Static("Host: jsonplaceholder.typicode.com\r\n"),
    #         Static("Content-Type: application/json\r\n\r\n"),
    #         String(
    #             default_value=dumps(
    #                 {"title": "test", "body": "test body", "userId": 1}
    #             ),
    #             name="post_body",
    #             fuzzable=True,
    #         ),
    #         # XSS Payloads
    #         String(name="post_body_xss", default_value="<script>alert('XSS')</script>", fuzzable=True),
    #         String(name="post_body_xss2", default_value='{"title": "<img src=x onerror=alert(1)>"}', fuzzable=True),
    #         # SQL Injection Payloads
    #         String(name="sql_injection1", default_value="' OR 1=1 --", fuzzable=True),
    #         String(name="sql_injection2", default_value="'; DROP TABLE users; --", fuzzable=True),
    #         String(name="sql_injection3", default_value="1' OR 'a'='a", fuzzable=True),
    #     ],
    # )
    # session.connect(post_request)

    # # Fuzz DELETE request
    # delete_request = Request(
    #     "DELETE_Request",
    #     children=[
    #         Static("DELETE /posts/"),
    #         String(name="id", default_value="1", fuzzable=True),  # Fuzz ID
    #         Static(" HTTP/1.1\r\nHost: jsonplaceholder.typicode.com\r\n\r\n"),
    #     ],
    # )
    # session.connect(delete_request)

    # Fuzz PUT request
    # put_request = Request(
    #     "PUT_Request",
    #     children=[
    #         Static("PUT /posts/1 HTTP/1.1\r\n"),
    #         Static("Host: jsonplaceholder.typicode.com\r\n"),
    #         Static("Content-Type: application/json\r\n\r\n"),
    #         String(
    #             default_value=dumps(
    #                 {"title": "updated title", "body": "updated body", "userId": 1}
    #             ),
    #             name="put_body",
    #             fuzzable=True,
    #         ),
    #     ],
    # )
    # session.connect(put_request)

    # Buffer Overflow Fuzzing
    buffer_overflow_request = Request(
        "Buffer_Overflow_Request",
        children=[
            Static("POST /posts HTTP/2\r\n"),
            Static("Host: jsonplaceholder.typicode.com\r\n"),
            Static("Content-Type: application/json\r\n\r\n"),
            String(
                default_value=dumps(
                    {"title": "A" * 1024, "body": "B" * 4096, "userId": 1}
                ),
                name="post_body",
                fuzzable=True,
            ),
            # String(
            #     default_value="A" * 1024,
            #     name="buffer_overflow",
            #     fuzzable=True,
            # ),
            # String(
            #     default_value="B" * 4096,
            #     name="buffer_overflow_large",
            #     fuzzable=True,
            # ),
        ],
    )
    session.connect(buffer_overflow_request)

def analyze_responses(response):
    """
    Analyze server responses for signs of vulnerabilities.
    """
    try:
        if response:
            response_text = response.text
            response_status = response.status_code

            # Log the response for debugging
            logging.info(f"Response Code: {response_status}")
            logging.info(f"Response Body: {response_text[:200]}...")  # Limit log length

            # SQL Injection Detection
            if re.search(r"(sql syntax|database error|unexpected token|mysql|syntax error|invalid query)", response_text, re.IGNORECASE):
                logging.warning("Potential SQL Injection vulnerability detected.")

            # XSS Detection
            if re.search(r"<script>|alert|onerror", response_text, re.IGNORECASE):
                logging.warning("Potential XSS vulnerability detected.")

            # Buffer Overflow Detection
            if len(response_text) > 4096:  # Arbitrary threshold for large responses
                logging.warning("Potential Buffer Overflow vulnerability detected: Large response size.")
    except Exception as e:
        logging.error(f"Error analyzing response: {e}")

def main():
    session = setup_boofuzz()
    generate_requests(session)

    try:
        logging.info("Starting fuzzing session.")
        session.fuzz()
    except Exception as e:
        logging.error(f"An error occurred during fuzzing: {e}")

if __name__ == "__main__":
    main()
