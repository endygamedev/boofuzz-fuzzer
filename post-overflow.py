from typing import Any
from sys import maxsize

from boofuzz import (
    Session,
    FuzzLogger,
    Target,
    SocketConnection,
    s_initialize,
    s_block,
    s_static,
    s_size,
    s_string,
    s_delim,
    s_int,
    s_get,
)


def monitor_response(
    target: Target,
    fuzz_data_logger: FuzzLogger,
    session: Session,
    sock: Any,
) -> None:
    try:
        if response := target.recv():
            fuzz_data_logger.log_info(
                f"Response:\n{response.decode('utf-8', errors='ignore')}"
            )

            if b"500 Internal Server Error" in response:
                fuzz_data_logger.log_fail(
                    "Received HTTP 500 Internal Server Error",
                )
        else:
            fuzz_data_logger.log_fail("No response received")
    except Exception as exception:
        fuzz_data_logger.log_fail(
            f"Error while receiving response: {exception}",
        )


def main():
    target = Target(
        connection=SocketConnection("jsonplaceholder.typicode.com", 80),
    )

    session = Session(
        target=target,
        post_test_case_callbacks=[monitor_response],
    )

    s_initialize("POST with Body Fuzzing")
    with s_block("Request-Line"):
        s_static(
            "POST /posts HTTP/1.1\r\n",
            name="Request-Line",
        )

    with s_block("Headers"):
        s_static(
            "Host: jsonplaceholder.typicode.com\r\n",
            name="Host-Header",
        )
        s_static(
            "Content-Type: application/json\r\n",
            name="Content-Type-Header",
        )
        s_static(
            "Content-Length: ",
            name="Content-Length-Header",
        )
        s_size(
            "Body",
            output_format="ascii",
            name="Content-Length-Value",
        )
        s_static(
            "\r\n\r\n",
            name="Header-End",
        )

    with s_block("Body"):
        s_static("{", name="JSON-Start")
        s_string('"title":', name="Title-Key")
        s_string(f'\"{"A"*100_000}\"', fuzzable=True, name="Title-Value")
        s_static(",", name="Comma-1")

        s_string('"body":', name="Body-Key")
        s_delim(" ", name="Colon-1")
        s_string(f'\"{"A"*100_000}\"', fuzzable=True, name="Body-Value")
        s_static(",", name="Comma-2")

        s_string('"userId":', name="UserId-Key")
        s_int(maxsize**10, output_format="ascii", fuzzable=True, name="UserId-Value")
        s_static("}", name="JSON-End")

    session.connect(s_get("POST with Body Fuzzing"))
    session.fuzz()


if __name__ == "__main__":
    main()
