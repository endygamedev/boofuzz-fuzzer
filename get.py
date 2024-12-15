from typing import Any

from boofuzz import (
    Session,
    FuzzLogger,
    Target,
    SocketConnection,
    s_initialize,
    s_block_start,
    s_block_end,
    s_static,
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

    s_initialize("GET Fuzzing")
    if s_block_start("Request-Line"):
        s_static(
            "GET /posts/",
            name="Request-Line-Start",
        )
        s_int(
            1,
            output_format="ascii",
            fuzzable=True,
            name="Post-ID",
        )
        s_static(" HTTP/1.1\r\n", name="Request-Line-End")
    s_block_end("Request-Line")

    if s_block_start("Headers"):
        s_static(
            "Host: jsonplaceholder.typicode.com",
            name="Host-Header",
        )
        s_static(
            "\r\n\r\n",
            name="Header-End",
        )
    s_block_end("Headers")

    session.connect(s_get("GET Fuzzing"))
    session.fuzz()


if __name__ == "__main__":
    main()
