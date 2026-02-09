import time

import requests


class KSEFAuthTimeoutError(RuntimeError):
    pass


class KSEFAuthFailError(RuntimeError):
    auth_state: dict

    def __init__(self, auth_state):
        status_code = auth_state["status"]["code"]
        super(f"Authentication failed with status code: {status_code}")
        self.auth_state = auth_state


def ksef_get_auth_state(api_base_url: str, reference_number: str, authentication_token: str) -> dict:
    res = requests.get(f"{api_base_url}/auth/{reference_number}",
                       headers={"Authorization": f"Bearer {authentication_token}"})
    res.raise_for_status()
    return res.json()


def ksef_redeem_token(api_base_url: str, authentication_token: str) -> dict:
    res = requests.post(f"{api_base_url}/auth/token/redeem",
                        headers={"Content-Type": "application/json",
                                 "Authorization": f"Bearer {authentication_token}"})
    res.raise_for_status()
    return res.json()


def ksef_poll_auth_finalized(
        *,
        api_base_url: str,
        reference_number: str,
        authentication_token: str,
        poll_interval: float=1.0,
        timeout: float=120.0) -> dict:
    if poll_interval < 0.1:
        raise ValueError("Poll interval is smaller than 0.1s")

    start_time = time.time()

    while True:
        if timeout != 0.0 and time.time() - start_time > timeout:
            raise KSEFAuthTimeoutError(f"Failed to finish authentication within {timeout} seconds timeout.")

        state = ksef_get_auth_state(api_base_url, reference_number, authentication_token)

        if state["status"]["code"] != 100:
            break

        time.sleep(poll_interval)

    if state["status"]["code"] != 200:
        raise KSEFAuthFailError(state)

    return {
        "redeemResult": ksef_redeem_token(api_base_url, authentication_token),
        "authState": state
    }
