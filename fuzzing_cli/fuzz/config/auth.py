import base64
import json
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import requests

from fuzzing_cli.fuzz.exceptions import AuthorizationError

from .options import FuzzingOptions


class AuthHandler:
    def __init__(self, options: FuzzingOptions):
        self.options = options

        self._refresh_token: Optional[str] = None
        self._api_key: Optional[str] = None
        self._expires_at: Optional[datetime] = None

    def _decode_api_key(self) -> Dict[str, Any]:
        payload = self.api_key.split(".")[1]
        input_bytes = payload.encode("utf-8")
        remainder = len(input_bytes) % 4
        if remainder > 0:
            # here we need to correct the padding
            input_bytes += b"=" * (4 - remainder)

        return json.loads(base64.urlsafe_b64decode(input_bytes))

    @property
    def user_id(self) -> str:
        token_data = self._decode_api_key()
        return token_data["sub"]

    def _get_access_token(self) -> Tuple[str, int]:
        response = requests.post(
            f"https://{self.options.auth_endpoint}/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.options.auth_client_id,
                "refresh_token": self.options.refresh_token,
            },
        )
        body = response.json()
        if response.status_code != 200:
            error = body.get("error", "")
            description = body.get("error_description", "")
            raise AuthorizationError(
                f"Authorization failed. Error: {error}", detail=description
            )
        return body.get("access_token"), body.get("expires_in", 0)

    @property
    def api_key(self) -> str:
        if (
            # if user has set another refresh token, we need to refresh the api key as well
            self.options.refresh_token == self._refresh_token
            and self._api_key
            and self._expires_at
            and self._expires_at > datetime.now()
        ):
            return self._api_key

        self._refresh_token = self.options.refresh_token
        access_token, expires_in = self._get_access_token()
        self._api_key = access_token
        self._expires_at = datetime.now() + timedelta(seconds=expires_in)
        return self._api_key
