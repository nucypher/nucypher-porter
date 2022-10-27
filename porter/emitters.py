import json
import os
from http import HTTPStatus
from typing import Callable

from flask import Response

import porter
from nucypher.utilities.logging import Logger


def null_stream():
    return open(os.devnull, 'w')


class WebEmitter:

    class MethodNotFound(BaseException):
        """Cannot find interface method to handle request"""

    _crash_on_error_default = False
    transport_serializer = json.dumps
    _default_sink_callable = Response

    def __init__(self,
                 sink: Callable = None,
                 crash_on_error: bool = _crash_on_error_default,
                 *args, **kwargs):

        self.sink = sink or self._default_sink_callable
        self.crash_on_error = crash_on_error
        super().__init__(*args, **kwargs)

        self.log = Logger('web-emitter')

    def _log_exception(self, e, error_message, log_level, response_code):
        exception = f"{type(e).__name__}: {str(e)}" if str(e) else type(e).__name__
        message = f"{self} [{str(response_code)} - {error_message}] | ERROR: {exception}"
        logger = getattr(self.log, log_level)
        message_cleaned_for_logger = Logger.escape_format_string(message)
        logger(message_cleaned_for_logger)

    @staticmethod
    def assemble_response(response: dict) -> dict:
        response_data = {'result': response,
                         'version': str(porter.__version__)}
        return response_data

    def exception(self,
                  e,
                  error_message: str,
                  log_level: str = 'info',
                  response_code: int = 500):

        self._log_exception(e, error_message, log_level, response_code)
        if self.crash_on_error:
            raise e

        response_message = str(e) or type(e).__name__
        return self.sink(response_message, status=response_code)

    def exception_with_response(self,
                                json_error_response,
                                e,
                                error_message: str,
                                response_code: int,
                                log_level: str = 'info'):
        self._log_exception(e, error_message, log_level, response_code)
        if self.crash_on_error:
            raise e

        assembled_response = self.assemble_response(response=json_error_response)
        serialized_response = WebEmitter.transport_serializer(assembled_response)

        json_response = self.sink(response=serialized_response, status=response_code, content_type="application/json")
        return json_response

    def respond(self, json_response) -> Response:
        assembled_response = self.assemble_response(response=json_response)
        serialized_response = WebEmitter.transport_serializer(assembled_response)

        json_response = self.sink(response=serialized_response, status=HTTPStatus.OK, content_type="application/json")
        return json_response

    def get_stream(self, *args, **kwargs):
        return null_stream()
