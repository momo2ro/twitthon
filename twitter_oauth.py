# -*- coding: utf-8 -*-
from urllib import parse
from urllib import request
from urllib import error
from hashlib import sha1
from hashlib import md5
import os
import sys
import hmac
import codecs
import time
import uuid
import json
import mimetypes
import mybase64


class TwitterHandler(object):
    BASE_URL          = "https://api.twitter.com"
    OAUTH_VERSION     = "/1.1"

    def __init__(self, consumer_key, consumer_secret, access_token="", access_token_secret=""):
        self.set_consumer(consumer_key, consumer_secret)
        self.set_token(access_token, access_token_secret)

    def set_consumer(self, consumer_key, consumer_secret):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

    def set_token(self, token, token_secret):
        self.token = token
        self.token_secret = token_secret

    def get_consumer(self):
        return tuple([self.consumer_key, self.consumer_secret])

    def get_token(self):
        return tuple([self.token, self.token_secret])

    def _quote(self, text):
        return parse.quote(text, safe="~")

    def _escape(self, text):
        return self._quote(text).encode("utf-8")

    def oauth_request(self,
                      method,
                      endpoint,
                      body=None,
                      oauth_addition=None,
                      header_addition=None,
                      override_base_url=None,
                      override_version=None):
        base_url = self.BASE_URL if override_base_url is None else override_base_url
        version = self.OAUTH_VERSION if override_version is None else override_version
        request_url = base_url + version + endpoint
        oauth_header = self.make_oauth_header(method, request_url, body, oauth_addition)
        if method.upper() == "POST":
            if body is None:
                encoded_body = b"\r\n"
            elif isinstance(body, dict):
                encoded_body = "&".join(
                    '{0}={1}'.format(parse.quote_plus(k), parse.quote_plus(v))
                    for k, v in body.items()
                ).encode()
            else:
                encoded_body = body.encode()
        else:
            encoded_body = None
        if header_addition is not None:
            oauth_header.update(header_addition)
        req = request.Request(
            url=request_url,
            data=encoded_body,
            headers=oauth_header
        )
        try:
            with request.urlopen(req) as response:
                return response.read().decode("utf-8")
        except error.HTTPError as e:
            err_response = json.loads(e.read().decode("utf-8"))["errors"][0]
            print(err_response["message"], file=sys.stderr)
            sys.exit(1)
        except error.URLError as e:
            print(e.reason, file=sys.stderr)
            sys.exit(1)

    def make_oauth_header(self, method, url, body=None, oauth_addition=None):
        params = {
            "oauth_consumer_key": self.consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": md5(codecs.encode(str(uuid.uuid4()))).hexdigest(),
            "oauth_version": "1.0"
        }
        if self.token != "":
            params["oauth_token"] = self.token
        if body is not None and isinstance(body, dict):
            params.update(body)
        if oauth_addition is not None:
            params.update(oauth_addition)
        params["oauth_signature"] = self._make_signature(method, url, params)
        return {"Authorization": "OAuth " + ",".join(
            '{0}="{1}"'.format(self._quote(k), self._quote(v)) for k, v in params.items()
            if "oauth_" in k
        )}

    def _make_signature(self, method, url, oauth_params):
        url_elements = parse.urlparse(url)
        base_str_uri = url_elements.scheme + "://" + url_elements.netloc + url_elements.path

        querys = parse.parse_qs(url_elements.query)
        oauth_params.update(querys)
        oauth_params_str = "&".join(
            "=".join(self._quote(x) for x in y)
            for y in sorted(oauth_params.items())
        )

        key = b"&".join([self._escape(x) for x in [
            self.consumer_secret, self.token_secret
        ]])
        sig_base_str = b"&".join([self._escape(x) for x in [
            method, base_str_uri, oauth_params_str
        ]])
        sig_bytes = hmac.new(key, sig_base_str, sha1).digest()
        return mybase64.byte_encode(sig_bytes)


class TwitterAuthorizer(TwitterHandler):

    class Authorize:
        OAUTH_VERSION = ""
        ENDPOINT = "/oauth/authorize"

    class AccessToken:
        METHOD = "POST"
        OAUTH_VERSION = ""
        ENDPOINT = "/oauth/access_token"

    class RequestToken:
        METHOD = "POST"
        OAUTH_VERSION = ""
        ENDPOINT = "/oauth/request_token"

    def __init__(self, consumer_key, consumer_secret):
        super(TwitterAuthorizer, self).__init__(consumer_key,
                                                consumer_secret)

    def receive_temporary(self, callback_url="oob"):
        oauth_addition = {"oauth_callback": callback_url}
        result_body = self.oauth_request(method=self.RequestToken.METHOD,
                                         endpoint=self.RequestToken.ENDPOINT,
                                         oauth_addition=oauth_addition,
                                         override_version=self.RequestToken.OAUTH_VERSION)
        result_dict = parse.parse_qs(result_body)
        self.set_token(result_dict["oauth_token"][0], result_dict["oauth_token_secret"][0])
        return self

    def get_authorization_url(self, callback_url="oob"):
        self.receive_temporary(callback_url)
        return self.BASE_URL + self.Authorize.ENDPOINT + "/?oauth_token=" + self.token

    def receive_token(self, verifier):
        oauth_addition = {"oauth_verifier": verifier}
        result_body = self.oauth_request(method=self.AccessToken.METHOD,
                                         endpoint=self.AccessToken.ENDPOINT,
                                         oauth_addition=oauth_addition,
                                         override_version=self.AccessToken.OAUTH_VERSION)
        result_dict = parse.parse_qs(result_body)
        self.set_token(result_dict["oauth_token"][0], result_dict["oauth_token_secret"][0])
        return self

    def get_token(self, verifier):
        self.receive_token(verifier)
        return super(TwitterAuthorizer, self).get_token()


class TwitterSession(TwitterHandler):

    class StatusUpdate:
        METHOD = "POST"
        ENDPOINT = "/statuses/update.json"

    class DirectMessageNew:
        METHOD = "POST"
        ENDPOINT = "/direct_messages/new.json"

    class MediaUpload:
        METHOD = "POST"
        BASE_URL = "https://upload.twitter.com"
        ENDPOINT = "/media/upload.json"

    class AccountVerifyCredentials:
        METHOD = "GET"
        ENDPOINT = "/account/verify_credentials.json"

    def __init__(self, consumer_key, consumer_secret, access_token, access_token_secret):
        super(TwitterSession, self).__init__(consumer_key,
                                             consumer_secret,
                                             access_token,
                                             access_token_secret)

    def status_update(self, status, media_ids=[]):
        body = {"status": status}
        if bool(media_ids):
            body["media_ids"] = ",".join(media_ids)
        self.oauth_request(method=self.StatusUpdate.METHOD,
                           endpoint=self.StatusUpdate.ENDPOINT,
                           body=body)
        return True

    def direct_message_new(self, text, screen_name, user_id):
        body = {"text": text}
        if bool(screen_name):
            body["screen_name"] = screen_name
        elif bool(user_id):
            body["user_id"] = user_id
        else:
            print("screen_name or user_id must be assign!", file=sys.stderr)
            sys.exit(1)
        self.oauth_request(method=self.DirectMessageNew.METHOD,
                           endpoint=self.DirectMessageNew.ENDPOINT,
                           body=body)
        return True

    def media_upload(self, file_path):
        mime_type = mimetypes.guess_type(file_path)[0]
        if mime_type == "video/mp4":
            return self.media_upload_chuncked(file_path, mime_type)
        elif mime_type in ["image/png",
                           "image/jpeg",
                           "image/bmp",
                           "image/webp",
                           "image/gif"]:
            return self.media_upload_unchuncked(file_path)
        else:
            print("File Type is not available.", file=sys.stderr)
            sys.exit(1)

    def media_upload_unchuncked(self, file_path):
        encoded_data = self._file_encode(file_path)
        boundary = "SMALLDICK" + md5(codecs.encode(str(uuid.uuid4()))).hexdigest()
        body = {"media_data": encoded_data}
        response_body = self.multipart_post(boundary, body)
        return json.loads(response_body)["media_id_string"]

    def media_upload_chuncked(self, file_path, mime_type="video/mp4"):
        # INIT
        file_size = os.path.getsize(file_path)
        body = {"command": "INIT",
                "media_type": mime_type,
                "total_bytes": str(file_size)}
        response_body = self.oauth_request(method=self.MediaUpload.METHOD,
                                           endpoint=self.MediaUpload.ENDPOINT,
                                           body=body,
                                           override_base_url=self.MediaUpload.BASE_URL)
        media_id = json.loads(response_body)["media_id_string"]
        # APPEND
        encoded_data = self._file_encode(file_path)
        boundary = "SMALLDICK" + md5(codecs.encode(str(uuid.uuid4()))).hexdigest()
        body = {"media_data": encoded_data,
                "command": "APPEND",
                "media_id": media_id,
                "segment_index": 0}
        self.multipart_post(boundary, body)
        # FINALIZE
        body = {"command": "FINALIZE",
                "media_id": media_id}
        self.oauth_request(method=self.MediaUpload.METHOD,
                           endpoint=self.MediaUpload.ENDPOINT,
                           body=body,
                           override_base_url=self.MediaUpload.BASE_URL)
        return str(media_id)

    def _file_encode(self, file_path):
        with open(file_path, mode="br") as f:
            raw_data = b""
            for buff in f:
                raw_data += buff
        return mybase64.byte_encode(raw_data)

    def multipart_post(self, boundary, body):
        header_addition = {"Content-Type": "multipart/form-data; boundary=" + boundary}
        form_body = "".join(self._form_onepart(boundary, k, v) for k, v in body.items())
        form_body += "--{0}--".format(boundary)
        return self.oauth_request(method=self.MediaUpload.METHOD,
                                  endpoint=self.MediaUpload.ENDPOINT,
                                  body=form_body,
                                  header_addition=header_addition,
                                  override_base_url=self.MediaUpload.BASE_URL)

    def _form_onepart(self, boundary, key, value):
        if key == "media_data":
            return ("--{0}\r\n"
                    'Content-Disposition: form-data; name="{1}"\r\n'
                    'Content-Type: application/octet-stream\r\n'
                    'Content-Transfer-Encoding: base64\r\n\r\n'
                    "{2}\r\n").format(boundary, key, value)
        else:
            return ("--{0}\r\n"
                    'Content-Disposition: form-data; name="{1}"\r\n'
                    'Content-Type: application/octet-stream\r\n\r\n'
                    "{2}\r\n").format(boundary, key, value)

    def account_verify_credentials(self):
        response_body = self.oauth_request(method=self.AccountVerifyCredentials.METHOD,
                                           endpoint=self.AccountVerifyCredentials.ENDPOINT)
        return json.loads(response_body)
