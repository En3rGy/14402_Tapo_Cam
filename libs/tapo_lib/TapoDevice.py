import logging
import hashlib
import urllib
import urllib2
import ssl
import json
import datetime
import time
import os


class TapoDevice:
    ERROR_CODES = {
        "-40401": "Invalid stok value",
        "-40413": "?",
        "-40210": "Function not supported",
        "-64303": "Action cannot be done while camera is in patrol mode.",
        "-64324": "Privacy mode is ON, not able to execute",
        "-64302": "Preset ID not found",
        "-64321": "Preset ID was deleted so no longer exists",
        "-40106": "Parameter to get/do does not exist",
        "-40105": "Method does not exist",
        "-40101": "Parameter to set does not exist",
        "-40209": "Invalid login credentials",
    }

    def __init__(self, host_ip, password, child_id=None):
        self.user = str()
        self.cnonce = str()
        self.hashedSha256Password = None
        self.is_secure_connection_cached = None
        self.time_correction = False
        self.logger = logging.getLogger(__name__)
        self.password = password
        self.host = host_ip
        self.stok = str()
        self.child_id = child_id
        self.user_id = str()

    def get_error_str(self, code):
        return self.ERROR_CODES.get(str(code), str(code))

    def get_https_response(self, url, data):
        self.logger.debug("Entering get_https_response({}, {})".format(url, data))

        ctx = ssl._create_unverified_context()

        headers = {"Host": self.host,
                   "Referer": "https://{}".format(self.host),
                   "Accept": "application/json",
                   "Accept-Encoding": "gzip, deflate",
                   "User-Agent": "Tapo CameraClient Android",
                   "Connection": "close",
                   "requestByApp": "true",
                   "Content-Type": "application/json; charset=UTF-8"
                   }

        try:
            request = urllib2.Request(url, data=json.dumps(data), headers=headers)
            response = urllib2.urlopen(request, timeout=30, context=ctx)

            result = response.read()
            ret_code = response.getcode()
            json_result = json.loads(result)
            self.logger.debug("get_https_response | In get_https_response, code {}, {}".format(ret_code, result))

            if ret_code == 200:
                if json_result["error_code"] == 0 or json_result["error_code"] == -40413:
                    return json_result
                else:
                    if "method" not in json_result:
                        json_result["method"] = "?"

                    error_str = "get_https_response | Received error {} ({}) " \
                                "trying to run method '{}'".format(json_result["error_code"],
                                                                   self.get_error_str(json_result["error_code"]),
                                                                   data["method"])
                    self.logger.error(error_str)
                    raise Exception(error_str)

            elif ret_code == 401:
                try:
                    if json_result["result"]["data"]["code"] == -40411:
                        self.logger.error("Code is -40411, raising Exception.")
                        raise Exception("Invalid authentication data")
                except Exception as e:
                    if str(e) == "Invalid authentication data":
                        raise e
                    else:
                        pass
            else:
                raise BaseException("Connecting to {} returns http code {}".format(url, ret_code))

        except urllib2.HTTPError as e:
            self.logger.info("get_https_response | Code {}, '{}'".format(e.code, e.message))
        except urllib2.URLError as e:
            self.logger.info("get_https_response | {}".format(e.message))

    def get_host_name(self):
        return "https://{}/stok={}/ds".format(self.host, self.stok if self.stok else self.get_stok())

    def is_secure_connection(self):
        self.logger.debug("Entering is_secure_connection()")
        if self.is_secure_connection_cached is None:
            url = "https://{host}".format(host=self.host)
            data = {
                "method": "login",
                "params": {
                    "encrypt_type": "3",
                    "username": "admin",
                },
            }

            ctx = ssl._create_unverified_context()

            headers = {"Host": self.host,
                       "Referer": "https://{}".format(self.host),
                       "Accept": "application/json",
                       "Accept-Encoding": "gzip, deflate",
                       "User-Agent": "Tapo CameraClient Android",
                       "Connection": "close",
                       "requestByApp": "true",
                       "Content-Type": "application/json; charset=UTF-8"
                       }

            res = urllib2.Request(url, data=json.dumps(data), headers=headers)
            res = urllib2.urlopen(res, timeout=30, context=ctx)
            response = json.loads(res.read())

            print("{}".format(response))

            print()
            self.is_secure_connection_cached = (
                "error_code" in response
                and response["error_code"] == -40413
                and "result" in response
                and "data" in response["result"]
                and "encrypt_type" in response["result"]["data"]
                and "3" in response["result"]["data"]["encrypt_type"]
            )
        return self.is_secure_connection_cached

    def validate_device_confirm(self, nonce, device_confirm):
        hashed_nonces_with_sha256 = (
            hashlib.sha256(
                self.cnonce.encode("utf8")
                + self.hashedSha256Password.encode("utf8")
                + nonce.encode("utf8")
            )
            .hexdigest()
            .upper()
        )
        hashed_nonces_with_md5 = (
            hashlib.md5(
                self.cnonce.encode("utf8")
                + self.hashedPassword.encode("utf8")
                + nonce.encode("utf8")
            )
            .hexdigest()
            .upper()
        )
        if device_confirm == (hashed_nonces_with_sha256 + nonce + self.cnonce):
            password_encryption_method = "SHA256"
        elif device_confirm == (hashed_nonces_with_md5 + nonce + self.cnonce):
            password_encryption_method = "MD5"
        else:
            password_encryption_method = str()
        return password_encryption_method is not None

    def generate_nonce(self, length):
        self.logger.debug("Entering generate_nonce({})".format(length))
        return os.urandom(length).hex().encode()

    def get_hashed_password(self):
        return hashlib.md5(self.password.encode("utf8")).hexdigest().upper()

    def get_stok(self):
        self.logger.debug("Entering get_stok()")

        if self.is_secure_connection():
            self.logger.debug("get_stok | Connection is secure.")
            cnonce = self.generate_nonce(8).decode().upper()
            data = {
                "method": "login",
                "params": {
                    "cnonce": cnonce,
                    "encrypt_type": "3",
                    "username": self.user,
                },
            }
        else:
            self.logger.debug("get_stok | Connection is insecure.")
            hashed_password = self.get_hashed_password()
            data = {
                "method": "login",
                "params": {
                    "hashed": True,
                    "password": hashed_password,
                    "username": "admin",
                },
            }

        url = f"https://{self.host}"

        json_result = {}
        try:
            json_result = self.get_https_response(url, data)
        except Exception as e:
            self.logger.debug(f"get_stock | {e}")
            raise e

        if self.is_secure_connection():
            self.logger.debug("get_stok | Processing secure response.")
            if ("result" in json_result and "data" in json_result["result"]
                    and "nonce" in json_result["result"]["data"] and "device_confirm" in json_result["result"]["data"]):
                self.logger.debug("Validating device confirm.")
                nonce = json_result["result"]["data"]["nonce"]
                if self.validate_device_confirm(nonce, json_result["result"]["data"]["device_confirm"]):
                    # sets self.passwordEncryptionMethod, password verified on client, now request stok
                    self.logger.debug("get_stok | Signing in with digest_passwd.")
                    digest_passwd = (
                        hashlib.sha256(
                            self.get_hashed_password().encode("utf8")
                            + self.cnonce.encode("utf8")
                            + nonce.encode("utf8")
                        )
                        .hexdigest()
                        .upper()
                    )
                    data = {
                        "method": "login",
                        "params": {
                            "cnonce": self.cnonce,
                            "encrypt_type": "3",
                            "digest_passwd": (
                                digest_passwd.encode("utf8")
                                + self.cnonce.encode("utf8")
                                + nonce.encode("utf8")
                            ).decode(),
                            "username": self.user,
                        },
                    }
                    res = urllib.request(
                        "POST",
                        url,
                        data=json.dumps(data),
                        headers=self.headers,
                        verify=False,
                    )
                    response_data = res.json()
                    if (
                        "result" in response_data
                        and "start_seq" in response_data["result"]
                    ):
                        if (
                            "user_group" in response_data["result"]
                            and response_data["result"]["user_group"] != "root"
                        ):
                            self.logger.debug("Incorrect user_group detected, raising Exception.")
                            # encrypted control via 3rd party account does not seem to be supported
                            # see https://github.com/JurajNyiri/HomeAssistant-Tapo-Control/issues/456
                            raise Exception("get_stok | Invalid authentication data")
                        self.logger.debug("get_stok | Geneerating encryption tokens.")
                        self.lsk = self.generateEncryptionToken("lsk", nonce)
                        self.ivb = self.generateEncryptionToken("ivb", nonce)
                        self.seq = response_data["result"]["start_seq"]
                    else:
                        if (
                            self.retryStok
                            and (
                                "error_code" in response_data
                                and response_data["error_code"] == -40413
                            )
                            and loginRetryCount < MAX_LOGIN_RETRIES
                        ):
                            loginRetryCount += 1
                            self.logger.debug(
                                f"Incorrect device_confirm value, retrying: {loginRetryCount}/{MAX_LOGIN_RETRIES}."
                            )
                            return self.refreshStok(loginRetryCount)
                        else:
                            self.logger.debug("Incorrect device_confirm value, raising Exception.")
                            raise Exception("Invalid authentication data")
        else:
            self.password_EncryptionMethod = "MD5"
        if (
            "result" in response_data
            and "data" in response_data["result"]
            and "time" in response_data["result"]["data"]
            and "max_time" in response_data["result"]["data"]
            and "sec_left" in response_data["result"]["data"]
            and response_data["result"]["data"]["sec_left"] > 0
        ):
            raise Exception(
                f"Temporary Suspension: Try again in {str(response_data['result']['data']['sec_left'])} seconds"
            )
        if (
            "data" in response_data
            and "code" in response_data["data"]
            and "sec_left" in response_data["data"]
            and response_data["data"]["code"] == -40404
            and response_data["data"]["sec_left"] > 0
        ):
            raise Exception(
                f"Temporary Suspension: Try again in {str(response_data['data']['sec_left'])} seconds"
            )

        if self.responseIsOK(res):
            self.logger.debug("Saving stok.")
            self.stok = res.json()["result"]["stok"]
            return self.stok
        if (
            self.retryStok
            and ("error_code" in response_data and response_data["error_code"] == -40413)
            and loginRetryCount < MAX_LOGIN_RETRIES
        ):
            loginRetryCount += 1
            self.logger.debug(
                f"Unexpected response, retrying: {loginRetryCount}/{MAX_LOGIN_RETRIES}."
            )
            return self.refreshStok(loginRetryCount)
        else:
            self.logger.debug("Unexpected response, raising Exception.")
            raise Exception("Invalid authentication data")



        # todo: continue with https://github.com/JurajNyiri/pytapo/blob/5e7df7d0e05065d2f04990cb1db0a2cd75d13775/pytapo/__init__.py

        if len(json_result) > 0:
            self.stok = json_result["result"]["stok"]
            self.logger.debug("get_stock | self.stok = {}".format(self.stok))

            return self.stok
        else:
            return str()

    def check_stok(self):
        self.logger.debug("Entering check_stok()")
        if not self.stok:
            self.get_stok()
        else:
            try:
                self.get_basic_info(False)
            except BaseException as e:
                if "40401" in str(e):
                    self.get_stok()

    def get_basic_info(self, check_stok=True):
        self.logger.debug("Entering get_basic_info()")
        if check_stok:
            self.check_stok()

        method = "getDeviceInfo"
        params = {"device_info": {"name": ["basic_info"]}}

        req_data = {"method": "multipleRequest",
                    "params": {"requests": [{"method": method, "params": params}]}
                    }
        if self.child_id:
            req_data = {"method": "multipleRequest",
                        "params": {"requests": [{
                            "method": "controlChild",
                            "params": {"childControl": {"device_id": self.child_id, "request_data": req_data}}}
                        ]}}

        ret = self.get_https_response(self.get_host_name(), req_data)
        self.logger.debug(ret)
        return ret

    def get_child_devices(self):
        self.logger.debug("Entering get_child_devices()")
        ret = self.perform_request({
            "method": "getChildDeviceList",
            "params": {"childControl": {"start_index": 0}}
        })

        child_device_list = ret["result"]["child_device_list"]
        child_list = {}
        for device in child_device_list:
            child_list[device["device_id"]] = device
        self.logger.debug("Child Devices: {}".format(child_list.keys()))
        return child_device_list

    def execute_function(self, method, params):
        self.logger.debug("Entering execute_function({}, {})".format(method, params))
        if method == "multipleRequest":
            data = self.perform_request({"method": "multipleRequest", "params": params})
            data = data["result"]["responses"]
        else:
            data = self.perform_request(
                {
                    "method": "multipleRequest",
                    "params": {"requests": [{"method": method, "params": params}]}
                }
            )
            data = data["result"]["responses"][0]

        if type(data) == list:
            return data

        if "result" in data and ("error_code" not in data or ("error_code" in data and data["error_code"] == 0)):
            return data["result"]

    def get_time(self):
        return self.execute_function(
            "getClockStatus", {"system": {"name": "clock_status"}}
        )

    def perform_request(self, request_data):
        self.logger.debug("Entering perform_request({})".format(request_data))
        self.check_stok()
        # self.ensure_authenticated()
        url = self.get_host_name()
        if self.child_id:
            full_request = {
                "method": "multipleRequest",
                "params": {
                    "requests": [{
                        "method": "controlChild",
                        "params": {"childControl": {"device_id": self.child_id, "request_data": request_data}}
                    }]
                }
            }
        else:
            full_request = request_data

        res = self.get_https_response(url, full_request)

        if self.child_id:
            responses = []
            for response in res["result"]["responses"]:
                if "method" in response and response["method"] == "controlChild":
                    if "response_data" in response["result"]:
                        responses.append(response["result"]["response_data"])
                    else:
                        responses.append(response["result"])
                else:
                    responses.append(response["result"])  # not sure if needed
            res["result"]["responses"] = responses
            res = res["result"]["responses"][0]
        return res

    def get_user_id(self):
        self.logger.debug("Entering get_user_id()")
        if not self.user_id:
            request = {"method": "getUserID",
                       "params": {"system": {"get_user_id": "null"}}}

            res = self.perform_request(request)

            self.user_id = res["result"]["user_id"]
        self.logger.debug("self.user_id = {}".format(self.user_id))
        return self.user_id

    def get_recordings_utc(self, date=None, start_index=0, end_index=999999999):
        if date is None:
            date = datetime.date.today().strftime("%Y%m%d")

        date_object = datetime.datetime.strptime(date, "%Y%m%d")
        start_time = int(time.mktime(date_object.timetuple()))
        end_time = int(time.mktime((date_object + datetime.timedelta(hours=23, minutes=59, seconds=59)).timetuple()))

        result = self.execute_function(
            "searchVideoWithUTC",
            {
                "playback": {
                    "search_video_with_utc": {
                        "channel": 0,
                        "end_time": end_time,
                        "end_index": end_index,
                        "id": self.get_user_id(),
                        "start_index": start_index,
                        "start_time": start_time
                    }
                }
            }
        )
        if "playback" not in result:
            raise Exception("Video playback is not supported by this camera")
        return result["playback"]["search_video_results"]

    def get_recordings_list(self, start_date="20230701", end_date=None):
        if end_date is None:
            end_date = datetime.date.today().strftime("%Y%m%d")

        result = self.execute_function(
            "searchDateWithVideo",
            {
                "playback": {
                    "search_year_utility": {
                        "channel": [0],
                        "end_date": end_date,
                        "start_date": start_date,
                    }
                }
            },
        )
        if "playback" not in result:
            raise Exception("Video playback is not supported by this camera")
        return result["playback"]["search_results"]

    def get_time_correction(self):
        if self.time_correction is False:
            current_time = self.get_time()

            time_returned = (
                    "system" in current_time
                    and "clock_status" in current_time["system"]
                    and "seconds_from_1970" in current_time["system"]["clock_status"]
            )
            if time_returned:
                now_ts = int(time.time())
                self.time_correction = (
                        now_ts - current_time["system"]["clock_status"]["seconds_from_1970"]
                )
        return self.time_correction

    def get_events(self, start_time=False, end_time=False):
        """
        Fetches a list of events that occurred within a specified time window.

        This method will attempt to fetch the list of events detected by a camera, where each event is represented as a
        dictionary. If start_time and end_time are not provided, the method defaults to a time window of 10 minutes
        before and one minute after the current time.

        @type start_time: int or bool
        @param start_time: The start of the time window for fetching events, in Unix timestamp format (seconds since
                           the Epoch). If False, default is 10 hours before the current time.
        @type end_time: int or bool
        @param end_time: The end of the time window for fetching events, in Unix timestamp format (seconds since the
                         Epoch). If False, default is one minute after the current time.
        @rtype: list[dict]
        @return: A list of events. Each event is a dictionary that includes the adjusted start_time and end_time (i.e.,
                 corrected with camera's time), and also relative start and end times with respect to the time of this
                 method execution. If no events are found, an empty list is returned.
        @raise Exception: If failed to get correct camera time.
        """
        time_correction = self.get_time_correction()
        # if not time_correction:
        #     raise Exception("Failed to get correct camera time.")

        now_ts = int(time.time())
        if start_time is False:
            start_time = now_ts + (-1 * time_correction) - (10 * 60 * 60)
        if end_time is False:
            end_time = now_ts + (-1 * time_correction) + 60

        response_data = self.execute_function(
            "searchDetectionList",
            {
                "playback": {
                    "search_detection_list": {
                        "start_index": 0,
                        "channel": 0,
                        "start_time": start_time,
                        "end_time": end_time,
                        "end_index": 99,
                    }
                }
            }
        )
        events = []

        detections_returned = (
                "playback" in response_data
                and "search_detection_list" in response_data["playback"]
        )

        if detections_returned:
            for event in response_data["playback"]["search_detection_list"]:
                event["start_time"] = event["start_time"] + time_correction
                event["end_time"] = event["end_time"] + time_correction
                event["startRelative"] = now_ts - event["start_time"]
                event["endRelative"] = now_ts - event["end_time"]
                events.append(event)
        return events

    def search_detection_list(self, start_time, end_time, start_index=0, end_index=999999999):
        result = self.execute_function(
            "searchDetectionList",
            {
                "playback": {
                    "search_detection_list": {
                        "channel": 0,
                        "end_index": end_index,
                        "end_time": end_time,
                        "start_index": start_index,
                        "start_time": start_time
                    }
                }
            }
        )
        if "playback" not in result:
            raise Exception("Video playback is not supported by this camera")
        return result["playback"]["search_video_results"]

    def get_recordings(self, date=None):
        self.logger.debug("Entering get_recordings({})".format(date))
        self.check_stok()
        if date is None:
            date = datetime.date.today().strftime("%Y%m%d")

        # date_object = datetime.datetime.strptime(date, "%Y%m%d")
        # start_time = int(time.mktime(date_object.timetuple()))
        # end_time = int(time.mktime((date_object + datetime.timedelta(hours=23, minutes=59, seconds=59)).timetuple()))

        method = "searchVideoOfDay"
        params = {
            "playback": {
                "search_video_utility": {
                    "channel": 0,
                    "date": date,
                    "end_index": 999999999,
                    "id": self.user_id if self.user_id else self.get_user_id(),
                    "start_index": 0,
                }
            }
        }

        req_data = {"method": "multipleRequest",
                    "params": {"requests": [{"method": method, "params": params}]}
                    }

        ret = self.get_https_response(self.get_host_name(), req_data)
        ret = ret["result"]["responses"][0]

        if ret["error_code"] == 0:
            pass
        else:
            error_str = "get_recordings | Received error {} ({}) " \
                        "trying to run method '{}'".format(ret["error_code"],
                                                           self.get_error_str(ret["error_code"]),
                                                           ret["method"])
            self.logger.error(error_str)
            raise BaseException(error_str)

        self.logger.debug(ret)
        return ret

    def set_notification_enabled(self, notification_enabled=True, rich_notification_enabled=False):
        """
        Sets the status of the notification and rich notification settings.

        :param notification_enabled: Indicates if the notification setting should be turned on or off.
                                     Defaults to True (on).
        :type notification_enabled: bool, optional

        :param rich_notification_enabled: Indicates if the rich notification setting should be turned on or off.
                                          Defaults to False (off).
        :type rich_notification_enabled: bool, optional

        :returns: True if the request was successful (i.e., the response from the 'execute_function' is an
                  empty dictionary), False otherwise.
        :rtype: bool

        :raises: Exception: Any exceptions raised by 'execute_function' or if the response structure is not
                            as expected.
        """
        self.logger.debug("Entering set_notification_enabled({}, {})".format(notification_enabled,
                                                                             rich_notification_enabled))
        params = {
            "msg_push": {
                "chn1_msg_push_info": {
                    "notification_enabled": "on" if notification_enabled else "off",
                    "rich_notification_enabled": "on" if rich_notification_enabled else "off"
                }
            }
        }
        result = self.execute_function("setMsgPushConfig", params)

        # {"method":"controlChild","result":{"response_data":{"result":{"responses":[{"method":"setMsgPushConfig","error_code":-1805}
        if result != {}:
            self.logger.warning("In set_notification_enabled, result was <{}>".format(result))
        return result == {}

    def get_notification_enabled(self):
        """
        This method retrieves the status of the notification setting.

        :returns: A boolean. True if the 'notification_enabled' in 'chn1_msg_push_info' is equal to 'on',
                  False otherwise.
        :rtype: bool

        :raises: Exception: Any exceptions raised by 'perform_request' or if the response structure is not as expected.
        """
        self.logger.debug("Entering get_notification_enabled()")
        params = {
            "method": "getMsgPushConfig",
            "params": {"msg_push": {"name": "chn1_msg_push_info"}}
        }
        result = self.perform_request(params)
        result = result["result"]["msg_push"]["chn1_msg_push_info"]["notification_enabled"]
        result = str(result).lower()
        return True if result == "on" else False

    def get_video(self, start_time, end_time):
        self.logger.debug("Entering get_video({}, {})".format(start_time, end_time))
        self.check_stok()
        payload = {
            "type": "request",
            "seq": 1,
            "params": {
                "playback": {
                    "client_id": self.user_id,
                    "channels": [0, 1],
                    "scale": "1/1",
                    "start_time": start_time,
                    "end_time": end_time,
                    "event_type": [1, 2]
                },
                "method": "get"
            }
        }

        url = self.get_host_name()
        res = self.get_https_response(url, payload)

        return res
