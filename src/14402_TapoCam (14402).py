# coding: UTF-8

import logging
import tapo_lib.TapoDevice as TapoDevice


##!!!!##################################################################################################
#### Own written code can be placed above this commentblock . Do not change or delete commentblock! ####
########################################################################################################
##** Code created by generator - DO NOT CHANGE! **##

class TapoCam_14402_14402(hsl20_4.BaseModule):

    def __init__(self, homeserver_context):
        hsl20_4.BaseModule.__init__(self, homeserver_context, "14402_TapoCam")
        self.FRAMEWORK = self._get_framework()
        self.LOGGER = self._get_logger(hsl20_4.LOGGING_NONE,())
        self.PIN_I_HOST_IP=1
        self.PIN_I_PWD=2
        self.PIN_I_NOTIFICATIONS_ENABLED=3
        self.PIN_O_STATUS=1

########################################################################################################
#### Own written code can be placed after this commentblock . Do not change or delete commentblock! ####
###################################################################################################!!!##

        self.g_out_sbc = {}
        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.tapo_device = None
        self.child_id = str()

    def set_output_value_sbc(self, pin, val):
        self.logger.debug("Entering set_output_value_sbc({}, {})".format(pin, val))
        if pin in self.g_out_sbc:
            if self.g_out_sbc[pin] == val:
                print ("# SBC: pin " + str(pin) + " <- data not send / " + str(val).decode("utf-8"))
                return

        self._set_output_value(pin, val)
        self.g_out_sbc[pin] = val

    def init_tapo(self):
        self.logger.debug("Entering init_tapo()")
        self.tapo_device = TapoDevice.TapoDevice(self._get_input_value(self.PIN_I_HOST_IP),
                                                 self._get_input_value(self.PIN_I_PWD),
                                                 self.child_id)

        self.child_id = str(self.tapo_device.get_child_devices()[0])
        self.tapo_device.child_id = self.child_id

    def on_init(self):
        self.logger.debug("Entering on_init()")
        self.DEBUG = self.FRAMEWORK.create_debug_section()
        self.init_tapo()

    def on_input_value(self, index, value):
        self.logger.debug("Entering on_input_value({}, {})".format(index, value))

        if self.tapo_device is None or index == self.PIN_I_PWD or index == self.PIN_I_HOST_IP:
            self.init_tapo()

        if index == self.PIN_I_NOTIFICATIONS_ENABLED:
            try:
                if not self.tapo_device.set_notification_enabled(bool(value), False):
                    raise BaseException("Received 'False' as return calling set_notification_enabled({},False)".format(
                        bool(value)))

                if self.tapo_device.get_notification_enabled() != bool(value):
                    raise BaseException("Notification not set. Current value differs from commanded one calling " +
                                        "set_notification_enabled({},False)".format(bool(value)))
            except Exception as e:
                self.DEBUG.add_exception(e)


