import os
import sys
import logging

from splunklib.modularinput import *

class MyScript(Script):

    def get_scheme(self):
        scheme = Scheme("PCAP File Location")
        scheme.description = "Location of PCAP files to be analyzed"
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        path_argument = Argument("path")
        path_argument.data_type = Argument.data_type_string
        path_argument.description = "Please specify the full path of the PCAP file location"
        path_argument.required_on_create = True
        scheme.add_argument(path_argument)

        return scheme

    def validate_input(self, validation_definition):
        path = str(validation_definition.parameters["path"])
        if len(path) < 1 :
            raise ValueError("Please specify a path!")

    def stream_events(self, inputs, ew):
        if (sys.version_info > (3, 0)):
            for input_name, input_item in inputs.inputs.items():
                path = str(input_item["path"])

                event = Event()
                event.stanza = input_name
                event.data = 'path="%s"'

                ew.write_event(event)		    

        else:
            for input_name, input_item in inputs.inputs.iteritems():
                path = str(input_item["path"])

                event = Event()
                event.stanza = input_name
                event.data = 'path="%s"'

                ew.write_event(event)

if __name__ == "__main__":
    sys.exit(MyScript().run(sys.argv))
