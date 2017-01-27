import os
import sys
import requests
import logging

from splunklib.modularinput import *

def do_work(input_name, ew, path):
	filepath = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', 'SplunkForPCAP', 'bin', 'InputHistory.log')
	directory = os.path.dirname(filepath)
	if not os.path.exists(directory):
                os.makedirs(directory)
                
        t_path=os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', 'SplunkForPCAP', 'bin')
        filename = 'InputHistory.log'
	with open(os.path.join(t_path, filename), 'a+') as f:
                f.write(path+';'+'\n')
                f.close()

        lines = open(os.path.join(t_path, filename), 'r').readlines()
        lines_set = set(lines)
        out  = open(os.path.join(t_path, filename), 'w')
        for line in lines_set:
                out.write(line)


class MyScript(Script):

	def get_scheme(self):
		scheme = Scheme("PCAP File Location")
		scheme.description = "Location of PCAP files to be analyzed"
		scheme.use_external_validation = True
		scheme.use_single_instance = True

		path_argument = Argument("path")
		path_argument.data_type = Argument.data_type_string
		path_argument.description = "Please specify the full path of the PCAP file location"
		path_argument.required_on_create = True
		scheme.add_argument(path_argument)

		return scheme

	def validate_input(self, validation_definition):
		logging.error("PCAP4LIFE")
		path = str(validation_definition.parameters["path"])
		logging.error("path %s" % path)
		if len(symbol) < 1:
			raise ValueError("Incorrect Path")


	def stream_events(self, inputs, ew):
		 for input_name, input_item in inputs.inputs.iteritems():
			path = str(input_item["path"])
			do_work(input_name, ew, path)

if __name__ == "__main__":
	MyScript().run(sys.argv)
