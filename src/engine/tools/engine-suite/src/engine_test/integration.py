import yaml
try:
    from yaml import CDumper as Dumper
except ImportError:
    from yaml import Dumper

from engine_test.events_collector import EventsCollector
from engine_test.formats.syslog import SyslogFormat
from engine_test.formats.json import JsonFormat
from engine_test.formats.eventchannel import EventChannelFormat
from engine_test.formats.macos import MacosFormat
from engine_test.formats.remote_syslog import RemoteSyslogFormat
from engine_test.formats.audit import AuditFormat
from engine_test.formats.command import CommandFormat
from engine_test.formats.full_command import FullCommandFormat
from engine_test.formats.multi_line import MultilineFormat
from engine_test.event_format import Formats
from engine_test.crud_integration import CrudIntegration

from engine_test.api_connector import ApiConnector

class Integration(CrudIntegration):
    def __init__(self, args):
        self.args = args

        # Get the integration
        try:
            integration_name = self.args['integration-name']
        except KeyError as ex:
            print("Integration name not foud. Error: {}".format(ex))
            exit(1)

        self.integration = self.get_integration(integration_name)
        if not self.integration:
            print("Integration not found!")
            exit(1)

        # Get the format of integration
        self.format = self.get_format(self.integration)
        if not self.format:
            print("Format of integration not found!")
            exit(1)

        self.args['full_location'] = self.format.get_full_location(self.args)

        # Client to API TEST
        self.api_client = ApiConnector(args)
        self.api_client.create_session()

    def run(self, interactive: bool = True):
        loop = True
        event_passed = self.args['event'] if 'event' in self.args else None
        events = []
        events_parsed = []
        try:
            while (loop):
                loop = interactive

                try:
                    # Get the events
                    events = EventsCollector.collect(interactive, self.format, event_passed)
                    if len(events) > 0:
                        for event in events:
                            response = self.process_event(event, self.format)
                            events_parsed.append(response)
                except KeyboardInterrupt as ex:
                    loop = False

        except Exception as ex:
            print("An error occurred while trying to process the events. Error: {}".format(ex))
        finally:
            self.write_output_file(events_parsed)
            self.api_client.delete_session()

    def process_event(self, event, format):
        event = format.format_event(event)
        result = self.api_client.test_run(event)
        response = "\n"
        response_output = { }
        response_traces = { }

        if len(result["data"]["run"]["traces"]) > 0:
            response_traces['Traces'] = result["data"]["run"]["traces"]

        response_output['Output'] = result["data"]["run"]["output"]

        if not self.args['json_format']:
            if len(result["data"]["run"]["traces"]) > 0:
                traces = self.response_to_yml(response_traces)
                response += traces.replace("Traces", "---\nTraces")

            output = self.response_to_yml(response_output)
            if len(result["data"]["run"]["traces"]) > 0:
                response += "\n" + output
            else:
                response += output.replace("Output", "---\nOutput")

        if not self.args['output_file']:
            print ("\n{}".format(response))

        return response

    def response_to_yml(self, response):
        response = yaml.dump(response, sort_keys=True, Dumper=Dumper)
        return response

    def write_output_file(self, events_parsed):
        try:
            if self.args['output_file'] and len(events_parsed) > 0:
                with open(self.args['output_file'], 'a') as f:
                    for event in events_parsed:
                        f.write(f"{event}\n")
        except Exception as ex:
            print("Failed to register the output file. Error: {}".format(ex))

    def get_format(self, integration):
        try:
            if integration['format'] == Formats.SYSLOG.value['name']:
                return SyslogFormat(integration, self.args)
            if integration['format'] == Formats.JSON.value['name']:
                return JsonFormat(integration, self.args)
            if integration['format'] == Formats.EVENTCHANNEL.value['name']:
                return EventChannelFormat(integration, self.args)
            if integration['format'] == Formats.MACOS.value['name']:
                return MacosFormat(integration, self.args)
            if integration['format'] == Formats.REMOTE_SYSLOG.value['name']:
                return RemoteSyslogFormat(integration, self.args)
            if integration['format'] == Formats.AUDIT.value['name']:
                return AuditFormat(integration, self.args)
            if integration['format'] == Formats.COMMAND.value['name']:
                return CommandFormat(integration, self.args)
            if integration['format'] == Formats.FULL_COMMAND.value['name']:
                return FullCommandFormat(integration, self.args)
            if integration['format'] == Formats.MULTI_LINE.value['name']:
                return MultilineFormat(integration, self.args, integration['lines'])
        except Exception as ex:
            print("An error occurred while trying to obtain the integration format. Error: {}".format(ex))