#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Gabriel Liñero and Quim Montal"

# Interact with PaloAlto's API
import logging
import argparse
import sys
import xmltodict, json
import configparser as cp
from pandevice import firewall, network, panorama
import pandas as pd
import datetime, time
import collections


class PaloAltoAPI():

    def __init__(self, location='panorama'):
        ''' Initialize Palo Alto connection '''
        configfile = 'cons.cfg'
        config = cp.RawConfigParser()
        config.read(configfile)
        self.logger = logging.getLogger(name='init_palo')
        self.logger.info("Starting Palo initialization")
        self.locations = ['panorama', 'firewall']
        if location == 'panorama':
            self.fw = panorama.Panorama(config.get('paloalto', 'panorama'), config.get('paloalto', 'username'),
                                        config.get('paloalto', 'password'))
        elif location in self.locations:
            self.fw = firewall.Firewall(config.get('paloalto', location), config.get('paloalto', 'username'),
                                        config.get('paloalto', 'password'))
        else:
            self.logger.error(
                "The location {} is not among the available locations: {}".format(location, self.locations))
            sys.exit(1)

    ###########################
    ### PARSING ABSTRACTION FUNCTIONS
    ###########################

    def execute_config_query(self, query):
        self.fw.xapi.show(query)
        return json.loads(json.dumps(xmltodict.parse(self.fw.xapi.xml_result())))

    def execute_op_command(self, command, cmd_xml=True, xml=False):
        return \
        json.loads(json.dumps(xmltodict.parse(self.fw.op("{}".format(command), cmd_xml=cmd_xml, xml=xml))))['response'][
            'result']

    def flatten(self, l):
        for el in l:
            if isinstance(el, collections.Iterable) and not isinstance(el, (str, bytes)):
                yield from self.flatten(el)
            else:
                yield el

    ###########################
    ### MONITOR LOGS FUNCTIONS
    ###########################

    def download_traffic(self, query="", skip=0, nlogs=5000):
        ''' Download Traffic from PaloAlto appliance '''
        self.logger = logging.getLogger(name='download_traffic')
        self.logger.debug("Downloading {} logs of query '{}'".format(nlogs, query))
        # TODO while True / check if x amount of hours of logs downloaded
        self.fw.xapi.log(log_type='traffic', nlogs=nlogs, skip=skip, filter=query)
        return json.loads(json.dumps(xmltodict.parse(self.fw.xapi.xml_root())))['response']['result']['log']['logs'][
            'entry']

    def create_query(self, source="", destination="", dest_port="", protocol="", application="", action=""):
        ''' Create the PaloAlto query '''
        statements = []
        if source:
            statements.append("(addr.src in {})".format(source))
        if destination:
            statements.append("(addr.dst in {})".format(destination))
        if dest_port:
            statements.append("(port.dst eq {})".format(dest_port))
        if protocol:
            statements.append("(proto eq {})".format(protocol))
        if application:
            statements.append("(app eq {})".format(application))
        if action:
            statements.append("(action eq {})".format(action))

        return " and ".join(statements)

    def search_palo(self, source="", destination="", dest_port="", protocol="", application="", action="", skip=0,
                    nlogs=5, query=""):
        self.logger = logging.getLogger(name='create_query')

        if not query:
            self.logger.info("Creating traffic query to PaloAlto")
            query = self.create_query(source, destination, dest_port, protocol, application, action)

        return self.download_traffic(query, skip, nlogs)

    def create_time_query(self, source="", destination="", dest_port="", protocol="", application="", action="",
                          hours=1):
        self.logger = logging.getLogger(name='create_time_query')
        self.logger.info("Creating time based traffic query to PaloAlto")
        query = self.create_query(source, destination, dest_port, protocol, application, action)
        skip = 0
        nlogs = 5000
        data = []
        initial, time_window = "", ""
        start = time.time()
        while True:
            self.logger.info("Downloading traffic logs from Palo for the last {} hours".format(hours))
            data += self.search_palo(skip=skip, nlogs=5000, query=query)
            if not initial:
                initial = datetime.datetime.strptime(data[0]['receive_time'], '%Y/%m/%d %H:%M:%S')
                # time_window is the date until we need to retrieve logs (24 hours earlier)
                time_window = initial - datetime.timedelta(hours=hours)
                query += "and ( receive_time leq '{}' )".format(data[0]['receive_time'])
                self.logger.info("Retrieving logs until {}".format(time_window))

            earliest_log = datetime.datetime.strptime(data[(len(data) - 1)]['receive_time'], '%Y/%m/%d %H:%M:%S')
            self.logger.debug(earliest_log, len(data))
            if earliest_log < time_window:
                break
            skip += 5000

        end = time.time()
        self.logger.info("Spent {} seconds for {} hours of logs".format(int(end - start), hours))
        return data

    ###########################
    ### PANORAMA FUNCTIONS
    ###########################

    def get_panorama_device_groups(self):
        # PANORAMA ONLY COMMAND
        return self.execute_config_query("/config/devices/entry[@name='localhost.localdomain']/device-group")

    def get_panorama_devices(self):
        # PANORAMA ONLY COMMAND
        return self.execute_op_command(command="show devices all", xml=True)

    def get_panorama_disabled_devices(self):
        # PANORAMA ONLY COMMAND
        devices = self.get_panorama_devices()
        # policies -> for each policy['target'] -> delete devices in list
        return [device for device in devices if device['connected'] == "no"]

    def get_panorama_security_pre_rules(self):
        # PANORAMA ONLY COMMAND
        return self.execute_config_query("/config/shared/pre-rulebase/security")['security']['rules']['entry']

    def get_panorama_security_post_rules(self):
        # PANORAMA ONLY COMMAND
        return self.execute_config_query("/config/shared/post-rulebase/security")['security']['rules']['entry']

    def get_panorama_addresses(self):
        # PANORAMA ONLY COMMAND
        return self.execute_config_query(
            "/config/shared/address")['address']['entry']

    def get_panorama_address_groups(self):
        # PANORAMA ONLY COMMAND
        return self.execute_config_query(
            "/config/shared/address-group")['address-group']['entry']

    def get_panorama_services(self):
        # PANORAMA ONLY COMMAND
        return self.execute_config_query(
            "/config/shared/service")["service"]['entry']

    def get_panorama_service_groups(self):
        # PANORAMA ONLY COMMAND
        return self.execute_config_query(
            "/config/shared/service-group")['service-group']['entry']

    ###########################
    ### LOCAL OBJECTS FUNCTIONS
    ###########################

    def get_local_addresses(self):
        return self.execute_config_query(
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address")['address'][
            'entry']

    def get_local_address_groups(self):
        return self.execute_config_query(
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group")[
            'address-group']['entry']

    def get_local_services(self):
        return self.execute_config_query(
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service")["service"][
            'entry']

    def get_local_service_groups(self):
        return self.execute_config_query(
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group")[
            'service-group']['entry']

    def get_local_security_rules(self):
        '''
        disabled_rules = []
        for rule in rules:
            if 'disabled' in rule.keys():
                if rule['disabled'] == 'yes':
                    disabled_rules.append(rule)
        '''
        return self.execute_config_query(
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules")[
            'rules']['entry']

    def show_system_info(self):
        return self.execute_op_command('show system info', True, True)

    def check_unused_local_services(self, service_group=False):
        # comparing against security rules
        # FIRST NEEDS TO BE CHECKED SERVICE GROUPS; THEN SERVICES
        if service_group:
            service_names = [service['@name'] for service in self.get_local_service_groups()]
        else:
            service_names = [service['@name'] for service in self.get_local_services()]
        rules = self.get_local_security_rules()
        service_usage = {}
        for service in service_names:
            service_usage[service] = []
            # compare the service to all the rules to see if it is being used
            for rule in rules:
                if service in rule['service']['member']:
                    service_usage[service].append(rule['@name'])

        unused_services = [service for service in service_usage if service_usage[service] == []]
        one_use_service = [(service, service_usage[service]) for service in service_usage if
                           len(service_usage[service]) == 1]

        return service_usage

    def check_unused_local_addresses(self, address_group=False):
        # comparing against security rules
        # FIRST NEEDS TO BE CHECKED SERVICE GROUPS; THEN SERVICES
        if address_group:
            address_names = [service['@name'] for service in self.get_local_address_groups()]
        else:
            address_names = [service['@name'] for service in self.get_local_addresses()]
        rules = self.get_local_security_rules()
        address_usage = {}
        for address in address_names:
            address_usage[address] = []
            # compare the service to all the rules to see if it is being used
            for rule in rules:
                if address in self.flatten([rule['destination']['member'], rule['source']['member']]):
                    address_usage[address].append(rule['@name'])

        unused_addresses = [address for address in address_usage if address_usage[address] == []]
        one_use_address = [(address, address_usage[address]) for address in address_usage if
                           len(address_usage[address]) == 1]

        return address_usage

    ###########################
    ### OTHER FUNCTIONS
    ###########################

    def compare_local_objects_with_panorama(self):
        # compare first address groups and service groups:
        local_service_groups = []
        pano_service_groups = []
        try:
            local_service_groups = palo.get_local_service_groups()
        except:
            print("No local service groups")
        try:
            pano_service_groups = pano.get_panorama_service_groups()
        except:
            print("No panorama service groups")

        print("{} local service-groups, {} panorama service_groups".format(len(local_service_groups),
                                                                           len(pano_service_groups)))
        ###################
        ###################
        local_address_groups = []
        pano_address_groups = []
        try:
            local_address_groups = palo.get_local_address_groups()
        except:
            print("No local address groups")

        try:
            pano_address_groups = pano.get_panorama_address_groups()
        except:
            print("No panorama addresss groups")

        print("{} local service-groups, {} panorama service_groups".format(len(local_address_groups),
                                                                           len(pano_address_groups)))
        ###################
        ###################
        local_addresses = []
        pano_addresses = []
        try:
            local_addresses = palo.get_local_addresses()
        except:
            print("No local addresses")
        try:
            pano_addresses = pano.get_panorama_addresses()
        except:
            print("No panorama addresses")

        print("{} local addresses, {} panorama addresses".format(len(local_addresses),
                                                                 len(pano_addresses)))
        address_matches = []
        if local_addresses and pano_addresses:
            for address in local_addresses:
                for pano_address in pano_addresses:
                    if "ip-netmask" in address.keys() and "ip-netmask" in pano_address.keys():
                        if address["ip-netmask"] == pano_address["ip-netmask"]:
                            count += 1
                            address_matches.append((address, pano_address))
                            print("ADDRESS MATCH!\nLocal object name: {}\nPano object name: {}".format(address["@name"],
                                                                                                       pano_address[
                                                                                                           "@name"]))
                    elif "fqdn" in address.keys() and "fqdn" in pano_address.keys():
                        if address["fqdn"] == pano_address["fqdn"]:
                            count += 1
                            address_matches.append((address, pano_address))
                            print("FQDN MATCH!\nLocal object name: {}\nPano object name: {}\n".format(address["@name"],
                                                                                                      pano_address[
                                                                                                          "@name"]))

        ###################
        ###################
        local_services = []
        pano_services = []
        try:
            local_services = palo.get_local_services()
        except:
            print("No local services")
        try:
            pano_services = pano.get_panorama_services()
        except:
            print("No panorama services")

        print("{} local services, {} panorama services".format(len(local_services),
                                                               len(pano_services)))
        service_matches = []
        if local_services and pano_services:
            for service in local_services:
                for pano_service in pano_services:
                    if list(service['protocol'].keys())[0] == list(pano_service['protocol'].keys())[0]:
                        protocol = list(service['protocol'].keys())[0]
                        if service['protocol'][protocol]['port'] == pano_service['protocol'][protocol]['port']:
                            count += 1
                            service_matches.append((service, pano_service))
                            print(
                                "SERVICE MATCH! \nLocal object name: {}\nPano object name: {}".format(service["@name"],
                                                                                                      pano_service[
                                                                                                          "@name"]))

        return address_matches, service_matches

    def get_globalprotect_users(self):
        return self.execute_op_command(
            command="<show><global-protect-gateway><current-user/></global-protect-gateway></show>", cmd_xml=False,
            xml=True)

    def get_tunnel_flow(self):
        return self.execute_op_command(
            command="<show><running><tunnel><flow><all></all></flow></tunnel></running></show>", cmd_xml=False,
            xml=True)

    def firewall_request_software_info(self, target):
        # No need for info, check already returns the whole list
        exists = False
        data = self.execute_op_command(
            command="<request><system><software><check></check></software></system></request>", cmd_xml=False, xml=True)
        versions = data['response']['result']['sw-updates']['versions']['entry']
        for version in versions:
            if version["version"] == target:
                exists = True
                print("Target version {} exists.".format(target))

        if exists:
            download = input("Do you want to download it?(y/n): ") or "n"
            if download == "y":
                response = self.execute_op_command(
                    command="<request><system><software><download><version>{}</version></download></software></system></request>".format(
                        target),
                    cmd_xml=False, xml=True)
                print(response)

            elif download == "n":
                print("Upgrade cancelled")
                sys.exit(1)
        else:
            print("Target version {} does not exist".format(target))
            sys.exit(1)

    def firewall_request_dynamic_updates(self, target):
        return

    def get_ha_state(self):
        data = self.execute_op_command(command="<show><high-availability><state></state></high-availability></show>",
                                       cmd_xml=False,
                                       xml=True)
        data = data['response']['result']
        dashboard = {
            # "HA": data['enabled'],
            "Mode": data['group']['mode'],
            "Local": data['group']['local-info']['state'],
            "Peer": data['group']['peer-info']['state'],
            "Running config": data['group']['running-sync'],
            "App Version": data['group']['local-info']['app-compat'],
            "Threat Version": data['group']['local-info']['threat-compat'],
            "Antivirus Version": data['group']['local-info']['av-compat'],
            "PAN-OS Version": data['group']['local-info']['build-compat'],
            "GlobalProtect Version": data['group']['local-info']['gpclient-compat'],
            "HA1": data['group']['peer-info']['conn-ha1']['conn-status'],
            "HA1 Backup": data['group']['peer-info']['conn-ha1-backup']['conn-status'],
            "HA2": data['group']['peer-info']['conn-ha2']['conn-status']
        }

        return dashboard

    def export_device_state(self):
        self.fw.xapi.export("device-state")
        return

    def get_group_mapping_state(self):
        return self.execute_op_command(
            command="<show><user><group-mapping><state>all</state></group-mapping></user></show>", cmd_xml=False,
            xml=True)

    def upgrade_firewall(self, target):
        self.firewall_request_software_info(target)
        # TODO
        # superuser privileges to download software update and export device-state
        # palo.fw.xapi.export("device-state") - https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-panorama-api/pan-os-xml-api-request-types/export-files-api.html
        # HA State Suspend -> https://firewall.yourcompany.com/php/rest/browse.php/op::request::high-availability::state::suspend
        # Install software version -> https://firewall.yourcompany.com/php/rest/browse.php/op::request::system::software::install::version
        # Content upgrade -> https://firewall.yourcompany.com/php/rest/browse.php/op::request::content::upgrade
        # Anti_Virus upgrade -> https://firewall.yourcompany.com/php/rest/browse.php/op::request::anti-virus::upgrade
        return


##########################
##########################
# TEST SCRIPT FUNCTION 
##########################
##########################

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--timespan', help="Specify timespan of logs (last x hours)(apis only)", type=int,
                        nargs='?', const=24, default=24)
    parser.add_argument('-l', '--location', help="Specify PaloAlto Instance", type=str, nargs='?',
                        const='panorama.yourcompany.com', default='panorama.yourcompany.com')
    parser.add_argument('-src', '--source', help='Query source (IP or Range)', type=str)
    parser.add_argument('-dest', '--destination', help='Query destination (IP or Range)', type=str)
    parser.add_argument('-dest_p', '--destination_port', help='Query Destination Port', type=int)
    parser.add_argument('-app', '--application', help='Query Application', type=str)
    parser.add_argument('-proto', '--protocol', help='Query Protocol', type=str)
    parser.add_argument('-nlogs', '--number_logs',
                        help='Amount of logs to retrieve (up to 5000, otherwise create timebased search)', type=int)
    parser.add_argument('-action', '--action', help='allow or deny', type=str)
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG if args.debug else logging.INFO
    )

    print(args)
    palo = PaloAltoAPI(args.location)
    pano = PaloAltoAPI()
    results = palo.search_palo(source=args.source, destination=args.destination, dest_port=args.destination_port,
                               protocol=args.protocol, application=args.application, nlogs=args.number_logs,
                               action=args.action)
    fields = ['device_name', 'receive_time', 'from', 'src', 'to', 'dst', 'rule', 'app', 'proto', 'dport', 'category',
              'srcuser', 'natsrc', 'action', 'session_end_reason']
    df = pd.DataFrame(results, columns=fields)
    print(df)
    from IPython import embed

    embed()
