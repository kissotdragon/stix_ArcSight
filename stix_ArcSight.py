#!/usr/bin/python2
# Author: John Kennedy
# Email: kissotdragon@gmail.com
# Date: 04/26/2016
# 
# This is a derivative work from the stix_import.py script created by IBM-Security
#
# 
import sys, socket, os, types, collections, json, re, io, urllib2, dateutil, datetime, time, pytz
#from IPython.Debugger import Tracer; debug_here = Tracer()
import pprint, getpass, csv
from urlparse import urlparse
import dicttoxml
#import pickle
from optparse import OptionParser
from optparse import BadOptionError
from optparse import AmbiguousOptionError
#import pudb; pu.db
from stix.core import STIXPackage, STIXHeader
from stix.utils.parser import EntityParser
from stix.common import vocabs
from stix.common.vocabs import VocabString
from stix.common.vocabs import IndicatorType

import libtaxii as t
import libtaxii.messages_11 as tm11
import libtaxii.clients as tc

import lxml.etree
from xml.etree.ElementTree import XML, XMLParser, tostring, TreeBuilder

#python version compatibility
from __future__ import print_function

# Set Global Timeout
socket.setdefaulttimeout(30)

## Default Config
## Please set your syslog destination and port
CONFIG = {}

CONFIG['FACILITY'] = {
    'kern': 0,
    'user': 1,
    'mail': 2,
    'daemon': 3,
    'auth': 4,
    'syslog': 5,
    'lpr': 6,
    'news': 7,
    'uucp': 8,
    'cron': 9,
    'authpriv': 10,
    'ftp': 11,
    'local0': 16,
    'local1': 17,
    'local2': 18,
    'local3': 19,
    'local4': 20,
    'local5': 21,
    'local6': 22,
    'local7': 23,
}

CONFIG['LEVEL'] = {
    'emerg': 0,
    'alert': 1,
    'crit': 2,
    'err': 3,
    'warning': 4,
    'notice': 5,
    'info': 6,
    'debug': 7
}
CONFIG['DESTINATION_IP'] = {
    'ip': '10.10.10.10',
    'port': '514',
}


def syslog(message,
           level=CONFIG['LEVEL']['notice'],
           facility=CONFIG['FACILITY']['daemon'],
           host='localhost',
           port=1514):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = '<%d>%s' % (level + facility * 8, message)
    sock.sendto(data, (host, port))
    sock.close()


def extractObservable(args, obs, values):
    typ = obs["properties"]["xsi:type"]

    if args[0].type and args[0].type != typ:
        return

    val = None
    if typ == "AddressObjectType":

        # Handle if Address_Value is a plain string or one with datatype
        if isinstance(obs["properties"]["address_value"], basestring):
            val = obs["properties"]["address_value"]
        elif 'value' in obs["properties"]["address_value"]:
            val = obs["properties"]["address_value"]["value"]
    elif typ == "URIObjectType" or typ == "DomainNameObjectType" or typ == "HostnameObjectType":
        val = obs["properties"]["value"]
        if 'value' in val:
            val = obs["properties"]["value"]["value"]
        else:
            val = obs["properties"]["value"]
    elif typ == "UserAccountObjectType":
        val = obs["properties"]["username"]
    elif typ == "FileObjectType":
        val = []
        theList = obs["properties"]["hashes"][0]
        if len(theList['simple_hash_value']) > 2:
            val.append(theList['simple_hash_value'])
        else:
            val.append(obs["properties"]["hashes"][0]['simple_hash_value'][
                'value'])

    if val:
        if (not isinstance(val, basestring)) and isinstance(
                val, collections.Iterable):
            for addr in val:
                values.append(addr)
        else:
            values.append(val)
    else:
        if args[0].strict:
            raise Exception("Encountered unsupported CybOX observable type: " +
                            typ)
        else:
            print(
                "Encountered unsupported CybOX observable type: " + typ +
                ", ignoring...",
                file=sys.stderr)


def extractObservables(args, indicators):

    values = []
    for indicator in indicators:

        #Check if we were passed a list of indicators, or observables
        obs = indicator
        if "observable" in indicator:
            obs = indicator["observable"]

        try:
            if 'object' in obs:
                extractObservable(args, obs["object"], values)
            elif 'observable_composition' in obs:
                for observable in obs["observable_composition"]["observables"]:
                    if 'object' in observable:
                        extractObservable(args, observable["object"], values)
            else:
                raise Exception("Unknown Object Type!! Please Investigate")
        except:
            print("Could not handle observable/indicator:\n", file=sys.stderr)
            pprint.pprint(indicator, sys.stderr)
            raise

    return values


class PassThroughOptionParser(OptionParser):
    def _process_args(self, largs, rargs, values):
        while rargs:
            try:
                OptionParser._process_args(self, largs, rargs, values)

            except (BadOptionError, AmbiguousOptionError) as e:
                largs.append(e.opt_str)


def get_parser():

    parser = PassThroughOptionParser(add_help_option=False)

    parser.add_option(
        '-h', '--help', help='Show help message', action='store_true')
    parser.add_option(
        '-f',
        '--file',
        help='STIX file to import. Either this parameter or a STIX file is required',
        action='store')
    parser.add_option(
        '-o',
        '--outfile',
        help='Output the data to a text file',
        action='store_true')
    parser.add_option(
        '-y',
        '--type',
        help='Only import this type of indicator',
        action='store')
    parser.add_option(
        '--strict',
        action="store_true",
        help="Raise an error on an unsupported indicator. Defaults to simply printing to stderr."
    )
    parser.add_option(
        '--verbose',
        action="store_true",
        help="Print various inputs and outputs to STDERR")
    parser.add_option(
        '-a',
        '--arcsight',
        help='Send the data to ArcSight using CEF Syslog',
        action='store_true')
    parser.add_option(
        '-x',
        '--taxii',
        help='TAXII Server Endpoint. Either this parameter or a STIX file is required.',
        action='store')
    parser.add_option(
        '-p',
        '--taxiiport',
        default="80",
        help='Port for the TAXII Server',
        action='store')
    parser.add_option(
        '-c',
        "--collection",
        default="default",
        help="TAXII Data Collection to poll. Defaults to 'default'.")
    parser.add_option(
        '--taxii_endpoint',
        help='TAXII Service Endpoint. Required if -x is provided.',
        action='store')
    parser.add_option(
        "--taxii_ssl",
        default=None,
        help="Set this to use SSL for the TAXII request")
    parser.add_option(
        "--taxii_username",
        default=None,
        help="Set this to the username for TAXII BASIC authentication, if any")
    parser.add_option(
        "--taxii_password",
        default=None,
        help="Set this to use password for TAXII BASIC authentication, if any")
    parser.add_option(
        "--taxii_cert",
        default=None,
        help="Set this to the cert file for TAXII CERT authentication, if any")
    parser.add_option(
        "--taxii_key",
        default=None,
        help="Set this to use password for TAXII CERT authentication, if any")
    parser.add_option(
        "--proxy",
        default=None,
        help="Set this to use a proxy server (format http[s]://proxy:port) to access TAXII, if necessary"
    )

    parser.add_option(
        "--taxii_start_time",
        dest="begin_ts",
        default=None,
        help="The start timestamp (YYYY-MM-dd HH:MM:SS) in UTC " +
        "for the taxii poll request. Defaults to None.")

    parser.add_option(
        "--taxii_end_time",
        dest="end_ts",
        default=None,
        help="The end timestamp (YYYY-MM-dd HH:MM:SS) in UTC " +
        "for the taxii poll request. Defaults to None.")

    return parser


def print_help(parser):
    print(
        "\nA utility that imports STIX documents from either a TAXII server collection or a file.\n",
        file=sys.stderr)
    print(
        "All indicators and observables in the STIX document(s) will be imported into the specified reference set.\n",
        file=sys.stderr)
    print(parser.format_help().strip(), file=sys.stderr)


# Processes a STIX package dictionary and adds all indicators and observables to a CEF Syslog message and sent to ArcSight 


def process_package_dict(args, stix_dict):
    values = []
    key = ""
    value = ""
    dest = CONFIG['DESTINATION_IP']['ip']
    dest_port = int(CONFIG['DESTINATION_IP']['port'])
    if "observables" in stix_dict:
        values.extend(
            extractObservables(args, stix_dict["observables"]["observables"]))
    if "indicators" in stix_dict:
        values.extend(extractObservables(args, stix_dict["indicators"]))
    if len(values) > 0:
        for item in values:
            try:
                ## send data to stdout if needed and/or save to a simple text file.
                if re.match("^(http|https)", item):
                    u = urlparse(item)
                    if args[0].verbose:
                        print('Web Site: %s | Path: %s' % (u.netloc, u.path))
                    if args[0].outfile:
                        with open('WebSites.txt', 'a') as mysites:
                            mysites.writelines("%s\n" % item)
                    if args[0].arcsight:
                        cef = 'CEF:0|IHC-OSINT|Soltra|1.0|100|Known Malicious ' + 'Website' + '|1|request=' + item + ' shost=' + u.netloc + ' msg=IHC-OSINT Malicious Domain ' + u.netloc
                        time.sleep(.02)
                        syslog(cef, host=dest, port=dest_port)
                elif re.match("[^@]+@[^@]+\.[^@]+", item):
                    if args[0].verbose:
                        print('Email Address: %s' % (item))
                    if args[0].outfile:
                        with open('EmailAddresses.txt', 'a') as myemails:
                            myemails.writelines("%s\n" % item)
                    if args[0].arcsight:
                        cef = 'CEF:0|IHC-OSINT|Soltra|1.0|100|Known Malicious ' + 'Email' + '|1|suser=' + item + ' msg=IHC-OSINT Malicious Email ' + item
                        time.sleep(.02)
                        syslog(cef, host=dest, port=dest_port)
                elif re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", item):
                    if args[0].verbose:
                        print('IP Address: %s' % (item))
                    if args[0].outfile:
                        with open('MyIPs.txt', 'a') as myips:
                            myips.writelines("%s\n" % item)
                    if args[0].arcsight:
                        cef = 'CEF:0|IHC-OSINT|Soltra|1.0|100|Known Malicious ' + 'Host' + '|1|src=' + item + ' msg=IHC-OSINT Malicious IP ' + item
                        time.sleep(0.2)
                        syslog(cef, host=dest, port=dest_port)
                elif re.match("^:", item):
                    if args[0].verbose:
                        item = item[2:]
                        myitem = 'http://' + item
                        d = urlparse(myitem)
                        item = d.netloc
                        print('Domain: %s' % (d.netloc))
                    if args[0].outfile:
                        with open('AdditionalDomains.txt', 'a') as adom:
                            adom.writelines("%s\n" % item)
                    if args[0].arcsight:
                        cef = 'CEF:0|IHC-OSINT|Soltra|1.0|100|Malicious ' + 'Domain' + '|1|request=' + item + ' msg=IHC-OSINT Malicious Domain ' + d.netloc
                        time.sleep(0.2)
                        syslog(cef, host=dest, port=dest_port)
                    elif re.match(
                            "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$",
                            item):
                        data = item.split(":")
                        #print data
                        if args[0].verbose:
                            print('IP Address: %s | Dest Port: %s' %
                                  (data[0], data[1]))
                        if args[0].outfile:
                            with open('IPandPort.txt', 'a') as IPdom:
                                IPdom.writelines("%s\n" % item)
                        if args[0].arcsight:
                            cef = 'CEF:0|IHC-OSINT|Soltra|1.0|100|Known Malicious ' + 'IP and Port' + '|1|src=' + data[
                                0] + ' dpt=' + data[
                                    1] + ' msg=NH-ISAC Malicious IP ' + data[
                                        0] + ' and Port ' + data[1]
                            time.sleep(0.2)
                            syslog(cef, host=dest, port=dest_port)
                else:
                    if args[0].verbose:
                        print('Indicator: %s' % (item))
                    if args[0].outfile:
                        with open('Indicators.txt', 'a') as Idom:
                            Idom.writelines("%s\n" % item)
                    if args[0].arcsight:
                        cef = 'CEF:0|IHC-OSINT|Soltra|1.0|100|Known Malicious ' + 'Indicator' + '|1|cs1=' + item + ' msg=IHC-OSINT Malicious Indicator ' + item
                        time.sleep(0.2)
                        syslog(cef, host=dest, port=dest_port)
            except ValueError:
                print("Could not parse values..", file=sys.stderr)
                print(item, file=sys.stderr)
                raise

    return len(values)


def main():

    # Create XML parser that can strip namespaces
    xmlParser = EntityParser()

    stix_package = None

    argParser = get_parser()
    args = argParser.parse_args()

    if args[0].help:
        print_help(argParser)

    # Import from a TAXII server
    elif args[0].taxii:
        begin_ts = None
        end_ts = None

        try:
            if args[0].begin_ts:
                structTime = time.strptime(args[0].begin_ts,
                                           '%Y-%m-%d %H:%M:%S')
                begin_ts = datetime.datetime(*structTime[:6])
                begin_ts = begin_ts.replace(tzinfo=pytz.UTC)
            else:
                begin_ts = None

            if args[0].end_ts:
                structTime = time.strptime(args[0].end_ts, '%Y-%m-%d %H:%M:%S')
                end_ts = datetime.datetime(*structTime[:6])
                end_ts = end_ts.replace(tzinfo=pytz.UTC)
            else:
                end_ts = None

        except ValueError:
            print("Could not parse either start or end time", file=sys.stderr)
            raise

        poll_req = tm11.PollRequest(
            message_id=tm11.generate_message_id(),
            collection_name=args[0].collection,
            exclusive_begin_timestamp_label=begin_ts,
            inclusive_end_timestamp_label=end_ts,
            poll_parameters=tm11.PollRequest.poll_parameters())

        poll_req_xml = poll_req.to_xml()

        client = tc.HttpClient()

        if args[0].taxii_ssl:
            client.set_use_https(True)

        if args[0].taxii_username:
            client.set_auth_type(1)
            if not args[0].taxii_password:
                args[0].taxii_password = getpass.getpass(
                    "Enter your taxii password: ")
            client.set_auth_credentials({
                'username': args[0].taxii_username,
                'password': args[0].taxii_password
            })
        elif args[0].taxii_key and args[0].taxii_cert:
            client.set_auth_type(2)
            client.set_auth_credentials({
                'key': args[0].taxii_key,
                'cert': args[0].taxii_cert
            })

        if arg[0].proxy:
            client.set_proxy(arg[0].proxy)

        resp = client.call_taxii_service2(
            args[0].taxii, args[0].taxii_endpoint + "/poll/",
            t.VID_TAXII_XML_11, poll_req_xml, args[0].taxiiport)

        response_message = t.get_message_from_http_response(resp, '0')
        response_dict = response_message.to_dict()
        indicators = 0
        if 'content_blocks' in response_dict:
            for content in response_dict["content_blocks"]:
                bindingId = content["content_binding"]["binding_id"]

                if bindingId and bindingId.startswith(
                        "urn:stix.mitre.org:xml"):
                    #if args[0].verbose:
                    #    print >> sys.stderr, "RECIEVED STIX DATA:\n"
                    #print >> sys.stderr, content["content"]

                    try:
                        # Parse the information 
                        stix_pkg = STIXPackage.from_xml(
                            io.BytesIO(content["content"]))
                        stix_package = stix_pkg
                        indicators += process_package_dict(
                            args, stix_package.to_dict())

                    except ValueError:
                        print(
                            "Could not parse STIX document: ", file=sys.stderr)
                        print(content["content"], file=sys.stderr)
                        raise

            print("Imported", indicators, "indicators into set")
        else:
            print("Invalid reponse from TAXII server", file=sys.stderr)
            pprint.pprint(response_dict, sys.stderr)
            exit(255)

    # Import from a XML file on disk
    elif args[0].file:

        stix_package = STIXPackage.from_xml(args[0].file)

        indicators = process_package_dict(args, stix_package.to_dict())

        print("Imported", indicators, "indicators into set")

    else:
        print(
            "Invalid arguments. Type 'python stix_Arcsight.py --help' for usage.\n",
            file=sys.stderr)


if __name__ == "__main__":
    main()
