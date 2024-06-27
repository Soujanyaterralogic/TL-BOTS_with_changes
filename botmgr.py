#!/usr/bin/python
#----------------------------------------------------------
# Copyright FUJITSU NETWORK COMMUNICATIONS
# All Rights Reserved
# Author       : Abhishek Patel
# Maintainer   : Abhishek Patel
# Credits      : Audrey, Arun, Girish
# Date         : 28-04-2020
# Updated      : 04-09-2021
# Description  : NEBot class present a CLI to manage simulations
# Usage        : python botmgr.py <req-cmd> [<args>] [<opt-cmd> [<args>]]
#----------------------------------------------------------


from __future__ import division
from contextlib import closing
from subprocess import Popen, PIPE
from time import sleep
from tqdm import tqdm
import json
import yaml
import argparse
import sys
import os
import signal
import socket
import psutil

DEFAULTS = {
"lport": 1024, 
"uport": 8192, 
"allow_fport": None,
"num": "1:0",
"cred": "ROOT:ROOT",
"region": "REGION",
"ver": "01-01-1",
"cxn": "telnet",
"sameport": 2024,
"loglevel": "ERROR",
"comm": "ipv4"
}

class NEBot(object):
    ''' Class to handle simulation'''

    def __init__(self):
        '''
            Constructor
        '''
        self.curr_dir = os.path.dirname(os.path.abspath(__file__))
        self.header = ['target_id', 'vendor', 'model', "version", 'user_id', 'passwd', 'gne_tid',
                       "ip", "cxn", "tmode", "port", "pid", "port2", "cxn2", "region"]
        # deictionary to define size of each column so we can print max column on console
        self.columns = {"ip": 15, "target_id": 16, "cxn": 6, "tmode": 5, "port": 5,\
                        "pid": 6, "vendor": 16, "model": 16, "user_id": 8, "passwd": 8,\
                        "gne_tid": 16, "version": 8, "region":10, "commands": 30, \
                        "description": 100, "port2": 5, "cxn2": 6}
        self.__args = self.__bot_parser()
        self.exist_file = "database/" + self.__args.database + "_existing_instances.json"
        self.act_file = "database/" + self.__args.database+ "_active_instances.json"
        self.__running_instances = self.__file_action(self.act_file)
        self.__existing_instances = self.__file_action(self.exist_file)
        # decide which neconfig file
        self.neconfig = self.__args.neconfig or "neconfig"
        # get hostname
        self.hostname = socket.gethostbyname(socket.gethostname())
        self.valid_card_names = ["IFP5-CMD1", "IFP5-EGS1", "IFP5-TCA2", "IFP5-CXF4", "IFP5-S9B1", "IFP5-CMS1",
                                 "IFP5-TGD1", "IFP5-CTC1", "IFP5-EXX1", "IFP5-STA2", "IFP5-TMD1"]

    def cprint(self, string, style="g"):
        '''
           Print coloured text
           :Arguments:
               1)style(char): decide the colour
               2)string: str to be printed
           :Return: None
        '''
        codes = {"c": "36", "r": "31", "y": "33", "g": "32"}
        style = style if style in codes else "g"
        print"\033[{}m{}\033[00m".format(codes[style], string)

    def __file_action(self, file_path, mode="r", wdata=None):
        '''
            Perform read and write into json file
            :Arguments:
               1)mode(str): mode to open file r/w
               2)file_name(str): file to be read/write
               3)wdata(dict): data to be dump in file
            :Return: rdata or None
               rdata: data loaded from file
        '''
        rdata = None
        directories = file_path.split('/')
        temp_dir = self.curr_dir
        for directory in directories[:-1]:
            temp_dir = os.path.join(temp_dir, directory)
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
        if not os.path.exists(file_path):
            # dump empty dict when file not exists
            with open(file_path, "w") as file_object:
                json.dump({}, file_object, indent=2)
        try:
            with open(file_path, mode) as file_object:
                if mode == "w":
                    json.dump(wdata, file_object, indent=2)
                elif mode == "r":
                    rdata = json.load(file_object)
            return rdata
        except:
            self.cprint("IOError: while performing file action; ", "r")

    def __bot_parser(self):
        '''
            Create argument parser object to handle all bot commands
            :Arguments:
            :Return: parsed args object
        '''
        coloured_text = lambda text: "\033[36m" + text + "\033[00m"
        command = "\033[32m./bot <required-command> [<args>] [<optional-command> [args>]]\033[00m"
        req_cmd = "\033[32mThe most commonly used NE-BOT commands are:\033[00m"
        lastline = "\033[32mCommand must be executed from tl1-bots directory\033[00m"
        cfg_parser = argparse.ArgumentParser(add_help=False,\
                       formatter_class=argparse.RawDescriptionHelpFormatter)
        help_msg = coloured_text('show version and exit')
        cfg_parser.add_argument("--version", help=help_msg, action='version', \
                                                         version="NE-BOT 2.1")
        help_msg = coloured_text("specify configuration file [default=botmgr.yml]")
        cfg_parser.add_argument("-config", help=help_msg, default="botmgr.yml",\
                                                             metavar="CFG-FILE")
        arg, remaining_argv = cfg_parser.parse_known_args()
        config_path = os.path.join(self.curr_dir, arg.config)
        if arg.config and os.path.exists(config_path):
            with open(config_path) as cfg_file:
                default = yaml.load(cfg_file, yaml.SafeLoader)
                DEFAULTS.update(default if default else {})
        __parser = argparse.ArgumentParser(prog='bot',\
                   formatter_class=argparse.RawDescriptionHelpFormatter, usage=command,\
                            description=req_cmd, parents=[cfg_parser], epilog=lastline)
        group = __parser.add_mutually_exclusive_group(required=True)
        # required commands
        help_msg = coloured_text('show available products [vendor/model]')
        group.add_argument("-products", help=help_msg, nargs='?', const="all")
        help_msg = coloured_text('show supported TL1 commands')
        group.add_argument("-commands", help=help_msg, nargs='?', const="all")
        help_msg = coloured_text('load instances given in csv file')
        group.add_argument("-load", help=help_msg, type=str, metavar="CSV-FILE")
        help_msg = coloured_text('show available instances')
        group.add_argument("-instances", "-ls", help=help_msg, nargs='?', const="all", \
                                                                     metavar="INSTANCES")
        help_msg = coloured_text('launch loaded instances')
        group.add_argument("-launch", "-l", nargs='+', help=help_msg, type=str, \
                                                              metavar="INSTANCES")
        help_msg = coloured_text('show running instances')
        group.add_argument("-running", "-lt", help=help_msg, nargs='?', const="all", \
                                                           metavar="VENDOR|MODEL|TID")
        help_msg = coloured_text('export running instances into csvfile')
        group.add_argument("-export", "-e", help=help_msg, type=str, metavar="CSV-FILE")
        help_msg = coloured_text('shutdown running instances')
        group.add_argument("-shutdown", "-s", nargs='+', help=help_msg, metavar="INSTANCES")
        help_msg = coloured_text('compute instance & mem consumption')
        group.add_argument("--compute", help=help_msg, action='store_true')
        help_msg = coloured_text('Monitor VM RAM & CPU')
        group.add_argument("--vmstat", help=help_msg, action='store_true')
        help_msg = coloured_text('launch instance for given vendor:model')
        group.add_argument("-initiate", "-i", help=help_msg, type=str, metavar="VENDOR:MODEL")
        help_msg = coloured_text('show resource consumed by process')
        group.add_argument("-res", help=help_msg, nargs='+', type=str, metavar="PID")
        help_msg = coloured_text('stop running instances')
        group.add_argument("-stop", nargs='+', help=help_msg, metavar="INSTANCES")
        help_msg = coloured_text('start running stopped instances')
        group.add_argument("-start", nargs='+', help=help_msg, type=str, metavar="INSTANCES")
        # optional arguments, useless without above commands
        title = "\033[32mOptional NE-BOT commands are\033[00m"
        opt_group = __parser.add_argument_group(title)
        help_msg = coloured_text('define lower port number >= 1024')
        opt_group.add_argument("-lport", help=help_msg, default=DEFAULTS["lport"],\
                                                          type=int, metavar="PORT")
        help_msg = coloured_text('define upper port number <= 49151')
        opt_group.add_argument("-uport", help=help_msg, default=DEFAULTS["uport"],\
                                                          type=int, metavar="PORT")
        help_msg = coloured_text('allow any free port')
        opt_group.add_argument("--allow_fport", help=help_msg, action='store_true')
        help_msg = coloured_text('launch all instances on same port')
        opt_group.add_argument("-sameport", help=help_msg, type=int, nargs='?'\
                                              , const=2024,  metavar="PORT")
        help_msg = coloured_text('number of instance to be launch')
        opt_group.add_argument("-num", help=help_msg, default=DEFAULTS["num"], metavar="GNE:SNE")
        help_msg = coloured_text('choose user_id and passwd')
        opt_group.add_argument("-cred", help=help_msg, default=DEFAULTS["cred"], \
                                                          metavar="user:passwd")
        help_msg = coloured_text('choose region for instances')
        opt_group.add_argument("-region", help=help_msg, default=DEFAULTS["region"])
        help_msg = coloured_text('choose version for instances')
        opt_group.add_argument("-ver", help=help_msg, default=DEFAULTS["ver"])
        help_msg = coloured_text('append instances while loading')
        opt_group.add_argument("--append", help=help_msg, action='store_true')
        help_msg = coloured_text('select devlopment mode')
        opt_group.add_argument("--dev", help=help_msg, action='store_true')
        help_msg = coloured_text('skip the launch & add only to DB')
        opt_group.add_argument("--skiplaunch", help=help_msg, action='store_true')
        help_msg = coloured_text('select database')
        opt_group.add_argument("-database", help=help_msg, type=str, \
                                 choices=["pri", "sec"], default="pri")
        help_msg = coloured_text('select neconfig file')
        opt_group.add_argument("-neconfig", help=help_msg, type=str)
        help_msg = coloured_text('select testmode [test-file to configure command failure]')
        opt_group.add_argument("-test", help=help_msg, type=str, nargs='?',\
                                            const=True, metavar="JSON-TFILE")
        help_msg = coloured_text('select connection type')
        opt_group.add_argument("-cxn", help=help_msg, type=str, \
               choices=["ssh", "telnet", "telnet:telnet", "ssh:ssh", "telnet:ssh"], default=DEFAULTS["cxn"])

        help_msg = coloured_text('select communication over ipv4/ipv6')
        opt_group.add_argument("-comm", help=help_msg, type=str, \
               choices=["ipv4", "ipv6"], default=DEFAULTS["comm"])
        help_msg = coloured_text('define loglevel')
        opt_group.add_argument("-loglevel", help=help_msg, type=str, default=DEFAULTS["loglevel"],\
               choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"])
        help_msg = coloured_text('filter instance based on target_id|vendor|model')
        opt_group.add_argument("-filter", help=help_msg, nargs='?', const="all", \
                                        default='all', metavar="VENDOR|MODEL|TID")
        help_msg = coloured_text('select fields to export')
        #  metavar=" ".join(self.header)
        opt_group.add_argument("-field", help=help_msg, type=str, nargs='+', \
                          metavar=" ".join(self.header), choices=self.header,\
                                   default=DEFAULTS.get("field", self.header))
        # Exit immediately with help msg when no arguments fed
        if len(sys.argv) == 1:
            __parser.print_help(sys.stderr)
            sys.exit(1)
        args = __parser.parse_args(remaining_argv)
        # check invalid conditions
        if args.lport < 1024 or args.uport > 49151:
            __parser.error("port range should be within 1024-49151")
        if args.uport - args.lport < 0:
           __parser.error("lower port can not be > upper port")
        return args

    def __kill_instances(self, tid_list, erase=True):
        '''
            shutdown instance linked to process id.
            :Arguments:
               tid_list : list of tids to be shutdown
            :Return: None
        '''
        if not self.__running_instances.keys():
            self.cprint("No active instance found", "y")
            return
        tids = [tid for tid in self.__running_instances.keys()] if 'all' in tid_list else tid_list
        killed_tids = set()
        for tid in tids:
            if tid in killed_tids:
                continue
            elif tid in self.__running_instances.keys():
                try:
                    pid = self.__running_instances[tid][self.header[11]]
                    os.kill(int(pid), signal.SIGTERM)
                except KeyError:
                    continue
                except OSError:
                    pass
                except:
                    pass
                # Remove all the tid having same port (respective SNE and GNE)
                for instance in self.__running_instances.keys():
                    if self.__running_instances[instance][self.header[11]] == pid:
                        killed_tids.add(instance)
                        self.cprint("TID:{:^20} : stopped".format(instance), "g")
                        if erase:
                            del self.__running_instances[instance]
            else:
                self.cprint("TID:{:^20} : DNE ".format(tid), "r")
        self.__file_action(self.act_file, "w", self.__running_instances)

    def __display_data(self, records):
        '''
            Display records in table
            :Arguments:
            1) records (list): list of dict like-
                 datas = [
                          {"k1": "vname", "k2": "mname",,, },
                          {"k1": "vname", "k2": "mname",,, },
                          ,,
                         ]
                 keys --->heading
                 values-->row
            :Return:
        '''
        if not records:
            self.cprint("No records found", "y")
            return None
        heading = tuple(records[0].keys())
        string = "|"
        col_size = 0
        for header in heading:
            col_size += self.columns.get(header, 16)
            string += " {:^#} |".replace('#', str(self.columns.get(header, 16)))
        col_size += + len(heading)*3
        self.cprint("=" + "="*col_size, "g")
        self.cprint(string.format(*heading), "g")
        self.cprint("=" + "="*col_size, "g")
        for record in records:
            row = tuple([record.get(key) for key in heading])
            self.cprint(string.format(*row), "c")
            self.cprint("-" + "-"*col_size, "g")
        return True

    def __get_free_port(self):
        '''
           return free port within range
           :Return: port if pass else raise exception
        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = self.__args.lport
        while port <= self.__args.uport:
            try:
                sock.bind(('', port))
                sock.close()
                self.__args.lport += 2  # reduce loop iteration
                # for serving bot on two port at the same time
                if port % 2 != 0:
                    raise Exception('Port is not even')
                return port
            except:
                port += 2
        if self.__args.allow_fport:
            sock.bind(('', 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            port = sock.getsockname()[1]
            sock.close()
            return port
        else:
            raise Exception('no free port available within given range')

    def __get_port(self, group):
        '''
           If instance defined with port and available return that port
           elif launched on single port mode get that port
           else get the random free port
           :Return: port
        '''
        port = None
        if self.__args.start:
            port = self.__running_instances[group[0]][self.header[10]]
        elif self.__args.sameport:
            port = self.__args.sameport
        else:
            gne_tid = [tid for tid in group \
                      if self.__existing_instances[tid][self.header[6]] == ""][0]
            port = self.__existing_instances[gne_tid].get(self.header[10])
        if port == "" or not port or self.__check_socket(int(port), 1):
            port = self.__get_free_port() # return free port
        return int(port)

    def __check_socket(self, port, retrial=2, delay=True):
        '''
           Check for socket retrial number of times
           :Arguments:
               1) port: port
               2) retrial: int
               3) delay 
           :Return:
               True/False
        '''
        status = True
        for trial in range(0, retrial):
            if delay:
                sleep(2)
            try:
                skt = socket.socket()
                skt.connect((self.hostname, port))
                status = True
            except Exception as exc:
                status = False
            else:
                break
            finally:
                skt.close()
        return status

    def __validate_json(self, filename):
        '''
           Check if json file is in correct format
           :Arguments:
               1) filename(str): filename
           :Return:
               True/False
        '''
        status = True
        filepath = os.path.join(self.curr_dir, filename)
        try:
            with open(filepath, "r") as fobject:
                json.load(fobject)
        except Exception as exc:
            self.cprint("{}: Invalid JSON".format(exc), "r")
            status = False
        return status


    def validate_eqpt_data(self, config):
        status=True
        try:
            no_of_shelves = int(config['commands']['RTRV-EQPT']['no_of_shelf'])
            no_of_slots = int(config['commands']['RTRV-EQPT']['no_of_slots'])
            card_names = config['commands']['RTRV-EQPT']['card_names']
            cards_to_insert = config['commands']['RTRV-EQPT']['cards_to_insert'].split(',')

            if (no_of_shelves<=0 or no_of_shelves>10):
                self.cprint("Number of shelves must be greater than 0 and less than 10.", "r")
                status = False

            if len(card_names) != no_of_shelves:
                self.cprint("The number of shelves does not match the length of the card_names entries.", "r")
                status = False

            for shelf, cards in card_names.items():
                card_list = [card.strip() for card in cards.split(',') if card.strip()]
                invalid_cards = [card for card in card_list if card not in cards_to_insert]

                if invalid_cards:
                    error_message = "Invalid card name(s) in {}: {}. Valid cards are: {}.".format(
                        shelf, ', '.join(invalid_cards), ', '.join(cards_to_insert))
                    self.cprint(error_message, "r")
                    status = False

                total_fields = len(cards.split(','))
                if total_fields != no_of_slots:
                    self.cprint(
                        "Something went wrong in configuring the slots for {}, it doesn't match the total fields.".format(
                            shelf), "r")
                    status = False

        except Exception as e:
            self.cprint("Configuration error: {}".format(str(e)), "r")
            status = False
        return status

    def __pre_launch(self, group):
        '''
           Check if configuration file for group is in correct format
           :Arguments:
               1) group(list): list of tids
           :Return:
               True/False
        '''
        status = True
        for tid in group:
            if self.__args.start:
                vendor = self.__running_instances[tid][self.header[1]]
                model = self.__running_instances[tid][self.header[2]]
            else:
                vendor = self.__existing_instances[tid][self.header[1]]
                model = self.__existing_instances[tid][self.header[2]]

            config_file = "products/{}/{}/{}.json".format(vendor, model, self.neconfig)

            if not self.__validate_json(config_file):
                self.cprint("{}/{}: Invalid Configuration file".format(vendor, model), "r")
                self.cprint("TID: {:^20}: Failed to launch".format(tid), "r")
                status = False
                continue

            # Load config to pass to the new validation function
            try:
                with open(config_file) as cfg_file:
                    config = json.load(cfg_file)
                    if not self.validate_eqpt_data(config):  # New validation function call
                        status = False
            except IOError:
                self.cprint("Failed to open configuration file.", "r")
                status = False

            if tid in self.__running_instances.keys():
                self.cprint("TID: {:^20}: already running".format(tid), "y")
                status = False if not self.__args.start else True
                continue
        return status

    def __arrange_nes(self, tids):
        '''
           Arrange SNEs and GNEs tids. SNE should be launched along with GNE.
           :Arguments:
             tids(list): list of tids
           :Return: nested list of arranged tids
            list_structure: [[GNE1,SNE1,SNE2],[GNE2,SNE3,SNE4],[gne3].....]
        '''
        groups = []
        for tid in tids:
            if tid not in self.__existing_instances.keys():
                # print warning and skip the invalid tids
                self.cprint("TID: {}: Invalid/DNE".format(tid), "y")
                continue
            gne_tid = self.__existing_instances[tid][self.header[6]]
            if gne_tid == "":
                ### GNE, Add if not in group ##
                for group in groups:
                    if tid in group:
                        break
                else:
                    groups.append([tid])
            else:
                ## SNE, Add SNE to its GNE group ##
                # while loading SNE instance in bot verify gne_tid exists
                for group in groups:
                    if gne_tid in group:
                        group.append(tid)
                        break
                else:
                    groups.append([gne_tid, tid])
        return groups

    def __rearrange_nes(self, tids):
        '''
           Rearrange NEs having same ports
           :Arguments:
             tids(list): list of tids
           :Return: nested list of arranged tids
            list_structure: [[GNE1,SNE1,SNE2],[GNE2,SNE3,SNE4],[gne3].....]
        '''
        groups = []
        arranged = set()
        for tid in tids:
            group = []
            if tid not in self.__running_instances.keys():
                self.cprint("TID: {}: Does not running".format(tid), "y")
                continue
            elif tid in arranged:
                continue
            port = self.__running_instances[tid][self.header[10]]
            for instance in self.__running_instances.keys():
                if port == self.__running_instances[instance][self.header[10]]:
                    group.append(instance)
                    arranged.add(instance)
            groups.append(group)
        return groups

    def __launch_instances(self, tids, skip):
        '''
            Spawn all instance or given and linked with process id.
            :Arguments:
                1)tids_list(list) = all instances
            :Return:
                None
        '''
        if not tids:
            return
        instances = self.__running_instances if self.__args.start \
                    else self.__existing_instances
        curr_instances = {}
        ### arrange GNEs and SNEs or rearrange instances for start
        if self.__args.start:
            groups = self.__rearrange_nes(tids)
        elif self.__args.sameport:
            groups = [tids]
        else:
            groups = self.__arrange_nes(tids)
        ### assign file name or True if launching in testmode else None
        if self.__args.test:
            tmode = testmode = "test" 
            if isinstance(self.__args.test, str):
                if not self.__validate_json(self.__args.test):
                    self.cprint("invalid command testfile", "r")
                    return
                testmode = self.__args.test
                tmode = "tfile"
        else:
            tmode = testmode = "None"
        ### todo :validate testfile
        tot_count = len(groups)
        for count, group in enumerate(groups, 1):
            try:
                if not self.__pre_launch(group):
                    ## check all pstart verification
                    continue
                if self.__args.start:
                    ### shutdown if it is start
                    self.__kill_instances(group, erase=False)
                    sleep(2.0)
                port = self.__get_port(group)
                # write launching details in json file
                instance_group = []
                for tid in group:
                    data = [instances[tid][key] for key in self.header[0:7]]
                    data.append(port)
                    instance_group.append(data)
                self.__file_action("database/launching.json", "w", instance_group)
                sleep(0.5)
                launch = ['python', '-W' ,'ignore' , '-uOO', 'simulators/simulator.py',\
                         self.__args.cxn, str(port), str(testmode), \
                         str(self.__args.neconfig), self.__args.loglevel, \
                         self.__args.comm, '&>/dev/null']
                if not self.__args.dev:
                    launch.insert(0, 'nohup')
                pid = "dummy" # dummy process id if launch is skipped
                percent = round((count*100)/tot_count)
                self.cprint("progress: |{:<40}| {}%".format("#"*(int(percent*0.4)), percent), "c")
                if not skip:
                    process = Popen(launch)
                    pid = str(process.pid)
                    delay = len(group)/3.0/(len(group)**0.5)
                    sleep(delay if delay > 2.5 else 2.5) # mandatory delay to start the server
                if not skip and not self.__check_socket(port):
                    for tid in group:
                        self.cprint("TID: {:^20}: Failed to launch".format(tid), "r")
                    process.kill()
                    continue
            except KeyboardInterrupt:
                sys.exit("KeyboardInterrupt: stopped running")
            #except Exception as error:
                sys.exit(error)
            else:
                # handle different connection type on ports
                conn_types = self.__args.cxn.split(":")
                cxn = conn_types[0]
                port2, cxn2 = (str(port + 1), conn_types[-1]) if len(conn_types) > 1 else ("", "")
                for tid in group:
                    curr_instances[tid] = instances[tid].copy()
                    curr_instances[tid].update({self.header[7]: self.hostname, \
                      self.header[9]: tmode, self.header[8]: cxn,\
                      self.header[10]: str(port), self.header[12]: port2, \
                      self.header[13]: cxn2, self.header[11]: pid})
        # update active instances JSON File
        self.__running_instances.update(curr_instances)
        self.__file_action(self.act_file, "w", self.__running_instances)
        if curr_instances:
            self.cprint("Follwing Instances launched", "c")
            self.__show_running_instances(curr_instances)

    def __verify_product(self, vendor, model):
        '''
            Verify the vendor or model configuration exist or not.
            :Arguments:
                1) vendor(str): vendor name
                2) model(str): model name
            :Return:
                1) True/False: if both vendor and model exist else False
        '''
        status = False
        temp_dir = os.path.join(self.curr_dir, "products")
        try:
            if vendor in os.listdir(temp_dir):
                vendor_dir = os.path.join(temp_dir, vendor)
                if model in os.listdir(vendor_dir):
                    model_dir = os.path.join(vendor_dir, model)
                    if self.neconfig + ".json" in os.listdir(model_dir):
                        status = True
        except:
            pass
        return status

    def __pre_load(self, ne_file):
        '''
           Check format and load instances declared in csv file.
           :Arguments:
               1) ne_file(str): csv file where instances declared
               csv headers:
               target_id,vendor,model,version,user_id,passwd,gne_tid,[region,port]
               region and port or optional
           :Return:
               if pass: (True, nedata)
               if fail: (False, None)
        '''
        incorrect_format = {}
        nedata = {}
        header = []
        file_path = os.path.join(self.curr_dir, ne_file)
        if not os.path.exists(file_path):
            return False, None
        with open(file_path) as file_pointer:
            for line_number, line in enumerate(file_pointer, 1):
                if line.startswith('#'):
                   # ignore comments
                   continue
                line = line.rstrip()
                linedata = line.split(",")
                if line_number == 1:
                    if any(field not in linedata for field in self.header[0:7]):
                        incorrect_format[line_number] = "missing parameters"
                        break
                    header = linedata
                    continue
                if len(linedata) != len(header):
                    incorrect_format[line_number] = "parameters required {} and found {}".format(\
                                                             len(header), len(linedata))
                elif not self.__verify_product(linedata[1], linedata[2]):
                    incorrect_format[line_number] = "product {}/{} does not exist".\
                                                   format(linedata[1], linedata[2])
                else:
                    tid = linedata[0]
                    nedata[tid] = {key: val for key, val in zip(header, linedata)}
                    # SNE-->GNE TID verification
                    gne_tid = nedata[tid].get(self.header[6], "")
                    if gne_tid != "" and gne_tid not in nedata.keys():
                        incorrect_format[line_number] = "GNE:{} :DNE".format(gne_tid)
            ### catch ports if defined in csv
            if incorrect_format:
                self.cprint("Error in {} at".format(ne_file), "r")
                for line_num, value in incorrect_format.items():
                    self.cprint("Line:{} :{}".format(line_num, value), "r")
                return False, None
            return True, nedata

    def __searching(self, records, string):
        '''
            search for string in records | wildcard search
            symbols for wildcard search: +
            Arguments:
              records: list of dict
                       [
                         {"k1": "vname", "k2": "mname",,, },
                         {"k1": "vname", "k2": "mname",,, },,,
                       ]
              string(str): search string
            Return: list of records having string
        '''
        group = []
        for record in records:
            # check wildcard search
            if "+" in string:
                asterisk = "+"
                search = string.strip(asterisk)
                for field in record.values():
                    if string.endswith(asterisk) and field.startswith(search):
                        group.append(record)
                        break
                    elif string.startswith(asterisk) and field.endswith(search):
                        group.append(record)
                        break
            elif string in record.values():
                group.append(record)
        return group

    def __load_instances(self):
        '''
        Load instances into Bot- will delete old instances and load new instances
        '''
        # perform prechecks
        precheck_status, nedata = self.__pre_load(self.__args.load)
        # load instances into Bot
        if not precheck_status:
            self.cprint("Failed to load instances", "r")
            return
        if not self.__args.append:
            self.__existing_instances.clear()
        self.__existing_instances.update(nedata)
        self.__file_action(self.exist_file, "w", self.__existing_instances)
        self.cprint("instances loaded", "g")

    def __show_products(self):
        '''
            show list of available vendor's and models.
        '''
        products = []
        products_dir = os.path.join(self.curr_dir, "products")
        for roots, _, files in os.walk(products_dir):
            if files:
                model = os.path.basename(roots)
                vendor = os.path.basename(os.path.dirname(roots))
                if vendor != "vendor":
                    products.append({"vendor": vendor, "model": model})
        self.__display_data(products)

    def __show_commands(self):
        '''
            Show supported TL1 commands
        '''
        data = self.__file_action("products/vendor/model/{}.json".format(self.neconfig))
        if not data:
            self.cprint("NE-Config file have error or does not exist", "r")
            return
        cmd_list = []
        for cmd, comment in data["commands"].items():
            cmd_list.append({"commands": cmd, "description": comment.get("_comment", "")})
        self.__display_data(cmd_list)

    def __show_instances(self):
        '''
            Show avilable instances
        '''
        if not self.__existing_instances:
            self.cprint("No instance found", "y")
            return
        records = [value for value in self.__existing_instances.values()]
        instances = records if "all" in self.__args.instances else \
                    self.__searching(records, self.__args.instances)
        self.__display_data(instances)

    def __manage_instances(self, groups):
        '''
            Manage instances:
              - launching
              - shutdown
              - starting
            get the instances tids and invoke the respective function
            :Arguments:
              groups: list of vendors/models/tids to launch or shutdown
        '''
        if self.__args.shutdown or self.__args.stop:
            method, instances = self.__kill_instances, self.__running_instances
            skip = False if self.__args.stop else True # to remove instance from db
        elif self.__args.start:
            method, instances = self.__launch_instances, self.__running_instances
            skip = self.__args.skiplaunch # skip launch if True
        else:
            method, instances = self.__launch_instances, self.__existing_instances
            skip = self.__args.skiplaunch # skip launch
        if not instances:
            self.cprint("No instance found", "y")
            return
        if "all" in groups:
            method(list(instances.keys()), skip)
            return
        # Check only vendor model target_id
        tids = set()
        records = list(instances.values())
        for group in groups:
            # get all instances associated with group
            found_instances = self.__searching(records, group)
            if not found_instances:
                self.cprint("No Instance Found for {}".format(group), "y")
                continue
            tids.update([instance[self.header[0]] for instance in found_instances])
        method(tids, skip)

    def __show_running_instances(self, instances):
        '''
            Show running instances and select only mandatory fields
        '''
        if not instances:
            self.cprint("No active instance found", "y")
            return
        # display only mandatory fields
        records = [{key: val for key, val in instance.items() if key in self.header[0:3] or \
                                  key in self.header[4:14]} for instance in instances.values()]
        if not self.__args.running:
            self.__display_data(records)
            return
        # search for the instance
        records = records if "all" in self.__args.running else \
                  self.__searching(records, self.__args.running)
        self.__display_data(records)

    def __show_resources(self, display=True):
        '''
            Show resources consumed by running instances
            :Arguments: None
            :Return: None
        '''
        if not self.__running_instances:
            self.cprint("No instance found", "y")
            return 0, 0.000 # return no of process, ram
        pids = {}
        if self.__args.res and "all" not in self.__args.res:
            # list of same process
            for spid in set(self.__args.res):
                for instance in self.__running_instances.values():
                    if instance.get(self.header[11]) == spid:
                        pids[spid] = pids.get(spid, 0) + 1
                if not pids.get(spid):
                    self.cprint("Proces: {}: DNE".format(spid), "y")
        else:
            for instance in self.__running_instances.values():
                pid = instance.get(self.header[11])
                pids[pid] = pids.get(pid, 0) + 1

        records = []
        ram = 0.0             # total ram used for instances
        shared = 0.0          # shared mem for instances
        for pid, noi in pids.items():
            record = {}
            record["no-of-instances"] = noi
            record[self.header[11]] = pid
            try:
                proc = psutil.Process(int(pid))
            except:
                continue
            mem = proc.memory_full_info()
            uss = mem.uss/(10**6)          # private memory
            shr = mem.shared/(10**6)       # shared memory
            shared = shr if shr > shared else shared
            ram += uss
            record["pvt-mem (MB)"] = round(uss, 3)
            record["shr-mem (MB)"] = round(shr, 3)
            record["cpu (%)"] = round(proc.cpu_percent(interval=0.1), 3) # cpu
            record["total-mem (MB)"] = round(ram + shared, 3)
            records.append(record)
        if display:
            self.__display_data(records)
        return len(pids), round(ram + shared, 3) # number of process, total ram used in MB

    def __export_data(self):
        '''
            export active instances into csv file
            :Return: None
        '''
        if not self.__running_instances:
            self.cprint("No instance found", "y")
            return None

        # filter instance
        records = [{key: val for key, val in instance.items() if key in self.header[0:3] or \
                 key in self.header[4:-1]} for instance in self.__running_instances.values()]
        # search for the instance
        records = records if "all" in self.__args.filter else \
                  self.__searching(records, self.__args.filter)

        # print the mentioned fields or all
        fields = self.__args.field if self.__args.field else self.header
        fileobject = open(self.__args.export, "w")
        heading = ",".join(fields) + "\n"
        fileobject.writelines(heading)
        for record in records:
        #for record in self.__running_instances.values():
            row = [record.get(key, "") for key in fields]
            row = ",".join(row) + "\n"
            fileobject.writelines(row)
        fileobject.close()
        self.cprint("active instances exported in the {}".format(self.__args.export), "g")
        return True

    def tid_generator(self, vendor, model):
        '''
        genrate first 6 letters for tid
        check the tid should not be duplicate
        :Argument: 
           vendor: vendor name
           model: model name
        :Return: string [V][M][A-Z][A-Z][A-Z][A-Z]
        '''
        vm = DEFAULTS.get("tid_start_with", vendor[0:2].upper() + model[0:2].upper())
        target_id = vm + "AAAA"
        tid = [65, 65, 65, 65] # vary four chararcters
        while any(tid.startswith(target_id) for tid in self.__running_instances.keys()):
            length = len(tid)
            tid[-1] = tid[-1] + 1
            for pos in reversed(range(length)):
                if tid[pos] > 90:
                    tid[pos - 1], tid[pos] = tid[pos - 1] + 1, 65
                else:
                    break
            if tid[0] == 90:
                break
            target_id = vm + ''.join(chr(t) for t in tid)
        return target_id

    def __insatnces_generator(self):
        '''
            generate user given number of instances,
            and launch the instances
            :Return: None
        '''
        def separate(string, assign=None):
            ''' return strings separated by :'''
            sep = string.split(":")
            sep1, sep2 = (sep[0], sep[1]) if len(sep) == 2 else \
                   (sep[0], sep[0] if assign == None else assign)
            return sep1, sep2

        instances = {}
        user_id, passwd = separate(self.__args.cred)   # get user passwd
        version = self.__args.ver                      # get version
        region = self.__args.region                    # get region
        gne, sne = separate(self.__args.num, 0)        # get nGNE & nSNE
        try:
            gne, sne = int(gne), int(sne)
        except:
            self.cprint("nGNE & nSNE must be integer", "r")
            return
        vendor, model = separate(self.__args.initiate) # get vendor and model
        if not self.__verify_product(vendor, model):
            self.cprint("product: " + vendor + "/" + model + ": DNE", "y")
            return
        tid = self.tid_generator(vendor, model)
        for ngne in range(0, gne):
            # append all in order
            gne_tid = "{}-{}".format(tid, ngne)
            instances[gne_tid] = {"target_id": gne_tid, "vendor": vendor, "model": model,\
                                "user_id": user_id, "passwd": passwd, "version": version,\
                                "region": region, "gne_tid": ""}
            for nsne in range(0, sne):
                sne_tid = "{}-{}".format(gne_tid, nsne)
                instances[sne_tid] = {"target_id": sne_tid, "vendor": vendor, "model": model,\
                                    "user_id": user_id, "passwd": passwd, "version": version,\
                                    "region": region, "gne_tid": gne_tid}
        # temporary update to avoid waring
        self.__existing_instances.update(instances)
        self.__launch_instances(instances, self.__args.skiplaunch) # launch instances

    def __counter(self):
        '''
            Show-
                number of running instances
                number of instances loaded
                resources consumed by running instances
            :Arguments: None
            :Return: None
        '''
        resources = []
        mem = psutil.virtual_memory()
        consumed = self.__show_resources(display=False)
        self.columns.update({"entity": 34, "quantity": 17})
        resources.append({"entity": "total memory", \
                 "quantity": "{} GB".format(round(mem.total/(1024*1024*1024), 3))})
        resources.append({"entity": "free memory", \
                      "quantity": "{} GB".format(round(mem.free/(1024*1024*1024), 3))})
        resources.append({"entity": "used memory", \
                   "quantity": "{} GB".format(round(mem.used/(1024*1024*1024), 3))})
        resources.append({"entity": "loaded instances", \
                    "quantity": len(self.__existing_instances)})
        resources.append({"entity": "running instances", \
                      "quantity": len(self.__running_instances)})
        resources.append({"entity": "no. of process used for running",\
                      "quantity": "{}".format(consumed[0])})
        resources.append({"entity": "mem consumed by running instances",\
                      "quantity": "{} MB".format(consumed[1])})
        self.__display_data(resources)

    def __check_vmstat(self):
        '''
            Show- CPU and RAM consumption in %
            :Arguments: None
            :Return: None
        '''
        with tqdm(total=100, desc='cpu%', position=0, colour='green') as cpubar,\
                tqdm(total=100, desc='ram%', position=1, colour='green') as rambar:
          while True:
            try:
                mem = psutil.virtual_memory().percent
                cpu = cpubar.n=psutil.cpu_percent()
                col = [(90, 'red'), (70, 'magenta'), (50, 'yellow'), (30, 'green'), (0, 'cyan')]
                for i, rang in col:
                    if mem > i:
                        rambar.colour = rang
                        break
                for i, rang in col:
                    if cpu > i:
                        cpubar.colour = rang
                        break
                rambar.n = mem
                cpubar.n = cpu
                rambar.refresh()
                cpubar.refresh()
                sleep(1)
            except KeyboardInterrupt:
                break

    def bot_manager(self):
        '''
            manager to handle commands and invoke respective methods
            :Arguments: None
            :Return: None
        '''
        ### pre-launch actions ###
        if self.__args.compute:
            self.cprint("Processing: Show no of instances and MEM used", "c")
            self.__counter()
        elif self.__args.vmstat:
            self.cprint("Processing: Monitor RAM & CPU", "c")
            self.__check_vmstat()
        elif self.__args.products:
            self.cprint("Processing: Show Supported Vendors/Models", "c")
            self.__show_products()
        elif self.__args.commands:
            self.cprint("Processing: Show Supported TL1 commands", "c")
            self.__show_commands()
        elif self.__args.load:
            self.cprint("Processing: Load Instances", "c")
            self.__load_instances()
        elif self.__args.instances:
            self.cprint("Processing: Show Available Instances", "c")
            self.__show_instances()
        ### launch instance ###
        elif self.__args.launch:
            self.cprint("Processing: Launch Instance", "c")
            self.__manage_instances(self.__args.launch)
        elif self.__args.start:
            self.cprint("Processing: Restart Instance", "c")
            self.__manage_instances(self.__args.start)
        elif self.__args.initiate:
            self.cprint("Processing: Generate & Launch Instance", "c")
            self.__insatnces_generator()
        ### post launch action ###
        elif self.__args.res:
            self.cprint("Processing: Show Resources Consumed", "c")
            self.__show_resources()
        elif self.__args.shutdown:
            self.cprint("Processing: Shutdown Running Instance", "c")
            self.__manage_instances(self.__args.shutdown)
        elif self.__args.stop:
            self.cprint("Processing: Stop Running Instance", "c")
            self.__manage_instances(self.__args.stop)
        elif self.__args.export:
            self.cprint("Processing: Export active instance as CSV", "c")
            self.__export_data()
        elif self.__args.running:
            self.cprint("Processing: Show Active Instances", "c")
            self.__show_running_instances(self.__running_instances)

if __name__ == "__main__":
    NE = NEBot()
    NE.bot_manager()
