# --------------------------------------------------------------
# Copyright FUJITSU NETWORK COMMUNICATIONS
# All Rights Reserved
# Author       :Abhishek Patel, Deng Marcus
# Maintainer   :Abhishek Patel
# Credits      :Audrey, Arun, Girish, Anitha
# Date         :28-04-2020
# Updated      :16-08-2021
# Description  :Module contain Actions class 
#               Under Action class action for respective command
# --------------------------------------------------------------

from __future__ import division
import os
import sys
import re
import random
import string
#import datetime
from datetime import datetime
from time import sleep
import threading
import multiprocessing
import subprocess
import ftplib
import pysftp
import tftpy
from telnetsrv.green import TelnetHandler
from simconfig import ConfigSetup
import logging
import logging.handlers
from collections import OrderedDict

NE = ConfigSetup(None, sys.argv[3], sys.argv[4])
NEDATA, NECFG = NE.data_generator()
# NEDATA and NECFG MUST be global variable
if not (NEDATA and NECFG):
    sys.exit("Fail to Load NE-Configuration")
TID = None 
# Set default GNE target_id
for tid, design in NEDATA.items():
    if design.get("type") == "GNE":
        TID = tid
        break
else:
    sys.exit("Default GNE TID Missing")

CDIR = os.path.dirname(os.path.abspath(__file__))# Current directory
LDIR = os.path.join(CDIR, "../Logs")#              Log directory
TDIR = os.path.join(CDIR, "tempfiles")#            Temp directory to store files
PORT = NEDATA[TID]["data"].get("port")
LOG = os.path.join(LDIR, str(PORT))# Creating dir as port inside ../Logs
for directory in [LDIR, TDIR, LOG]:
    if not os.path.exists(directory):
        os.makedirs(directory)#create directory if does not exist

# IPV4 regular expression
RGXIPV4 = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


class Actions(TelnetHandler, object):
    '''
    Class to process actions for commands
    '''
    # Logger setup
    LOG_FILENAME = os.path.join(LOG, 'sim.log')
    sim_logger = logging.getLogger('SIMLogger')
    loglevel = sys.argv[5]
    simlog_lock = threading.Lock()
    sim_logger.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=5000000, backupCount=3)
    handler.setFormatter(logging.Formatter('%(message)s'))
    sim_logger.addHandler(handler)

    # Default prompt
    PROMPT = NECFG[TID].get("prompt")
    # WELCOME banner
    WELCOME = NECFG[TID].get("banner")
    # AutoMsg feature
    AUTOMSG = NECFG[TID].get("autoMsg")
    # Set flag response end with nextline or not
    RENL =  NECFG[TID].get("respENL", True)
    # Default GNE Target_id
    GTID = TID
    # set logger object
    log = None
    # num of times EXIT cmd must be executed to exit the session
    EXITCOUNT = 1
    active_sessions = []

    def session_start(self):
        '''
        Method invoked when client session starts
        Create logger per client session
        '''
        Actions.active_sessions.append(self)
        self.log = []
        # Bugfix list of alive(Login active) TID
        self.LNE = []
        # for alarm clearance
        self.ANE = []
        self.lnelock = threading.Lock()
        # Decide to echo a command 
        self.DOECHO = NECFG[TID].get("doEcho", True)
        # Autonomous msg
        self.state = threading.Condition()
        # flag to keep autonomous msg pause until ACT-USER executed
        self.pause = False
        async = threading.Thread(target=self.handle_start_automsg, args=(5,))
        # start thread if autoMsg feature True
        if self.AUTOMSG:
            async.start()

    def handle_automsg(self, cmd, ne_data, cmd_config):
        '''
           Enable or disable autonomous
           if autoMsg feature is disabled by default
           Then this method won't do anything
        '''
        if self.AUTOMSG:#                check autoMsg feature on
            with self.state:
                self.lnelock.acquire()
                if cmd.get("autoMsg"): # enable command
                    if cmd["TID"] not in self.LNE: 
                        # add TID to automsg LNE
                        self.LNE.append(cmd["TID"])
                    self.pause = False#  enable autonomous msg if not enabled
                    self.state.notify()# unblock pause thresd
                else:# disable command
                    if cmd["TID"] in self.LNE: # remove TID from autonMsg LNE
                        self.LNE.remove(cmd["TID"])
                    if not self.LNE:
                        self.pause = True#   disable autonomous msg
                self.lnelock.release()
        return (True, None)

    def writeline(self, text):
        '''
        lib method, overiding needed to remove nextline char
        '''
        if self.RENL:
            # default- response end with nextline
            self.write(text+chr(10))
        else:
            # send response without nextline at the end
            self.write(text)

    def log_out(self, text):
        '''
        responds with a message
        does not conform to expected error messages;
        to be used only for general communications/debugging
        :param:
          - text: the message
        '''
        self.writeline(text)
        self.log_info(text)

    def handle_prompt(self, cmd, data, cmd_config):
        '''
        Change prompt and return response
        '''
        status = True
        try:
            self.PROMPT = cmd.get("prompt", self.PROMPT)
            self.EXITCOUNT = int(cmd.get("exitCount", self.EXITCOUNT))
        except:
            status = False
        return (status, None)

    def handle_login(self, cmd, data, cmd_config):
        '''
        handles ACT-USER
        :@Command: ACT-USER:{{TID}}:{{USER}}:C::{{PASSWD}}
        Note that once a client has successfully ACT-USER into a NE,
        no one can use that same username until the session is closed or reset
        TODO: implement the login banner
        :param:
          - cmd: ACT-USER command and arguments
          - data: NE executing ACT-USER
        '''
        # check for user-password
        if NECFG[self.GTID].get("authUser") and cmd.get("USER") != data["data"]["user_id"]:
            return (False, None) # username does not matched
        elif NECFG[self.GTID].get("authPasswd") and cmd.get("PASSWD", "") != data["data"]["passwd"]:
            return (False, None) # passwd does not mathced
        auth_pair = (cmd["owner"], cmd["USER"])
        if auth_pair in data["auth"]:
            return (False, None)
        data["auth"].add(auth_pair)
        if cmd["command"] not in data["progress"]:
            data["progress"][cmd["command"]] = set()
        data["progress"][cmd["command"]].add(cmd["owner"])
        self.lnelock.acquire()
        if not self.LNE: #Set GNE TID for saving Logs
            self.GTID = cmd["TID"]
        self.LNE.append(cmd["TID"])#Append NE TID to LIVE
        self.ANE.append(cmd["TID"])
        self.lnelock.release()
        # login success --> start autonomous response
        # Turn on autonomous msg feature selected
        if self.AUTOMSG and len(self.LNE) == 1:
            with self.state:
                self.pause = False#   enable autonomous msg
                self.state.notify()#  unblock pause thresd
        return (True, None)

    def handle_logout(self, cmd, data, cmd_config):
        '''
        handles CANC-USER
        CANC-USER:{{TID}}:{{USER}}:C
        :param:
         - cmd: CANC-USER command and arguments
         - data: NE executing CANC-USER
        '''
        auth_pair = (cmd["owner"], cmd["USER"])
        if auth_pair in data["auth"]:
            #find the command with "handle_login" and remove the owner
            login_command = None
            for command in NECFG[cmd["TID"]]["commands"]:
                if "method" in NECFG[cmd["TID"]]["commands"][command]:
                    if NECFG[cmd["TID"]]["commands"][command]["method"] == "handle_login":
                        login_command = command
            if login_command is None:
                return (False, None)
            data["progress"][login_command].remove(cmd["owner"])
            data["auth"].remove(auth_pair)
            self.lnelock.acquire()
            if cmd["TID"] in self.LNE:
                #Remove TID from LIVE TIDS
                self.LNE.remove(cmd["TID"])
            if cmd["TID"] in self.ANE:
                #Remove TID from LIVE TIDS
                self.ANE.remove(cmd["TID"])
            self.lnelock.release()
            if not self.LNE:
                with self.state:
                    # No alive NE pause autonomous msg
                    self.pause = True
            return (True, None)
        return (False, None)

    def handle_cpy_mem(self, cmd, data, cmd_config):
        '''
        handles CPY-MEM
        CPY-MEM:{{TID}}:ACT,{{DB_MEM_FILE}},RDISK,{{MEM_FILE}}:C::DBS:TIDCHK=Y
        note that for the SRC,SRCFILE,DST,DSTFILE argument, commas in field can be escaped with \,
        for example, src\,src,srcfile,dst,dst\,file will be parsed as:
                source: src,src
                source file: srcfile
                destination: dst
                destination file: dst,file
        there seems to be issues with double backslashes in telnet,
        so although more complicated escaping is supported, telnet does not support it
        Following modes are supported:
          - ACT --> RDISK (RAM memory limits checked)
          - RDISK --> STBY
          - ACT --> STBY
        :param cmd: CPY-MEM command and arguments
        :param data: NE executing CPY-MEM
        '''
        for param in ["SRC", "DST", "SRC_FILE"]:
            if param not in cmd:
                out = "   IMPS\n   /*Input, Parameter Missing*/"
                return(False, out)
        if not cmd.get("DST_FILE", ""):
            cmd["DST_FILE"] = cmd["SRC_FILE"]
        def copying(source, destination):
            '''Copy SRC --> DST '''
            # check if file exists
            if cmd["SRC_FILE"] not in data["files"][source]:
                out = "   IENE\n   /*{} File Does Not Exist*/".format(cmd["SRC_FILE"])
                return (False, out)
            # check memory available only when copying to ram
            if destination == "RAM" and data["MEM"] + NECFG[cmd["TID"]]["fileSize"] > data["MAXMEM"]:
                out = "   \PIMA\n   /*Memory Out Of Range*/"
                return (False, out)
            if destination == "RAM" and cmd["DST_FILE"] not in data["files"][destination]:
                data["MEM"] += NECFG[cmd["TID"]]["fileSize"]    #all same sizes
            data["files"][destination].add(cmd["DST_FILE"])
            return (True, cmd["DST_FILE"])
        # ACTIVE--> RAM
        if cmd["SRC"] == NECFG[cmd["TID"]]["memory"]["RAM"] and \
                   cmd["DST"] == NECFG[cmd["TID"]]["memory"]["ACTIVE"]:
            status, out = copying("RAM", "ACTIVE")
        elif cmd["SRC"] == NECFG[cmd["TID"]]["memory"]["ACTIVE"] and \
                   cmd["DST"] == NECFG[cmd["TID"]]["memory"]["RAM"]:
            status, out = copying("ACTIVE", "RAM")
        # ACTIVE--> STANDBY
        elif cmd["SRC"] == NECFG[cmd["TID"]]["memory"]["ACTIVE"] and \
              cmd["DST"] == NECFG[cmd["TID"]]["memory"]["STANDBY"]:
            status, out = copying("ACTIVE", "STANDBY")
        # RAM-->STANDBY
        elif cmd["SRC"] == NECFG[cmd["TID"]]["memory"]["RAM"] and \
              cmd["DST"] == NECFG[cmd["TID"]]["memory"]["STANDBY"]:
            status, out = copying("RAM", "STANDBY")
        else:
            status = False
            out = "   SROF\n   /*Operation Not Supported*/"
        return (status, out)

    def check_sne(self,key, keytype="nsap"):
        ''' get respective tid of nsap address'''
        for tid, tid_data in NEDATA.items():
            if str(key) == str(tid_data[keytype]):
                return tid
        return None

    def txfr_mode(self, cmd, data, cmd_config):
        '''
        Get the File Transfer mode
        :Return: (FTPin, FTPout | FTAMin | FTAMout | None, out)
        '''
        mode, out = None, None
        memloc = "RAM"
        for mem, alias in NECFG[cmd["TID"]]["memory"].items():
            if alias == cmd.get("MEMLOC"):
                memloc = mem
                break
        if cmd["SRC"] == NECFG[cmd["TID"]]["memory"][memloc]:
            # Check if dst is ip address or remote server
            if RGXIPV4.match(cmd["DST"]) or cmd["DST"] in data["remoteServer"]:
                mode = "FTPout"
            # Check if destinatin id SNE NSAP address
            elif self.check_sne(cmd["DST"], "nsap"):
                mode = "FTAMout"
            else:
                # could be ipv6, need to add regex
                mode = "FTPout"
                out = "   ERRO\n   /*{}, DST Unrecognized*/".format(cmd["DST"])
        elif cmd["DST"] == NECFG[cmd["TID"]]["memory"][memloc]:
            # check if source isn't ip address or not remote server key
            if RGXIPV4.match(cmd["SRC"]) or cmd["SRC"] in data["remoteServer"]:
                mode = "FTPin"
            # Check if source is SNE NSAP address
            elif self.check_sne(cmd["SRC"], "nsap"):
                mode = "FTAMin"
            else:
                # could be ipv6, need to add regex
                mode = "FTPin"
                out = "   ERRO\n   /*{}, SRC Unrecognized*/".format(cmd["SRC"])
        else:
            out = "   ERRO\n   /*Unrecognized SRC DST*/"
        return mode, out

    def local_copy(self, cmd, mode):
        ''' copying within simulator from from_tid to to_tid'''
        for param in ["SRC", "DST", "SRC_FILE", "OVERWRITE"]:
            if param not in cmd:
                ret = "   IMPS\n   /*Input, Parameter Missing*/"
                return (False, ret)
        if mode == "FTAMout":
            from_tid = cmd["TID"]
            to_tid = self.check_sne(cmd["DST"], "nsap")
        elif mode == "FTAMin":
            from_tid = self.check_sne(cmd["SRC"], "nsap")
            to_tid = cmd["TID"]
        if not from_tid or not to_tid:
            ret = "   IMPS\n   /*Input, Parameter Missing*/"
            return (False, ret)
        if cmd["SRC_FILE"] not in NEDATA[from_tid]["files"]["RAM"]:
            out = "   IENE\n   /*{} File Does Not Exist*/".format(cmd["SRC_FILE"])
            return (False, out)
        remoteExists = cmd["DST_FILE"] in NEDATA[to_tid]["files"]["RAM"]
        if not cmd["OVERWRITE"] and remoteExists:
            out = "   IEAE\n   /*File Already Exist Enable Overwrite*/"
            return (False, out)
        if not remoteExists and \
        NEDATA[to_tid]["MEM"] + NECFG[cmd["TID"]]["fileSize"] > NEDATA[to_tid]["MAXMEM"]:
            out = "   \PIMA\n   /*Memory Out Of Range*/"
            return (False, out)
        if not remoteExists:
            NEDATA[to_tid]["MEM"] += NECFG[cmd["TID"]]["fileSize"]
        NEDATA[to_tid]["files"]["RAM"].add(cmd["DST_FILE"])
        return (True, cmd["DST_FILE"])

    

    def handle_cpy_tftp(self, cmd, data, cmd_config):
        '''
        handle STA-UPLD command
        STA-UPLD:{{TID}}:{{SRC}}:{{CTAG}}:::SERVER={{DST}},FILE={{TFTPATH/DST_FILE}};
        @example:
        STA-UPLD:RNKNNYRNK01:NVM::::SERVER=166.34.96.148,FILE=RNKNNYRNK01;
        support: RAM/ACTIVE <===> TFTP
        :Arguments:
            1) cmd: command and respective arguments
            2) data: pre-configured NE data
            3) cmd_config: cmd configurations
        '''
        # assign default values
        memloc = "RAM"
        for mem, alias in NECFG[cmd["TID"]]["memory"].items():
            if alias == cmd.get("MEMLOC"):
                memloc = mem
                break
        cmd["SRC_FILE"] = cmd.get("SRC_FILE", NECFG[cmd["TID"]]["ALL"])
        cmd.setdefault("PORT", 69)
        for detail in ["DST", "SRC"]:
            if detail not in cmd:
                out = "   IMPS\n   /*Input, Parameter Missing*/"
                self.log_out(out)
                return (False, out)
        mode, out = self.txfr_mode(cmd, data, cmd_config)
        if not mode:
            self.log_out(out)
            return (False, out)
        src_files = data["files"][memloc] if cmd["SRC_FILE"] == NECFG[cmd["TID"]]["ALL"] \
                                                  else cmd["SRC_FILE"].split("&")
        dst_files = src_files if cmd["SRC_FILE"] == NECFG[cmd["TID"]]["ALL"] \
                                      else cmd["DST_FILE"].split("&")
        if len(src_files) != len(dst_files):
            out = "   IISP\n   /*Input, Invalid Syntax or Punctuation*/"
            self.log_out(out)
            return (False, out)
        try:
            if mode == "FTPout":
                tftp = tftpy.TftpClient(cmd["DST"], int(cmd["PORT"]))
                num = 1
                for src_file, dst_file in zip(src_files, dst_files):
                    if src_file not in data["files"][memloc]:
                        return (False, "   ERRO\n   /*{}, SRC_FILE DNE*/".format(src_file))
                    fobject = open(os.path.join(TDIR, src_file), 'w')
                    fobject.write("Sample file uploaded to TFTP srv")
                    fobject.close()
                    file_path = os.path.join(TDIR, src_file)
                    tftp.upload(dst_file, file_path)
                    cmd["DST_FILE" + str(num)] = dst_file
                    num += 1
            elif mode == "FTPin":
                tftp = tftpy.TftpClient(cmd["SRC"], int(cmd["PORT"]))
                num = 1
                for src_file, dst_file in zip(src_files, dst_files):
                    file_path = os.path.join(TDIR, dst_file)
                    tftp.download(src_file, file_path)
                    if not os.path.exists(file_path):
                        raise Exception("{}-downloading failed".format(src_file))
                    if dst_file not in data["files"][memloc]:
                        data["MEM"] += NECFG[cmd["TID"]]["fileSize"]
                    data["files"][memloc].add(dst_file)
                    cmd["DST_FILE" + str(num)] = dst_file
                    num += 1
        except Exception  as exe:
            self.log_error("Error: {}".format(exe))
            return (False, None)
        return (True, cmd["DST_FILE"])

    
    def handle_cpy_file(self, cmd, data, cmd_config):
        '''
        handles CPY-FILE
        :command:
        CPY-FILE:{{TID}}:{{SRC}},{{MEM_FILE}},{{DST}},{{MEM_FILE}}:C:::OVERWRITE=Y,
        FTUID="{{FTP_USER}}",FTPID="{{FTP_PASSWD}}",FTPATH="{{FTP_PATH}}",SIGNATURE={{NE_SIGN}}

        used in GNE FTP (RDISK -> FTP) and SNE/RNE FTAM (SNE -> GNE -> FTP)
        for FTAM SNE -> GNE, it is currently assumed that the TARP for the SNE is the TID of the SNE
        DOES NOT PERFORM SYNTAX CHECKING OF ARGUMENTS
        only supports copying local files to remote
        :param:
          - cmd: CPY-FILE command and arguments
          - data: NE executing CPY-FILE
        '''
        # check mandatory arguments
        memloc = "RAM"
        for mem, alias in NECFG[cmd["TID"]]["memory"].items():
            if alias == cmd.get("MEMLOC"):
                memloc = mem
                break
        cmd.setdefault("SRC", NECFG[cmd["TID"]]["memory"]["RAM"])
        parameters = ["SRC", "DST", "SRC_FILE", "FTUID", "FTPID", "FTPATH"]
        for param in parameters[0:3]:
            if param not in cmd:
                ret = "   IMPS\n   /*Input, Parameter Missing*/"
                return (False, ret)
        cmd.setdefault("DST_FILE", cmd["SRC_FILE"])
        mode, out = self.txfr_mode(cmd, data, cmd_config)
        if not mode:
            self.log_out(out)
            return (False, out)
        src_files = data["files"]["RAM"] if cmd["SRC_FILE"] == \
                 NECFG[cmd["TID"]]["ALL"] else cmd["SRC_FILE"].split("&")
        dst_files = src_files if cmd["SRC_FILE"] == NECFG[cmd["TID"]]["ALL"] \
                  else cmd.get("DST_FILE",cmd["SRC_FILE"]).split("&")
        if len(src_files) != len(dst_files):
            out = "   IISP\n   /*Input, Invalid Syntax or Punctuation*/"
            self.log_out(out)
            return (False, out)
        ## set post conditions:
        ## copies the file to destination
        if mode == "FTPout":
            if cmd["DST"] in data["remoteServer"]:
                #print("DST is into remoteServer key")
                # add ftp server detail from remoteServer
                svr = cmd["DST"]
                cmd["DST"] = data["remoteServer"][svr]["ADDR"]
                cmd["PORT"] = data["remoteServer"][svr]["PORT"]
                cmd["FTPATH"] = data["remoteServer"][svr]["DIR"]
            for param in parameters[3:]:
                if param not in cmd:
                    ret = "   IMPS\n   /*Input, Parameter Missing*/"
                    return (False, ret)
            if "OVERWRITE" not in cmd or not cmd["OVERWRITE"]:
                out = "   ERRO\n   /*Overwrit Not Enabled*/"
                return (False, out)
            try:
                ftp = ftplib.FTP()
                ftp.connect(cmd["DST"], cmd["PORT"])
                ftp.login(cmd["FTUID"], cmd["FTPID"])   #strip quotes
                try:
                    ftp.cwd(cmd["FTPATH"])  #strip quotes
                except:
                    self.log_debug("making ftp directory")
                    ftp.cwd("/")
                    path_data = cmd["FTPATH"].split("/")
                    for folder in path_data:
                        if folder == "":
                            continue
                        try:
                            ftp.cwd(folder)
                        except:
                            ftp.mkd(folder)
                            ftp.cwd(folder)
                    self.log_debug("made folder")
                num = 1
                for src_file, dst_file in zip(src_files, dst_files):
                    if src_file not in data["files"][memloc]:
                        return (False, "   ERRO\n   /*{}, SRC_FILE DNE*/".format(src_file))
                    # create temp local file fore ftp
                    # copy file to ftp
                    file_path = os.path.join(TDIR, src_file)
                    with open(file_path, 'w') as fobject:
                        # to avoid empty file
                        fobject.write("Sample file used to perform copy operation")
                        pass
                    with open(file_path, 'rb') as file_obj:
                        resp = ftp.storbinary("STOR " + dst_file, file_obj)
                        self.log_debug("ftp response: {}".format(resp))
                        if not resp.startswith("226"):
                            raise ftplib.error_reply
                    cmd["DST_FILE" + str(num)] = dst_file
                    num += 1
            except Exception  as exe:
                self.log_error("Error {}".format(exe))
                return (False, None)
            finally:
                try:
                    ftp.quit()
                except:
                    pass
        elif mode == "FTPin":
            if cmd["SRC"] in data["remoteServer"]:
                self.log_debug("SRC is into remoteServer key")
                # add ftp server detail from remoteServer
                svr = cmd["SRC"]
                cmd["SRC"] = data["remoteServer"][svr]["ADDR"]
                cmd["PORT"] = data["remoteServer"][svr]["PORT"]
                cmd["FTPATH"] = data["remoteServer"][svr]["DIR"]
            for param in parameters[3:]:
                if param not in cmd:
                    ret = "   IMPS\n   /*Input, Parameter Missing*/"
                    return (False, ret)
            local_exists = any(dst_file in data["files"]["RAM"] for dst_file in dst_files)
            if local_exists and ("OVERWRITE" not in cmd or not cmd["OVERWRITE"]):
                out = "   IEAE\n   /*File Already Exist Enable Overwrite*/"
                self.log_out(out)
                return (False, out)
            try:
                ftp = ftplib.FTP()
                ftp.connect(cmd["SRC"], cmd["PORT"])
                ftp.login(cmd["FTUID"], cmd["FTPID"])   #strip quotes
                available = [os.path.basename(fil) for fil in ftp.nlst(cmd["FTPATH"])]
                num = 1
                for src_file, dst_file in zip(src_files, dst_files):
                    if src_file not in available:
                        raise Exception("{} file DNE in FTP server".format(src_file))
                    if not dst_file in data["files"]["RAM"]:
                        data["MEM"] += NECFG[cmd["TID"]]["fileSize"]
                    data["files"]["RAM"].add(dst_file)
                    cmd["DST_FILE" + str(num)] = dst_file
                    num += 1
            except Exception  as exe:
                self.log_error("FTP Error:{}".format(exe))
                return (False, None)
            finally:
                try:
                    ftp.quit()
                except:
                    pass
        elif mode == "FTAMout" or mode == "FTAMin":
            status, out = self.local_copy(cmd, mode)
            if not status:
                return (False, out)
        self.log_debug("FTP success")
        return (True, cmd["DST_FILE"])

    def handle_copy_file_fttd(self, cmd, data, cmd_config):
        '''
        handles COPY-RFILE
        :command:
         - COPY-RFILE:{{TID}}:{{SRC_FILE}}:C::{{XFERTYPE}},{{DST}},{{DST_URL}},YES,"{{FTTD_URI}}"
         - COPY-RFILE:{{TID}}::C::{{XFERTYPE}},"FILE:///{{MEM_FILE}}","FTP://{{FTP_USER}}:
                 {{FTP_PASSWD}}@{{FTP_SERVER}}{{FTP_PATH}}{{MEM_FILE}}",YES,"{{FTTD_URI}}"
        source files are always assumed to be in root
        asumed FTP_USER, FTP_PASSWD, FTP_SERVER, FTP_PATH, and MEM_FILE are parsable by curl,
        which is the underlying command.the expected format of the FTP block is:
        DST_URL = "FTP://{{FTP_USER}}:{{FTP_PASSWD}}@{{FTP_SERVER}}/{{FTP_PATH}}/{{MEM_FILE}}"
        absolute path or relative path to entrypoint is required
        :param cmd: COPY-RFILE command and arguments
        :param data: NE executing COPY-RFILE
        '''
        # Assign default values
        # ftp or sftp in SRC_URI then restore
        # ftp or sftp in DST_URI then backup
        memloc = "RAM"
        for mem, alias in NECFG[cmd["TID"]]["memory"].items():
            if alias == cmd.get("MEMLOC"):
                memloc = mem
                break
        cmd.setdefault("SRC_FILE", NECFG[cmd["TID"]]["ALL"])
        #parse the local file path
        # localFile = cmd["SRC_FILE"][1:-1][8:] # TODO: will this change?
        for param in ["SRC_FILE", "DST_URI", "OVERWRITE"]:
            if param not in cmd:
                ret = "   IMPS\n   /*Input, Parameter Missing*/"
                return (False, ret)
            if param == "OVERWRITE" and not cmd.get(param):
                out = "   ERRO\n   /*Overwrit Not Enabled*/"
                return (False, out)
        mode = None
        if "@" in cmd.get("DST_URI", None) and "ftp" in cmd.get("DST_URI", None):
            mode = "FTTDout"
        elif "@" in cmd.get("SRC_URI", None) and "ftp" in cmd.get("SRC_URI", None):
            mode = "FTTDin"
        else:
            return (False, None)
        local_files = cmd["SRC_FILE"].split("&") if cmd["SRC_FILE"] != NECFG[cmd["TID"]]["ALL"] \
                      else data["files"][memloc]
        if mode == "FTTDout":
            for local_file in local_files:
                # get source file
                localFile = re.search(r"FILE:(.*?)(([\w\.]|-)+)", local_file)
                local_file = localFile.group(2) if localFile else local_file
                #local_file = local_file.group(2)
                self.log_debug("found local file: {}".format(local_file))
                if local_file not in data["files"][memloc]:
                    out = "   /* File Not Found In RAM */"
                    return (False, out)
                file_obj = open(os.path.join(TDIR, local_file), 'w')
                #create a temp local file to FTP
                file_obj.write("Sample FILE to verify File Transfer")
                file_obj.close()
                ftp_uri = cmd["DST_URI"].strip('\"')
                cmds = ["curl", "-p", ftp_uri, "-T", os.path.join(TDIR, local_file), \
                                                      "--ftp-create-dirs", "-v"]
                curl_proc = subprocess.Popen(cmds, stdout=subprocess.PIPE, \
                                                   stderr=subprocess.STDOUT)
                curl_result = curl_proc.communicate()
                if "226 Transfer complete" not in curl_result[0]:
                    self.log_debug("FTPout Curl Failed")
                    return (False, None)
        elif mode == "FTTDin":
            ftp_uri = cmd["SRC_URI"].strip('\"')
            cmds = ["curl", "-p", ftp_uri, "--ftp-create-dirs", "-v"]
            curl_proc = subprocess.Popen(cmds, stdout=subprocess.PIPE, \
                                               stderr=subprocess.STDOUT)
            curl_result = curl_proc.communicate()
            if "226 Transfer complete" not in curl_result[0]:
                self.log_debug("FTPin Curl Failed")
                return (False, None)
        return (True, None)

    def handle_cpy_file_sftp(self, cmd, data, cmd_config):
        '''
        handles CPY-SFILE
        CPY-SFILE:{{TID}}:RDISK,{{MEM_FILE}},{{FTP_SERVER}},{{MEM_FILE}}:C:::OVERWRITE=Y,
        FTUID="{{FTP_USER}}",FTPID="{{FTP_PASSWD}}",FTPATH="{{FTP_PATH}}",PORT={{FTPORT}},
                                                                    SIGNATURE={{NE_SIGN}}
        absolute path is required, unlike handle_cpy_file(),
        unless the path is relative to the default entrypoint
        :param cmd: CPY-SFILE command and arguments
        :param data: NE executing CPY-SFILE
        '''
        # check mandatory arguments
        def setup_sftp(remote):
            cnopts = pysftp.CnOpts(knownhosts='known_hosts') #pysftp.CnOpts()
            hostkeys = None
            if cnopts.hostkeys.lookup(remote) is None:
                self.log_debug("new ssh host")
                hostkeys = cnopts.hostkeys
                cnopts.hostkeys = None
                self.log_debug(cnopts.hostkeys)
                self.log_debug("accepted new host")
            return cnopts, hostkeys
        memloc = "RAM"
        for mem, alias in NECFG[cmd["TID"]]["memory"].items():
            if alias == cmd.get("MEMLOC"):
                memloc = mem
                break
        parameters = ["SRC", "DST", "SRC_FILE", "FTUID", "FTPID", "FTPATH"]
        for param in parameters[0:3]:
            if param not in cmd:
                ret = "   IMPS\n   /*Input, Parameter Missing*/"
                return (False, ret)
        cmd.setdefault("DST_FILE", cmd["SRC_FILE"])
        mode, out = self.txfr_mode(cmd, data, cmd_config)
        if not mode:
            return (False, out)
        src_files = data["files"]["RAM"] if cmd["SRC_FILE"] == \
                 NECFG[cmd["TID"]]["ALL"] else cmd["SRC_FILE"].split("&")
        dst_files = src_files if cmd["SRC_FILE"] == NECFG[cmd["TID"]]["ALL"] \
                  else cmd.get("DST_FILE",cmd["SRC_FILE"]).split("&")
        if len(src_files) != len(dst_files):
            out = "   IISP\n   /*Input, Invalid Syntax or Punctuation*/"
            return (False, out)
        ## set post conditions:
        ## - copies the file to destination
        if mode == "FTPout":
            if cmd["DST"] in data["remoteServer"]:
                #print("DST is into remoteServer key")
                # add ftp server detail from remoteServer
                svr = cmd["DST"]
                cmd["DST"] = data["remoteServer"][svr]["ADDR"]
                cmd["PORT"] = data["remoteServer"][svr]["PORT"]
                cmd["FTPATH"] = data["remoteServer"][svr]["DIR"]
            for param in parameters[3:]:
                if param not in cmd:
                    ret = "   IMPS\n   /*Input, Parameter Missing*/"
                    return (False, ret)
            if "OVERWRITE" not in cmd or not cmd["OVERWRITE"]:
                out = "   ERRO\n   /*Overwrit Not Enabled*/"
                return (False, out)
            cnopts = pysftp.CnOpts(knownhosts='known_hosts') #pysftp.CnOpts()
            hostkeys = None
            if cnopts.hostkeys.lookup(cmd["DST"]) is None:
                hostkeys = cnopts.hostkeys
                cnopts.hostkeys = None
            try:
                with pysftp.Connection(cmd["DST"], username=cmd["FTUID"], password=cmd["FTPID"],\
                                               port=int(cmd["PORT"]), cnopts=cnopts) as sftp:
                    if hostkeys != None:
                        if not os.path.exists(os.path.join(os.environ["HOME"], ".ssh")):
                            os.makedirs(os.path.join(os.environ["HOME"], ".ssh"))
                        with open(os.path.join(os.environ["HOME"], ".ssh", "known_hosts"), "a") \
                                                                                      as fobject:
                            pass
                        hostkeys.add(cmd["DST"], sftp.remote_server_key.get_name(), \
                                                              sftp.remote_server_key)
                        hostkeys.save(pysftp.helpers.known_hosts())
                    try:
                        sftp.cwd(cmd["FTPATH"]) #strip quotes
                    except:
                        self.log_debug("making sftp directory")
                        sftp.cwd("/")
                        path_data = cmd["FTPATH"].split("/")
                        for folder in path_data:
                            if folder == "":
                                continue
                            try:
                                sftp.cwd(folder)
                            except:
                                sftp.mkdir(folder)
                                sftp.cwd(folder)
                        self.log_debug("made folder")
                    num = 1
                    for src_file, dst_file in zip(src_files, dst_files):
                        if src_file not in data["files"][memloc]:
                            return (False, "   ERRO\n   /*{}, FILE Does Not Exist*/".format(src_file))
                        # create temp local file fore ftp
                        # copy file to ftp
                        file_path = os.path.join(TDIR, src_file)
                        with open(file_path, 'w') as fobject:
                            # to avoid empty file
                            fobject.write("Sample file used to perform copy operation")
                            pass
                        sftp.put(file_path, dst_file)
                        cmd["DST_FILE" + str(num)] = dst_file
                        num += 1
            except Exception as exc:
                    self.log_error("SFTP Error: {}".format(exc))
                    return (False, None)
            finally:
                    try:
                        sftp.close()
                    except:
                        pass
        if mode == "FTPin":
            if cmd["SRC"] in data["remoteServer"]:
                #print("SRC is into remoteServer key")
                # add ftp server detail from remoteServer
                svr = cmd["SRC"]
                cmd["SRC"] = data["remoteServer"][svr]["ADDR"]
                cmd["PORT"] = data["remoteServer"][svr]["PORT"]
                cmd["FTPATH"] = data["remoteServer"][svr]["DIR"]
            for param in parameters[3:]:
                if param not in cmd:
                    ret = "   IMPS\n   /*Input, Parameter Missing*/"
                    return (False, ret)
            local_exists = any(dst_file in data["files"]["RAM"] for dst_file in dst_files)
            if local_exists and ("OVERWRITE" not in cmd or not cmd["OVERWRITE"]):
                out = "   IEAE\n   /*File Already Exist Enable Overwrite*/"
                return False, out
            #else not a local NE, connect to remote server
            try:
                cnopts, hostkeys = self.setup_sftp(cmd["SRC"])
                with pysftp.Connection(cmd["SRC"], username=cmd["FTUID"], password=cmd["FTPID"], port=int(cmd["PORT"]), cnopts=cnopts) as sftp:
                    if hostkeys != None:
                        if not os.path.exists(os.path.join(os.environ["HOME"], ".ssh")):
                            os.makedirs(os.path.join(os.environ["HOME"], ".ssh"))
                        with open(os.path.join(os.environ["HOME"], ".ssh", "known_hosts"), "a") as fd:
                            pass
                        hostkeys.add(cmd["DST"], sftp.remote_server_key.get_name(), sftp.remote_server_key)
                        hostkeys.save(pysftp.helpers.known_hosts())
                    try:
                        sftp.cwd(cmd["FTPATH"])	#strip quotes
                    except:
                        out = "   ERRO\n   /*Fail to Change Directory*/"
                        return (False, out)
                    #check if file exists
                    num = 1
                    for src_file, dst_file in zip(src_files, dst_files):
                        try:
                            sftp.isfile(src_file)
                            if local_exists:
                                data["MEM"] += NECFG[cmd["TID"]]["fileSize"]
                            data["files"]["RAM"].add(dst_file)
                        except FileNotFoundError:
                            out = "   IENE\n   /*File Does not Exist in Server*/"
                            return (False, out)
                        cmd["DST_FILE" + str(num)] = dst_file
                        num += 1
                    #add file
            except Exception as exc:
                    self.log_error("SFTP Error: {}".format(exc))
                    return (False, None)
            finally:
                    try:
                        sftp.close()
                    except:
                        pass
        elif mode == "FTAMout" or mode == "FTAMin":
            status, out = self.local_copy(cmd, mode)
            if not status:
                return (False, out)
        self.log_debug("sftp success")
        return (True, cmd["DST_FILE"])


    def handle_dlt_file(self, cmd, data, cmd_config):
        '''
        handles DLT-FILE
        DLT-FILE:{{TID}}:ALL|{{MEM_FILE}}:C
        only deletes from RAM
        :param cmd: DLT-FILE command and arguments
        :param data: NE executing DLT-FILE
        '''
        #can only delete from RAM
        if cmd["AID"] != NECFG[cmd["TID"]]["ALL"] and cmd["AID"] not in data["files"]["RAM"]:
            out = "   IENE\n   /*File Does not Exist*/"
            return (False, out)
        if cmd["AID"] == NECFG[cmd["TID"]]["ALL"]:
            data["files"]["RAM"].clear()
            data["MEM"] = 0
        else:
            data["files"]["RAM"].remove(cmd["AID"])
            data["MEM"] -= NECFG[cmd["TID"]]["fileSize"]
        return (True, None)

    def handle_ed_ftp_client(self, cmd, data, cmd_config):
        '''
        handles ED-FTP-CLIENT | handles ED-SFTP-CLIENT
        ED-FTP-CLNT:{{TID}}::C::::IS
        ED-SFTP-CLNT:{{TID}}::C::::IS
        :param cmd: ED-FTP-CLIENT command and arguments
        :param data: NE executing ED-FTP-CLIENT
        '''
        if cmd["CLNT_STATE"] not in NECFG[cmd["TID"]]["options"]["{{CLNT_STATE}}"]:
            return (False, None)
        data["progress"][cmd["command"]] = cmd["CLNT_STATE"]
        return (True, cmd["CLNT_STATE"])

    def handle_opr_tef(self, cmd, data, cmd_config):
        '''
        handles OPR-TEF
        OPR-TEF:{{TID}}::C::{{DTID}}
        :param cmd: OPR-TEF command and arguments
        :param data: NE executing OPR-TEF
        '''
        if "DTID" not in cmd:
            out = "   IMPS\n   /*Input, Parameter Missing*/"
            return (False, out)
        if cmd["DTID"] not in NEDATA:
            return (False, out)
        return (True, NEDATA[cmd["DTID"]]["nsap"])

    def handle_rtrv_remote_server(self, cmd, data, cmd_config):
        '''
        handle_rtrv_remote_server
        '''
        ret = []
        if not data["remoteServer"]:
            # return(True, "/*No Remote Server Data on RAM Disk*/")
            return (True, ret)
        elif cmd["AID"] == NECFG[cmd["TID"]]["ALL"]:
            # data_str = ""
            for server in data["remoteServer"].values():
                ret.append(server)
        elif cmd["AID"] in data["remoteServer"]: # key exist append that dict
            ret.append(data[remoteServer][cmd["AID"]])
        return (True, ret)

    def handle_rtrv_modifier(self, cmd, data, cmd_config):
        '''
        handle_rtrv_record
        "RTRV-MODIFIER:{{TID}}:{{AID}}:{{CTAG}}:::{{KWBLOCK}}"
        KWBLOCK == [ID1=<VALUE>]
        1) RTRV by property
        2) RTRV by AID:: No need to pass property of AID, will be ignored if passed
        Example::
        RTRV-FTPSERVER:TID::C:::IPADDR=10.20.30.40;
        '''
        ret = []
        records = NECFG[cmd["TID"]].get("MODIFIER", {}).get(cmd["MODIFIER"], {})
        for key in records.keys():
            if key.startswith("#"):
                unique_key = key
                break
        else:
            return (False, "\n   IEDE\n   /*Input, Entity Does Not Exist*/")
        print("@debug1",records.keys(), cmd.get("AID"))
        if cmd.get("AID") in records.keys():
            # Return record matching with aid
            ret.append(records[cmd["AID"]])
        elif cmd.get("AID") and cmd.get("AID") != NECFG[cmd["TID"]]["ALL"]: # cond fail if AID == ""
            out = "\n   IIAC\n   /*Input, Invalid Access Identifier*/"
            return (False, out)
        elif cmd.get("KWBLOCK") or cmd.get("PSBLOCK"):
            # return intersection of matching property
            search = [header for header in records[unique_key].keys() if cmd.get(header)]
            if search:
                for record in records.values():
                    for header in search:
                        if cmd[header] != record[header]:
                            break
                    else: # full loop executed  means match found
                        ret.append(record)
        elif cmd.get("AID") == NECFG[cmd["TID"]]["ALL"]:
            # return All Records
            for key, record in records.items():
                if key == unique_key:
                    continue
                ret.append(record)
        return (True, ret)

    def handle_delete_modifier(self, cmd, data, cmd_config):
        '''
        handle_delete_record
        "DELETE-MODIFIER:{{TID}}:{{AID}}:{{CTAG}}:::{{KWBLOCK}}"
        KWBLOCK == [ID1=<VALUE>]
        delete record by AID or matching property passed in KWBLOCK section
        Example::
        RTRV-FTPSERVER:TID::C:::IPADDR=10.20.30.40;
        '''
        status, out = True, None
        records = NECFG[cmd["TID"]].get("MODIFIER", {}).get(cmd["MODIFIER"], {})
        for key in records.keys():
            if key.startswith("#"):
                unique_key = key
                break
        else:
            return (False, None)
        if cmd.get("AID") in records.keys():
            # delete matching record
            del records[cmd["AID"]]
        elif cmd.get("AID") and cmd.get("AID") != NECFG[cmd["TID"]]["ALL"]: # will fail if AID == ""
            out = "   IIAC\n   /*Input, Invalid Access Identifier*/"
            status = False
        elif cmd.get("KWBLOCK") or cmd.get("PSBLOCK"):
            # delete intersection of matching property
            search = [header for header in records[unique_key].keys() if cmd.get(header)]
            if search:
                for aid in records.keys():
                    for header in search:
                        if cmd[header] != records[aid][header]:
                            break
                    else: # all property matched
                        del records[aid]
        elif cmd.get("AID") == NECFG[cmd["TID"]]["ALL"]:
            # delete All Records
            for aid in records.keys():
                if aid == unique_key:
                    continue
                del records[aid]
        return (status, out)

    def handle_add_modifier(self, cmd, data, cmd_config):
        '''
        handle_add_record
        "ADD-MODIFIER:{{TID}}:{{AID}}:{{CTAG}}:::{{KWBLOCK}}"
        KWBLOCK == [ID1=<VALUE>,ID2=<VALUE>...]
        AID is optional consider unique proprty (name of entity) as AID while adding
        '''
        records = NECFG[cmd["TID"]].get("MODIFIER", {}).get(cmd["MODIFIER"], {})
        for key in records.keys():
            if key.startswith("#"):
                unique_key = key
                break
        else:
            return (False, None)
        aid = unique_key.strip('#')
        if cmd("KWBLOCK") or cmd("PSBLOCK"):
            record = {}
            # add record if it contain all req params
            for param in records[unique_key].keys():
                if cmd.get(param, "") == "":
                    out = "   IMPS\n   /*Input, Parameter Missing*/"
                    return (False, out)
                record[param] = cmd[param]
            records[record[aid]] = record
        else:
            out = "   IBMS\n   /*Input, Block Missing*/"
            return (False, out)
        return (True, None)

    def handle_edit_modifier(self, cmd, data, cmd_config):
        '''
        handle_edit_record
        "EDIT-MODIFIER:{{TID}}:{{AID}}:{{CTAG}}:::{{KWBLOCK}}"
        KWBLOCK == [ID1=<VALUE>,ID2=<VALUE>...]
        AID is manadatory either to pass in KWBLOCK section or AID section
        '''
        status, out = True, None
        records = NECFG[cmd["TID"]].get("MODIFIER", {}).get(cmd["MODIFIER"], {})
        # find unique key which contain the modifier defination
        for key in records.keys():
            if key.startswith("#"):
                unique_key = key
                break
        else:
            return (False, None)
        aid = unique_key.strip('#')
        rec_aid = cmd.get("AID") or cmd.get(aid)
        if not rec_aid:
            out = "   IMPS\n   /*Input, Parameter Missing*/"
            status = False
        elif rec_aid not in records.keys():
            out = "   IIAC\n   /*Input, Invalid Access Identifier*/"
            status = False
        else: #cmd.get("KWBLOCK") or cmd.get("PSBLOCK"):
            for param in records[unique_key].keys():
                # 1st element in records, will define parameters type
                # apply value type check before adding
                if param != aid and cmd.get(param):
                    records[rec_aid][param] = cmd[param]
        #else:
        #    out = "   IBMS\n   /*Input, Block {} Missing*/"
        #    status = False
        return (status, out)

    import threading

    def handle_generic(self, cmd, data, cmd_config):
        '''
        handle_generic -
        "CMD:{{TID}}:{{AID}}:{{CTAG}}:"
        No Action return True and None
        '''
        if cmd.get("auto_msg"):
            async_msg = threading.Thread(target=self.msg_in_active_session, args=(cmd, data, cmd_config))
            # start thread if autoMsg feature True
            async_msg.start()
        self.LNE.append(cmd["TID"])
        if self.AUTOMSG and len(self.LNE) == 1:
            with self.state:
                self.pause = False  # enable autonomous msg
                self.state.notify()  # unblock pause thresd
        return (True, None)

    def handle_set_remote_server(self, cmd, data, cmd_config):
        '''
        handles CPY-MEM
        SET-REMOTE-SERVER:{{TID}}::{{CTAG}}::mod:{{KWBLOCK}}
        '''
        #check if block data is not proper
        for key in ["SVR", "ADDR", "PORT", "DIR"]:
            if key not in cmd:
                # incomplete KWBLOCK data
                return (False, None)
        # verify block data before adding
        if not RGXIPV4.match(cmd["ADDR"]):
            #not proper ip
            out = "   IPNV\n   /*Invalid Remote IP Address*/"
            return (False, out)
        #proper block data add to remoteServer
        data["remoteServer"][cmd["SVR"]] = {"SVR": cmd["SVR"], "ADDR": cmd["ADDR"], \
                                              "PORT": cmd["PORT"], "DIR": cmd["DIR"]}
        return (True, cmd["SVR"])

    def handle_rtrv_file(self, cmd, data, cmd_config):
        '''
        handles file retrieval from RAM/ACTIVE/STANDBY
        :Command:
          - RTRV-FILE-NVM:{{TID}}:{{AID}}:C::::{{MEMLOC}}
          - RTRV-FILE-RDISK:{{TID}}:ALL|{{MEM_FILE}}:C
        :Param and possible values
          - MEMLOC = RAM (default) | ACTIVE | STANDBY
          - AID = ALL | MEM_FILE
        '''
        # default MEMLOC == RAM
        for memloc, alias in NECFG[cmd["TID"]]["memory"].items():
            if alias == cmd.get("MEMLOC"):
                memlist = [memloc]
                break
        else:
            if cmd.get("MEMLOC") == NECFG[cmd["TID"]]["ALL"]:
                memlist = ["ACTIVE", "STANDBY"]
            else:
                return (False, "   PIMA\n   /*Invalid Memory Address*/")
        ret = []
        if cmd.get("AID") == NECFG[cmd["TID"]]["ALL"]:
            for mem_area in memlist:
                for file_name in data["files"][mem_area]:
                    ret.append({"FILE": file_name, "TYPE": "DBS", "GISSUE": data["data"]["version"],\
                                "UPDTDAT": "UPDTDAT", "UPDTTM": "UPDTTM", "BKUPDAT": "BKUPDAT",\
                                "BKUPTM": "BKUPTM", "COMMENT": "", \
                                "MEMLOC": NECFG[cmd["TID"]]["memory"][mem_area],\
                                "SIZE": NECFG[cmd["TID"]]["fileSize"], "CRDAT": "CRDAT", "CRTM": "CRTM",\
                                "SIGNATURE": "SIGNATURE"})
        else:
            #find the file in the specified memory location
            for mem_area in memlist:
                if cmd["AID"] in data["files"][mem_area]:
                    # Returning File with given property
                    ret.append({"FILE": cmd["AID"], "TYPE": "DBS", "GISSUE": data["data"]["version"],\
                                "UPDTDAT": "UPDTDAT", "UPDTTM": "UPDTTM", "BKUPDAT": "BKUPDAT",\
                                "BKUPTM": "BKUPTM", "COMMENT": "", \
                                "MEMLOC": NECFG[cmd["TID"]]["memory"][mem_area],\
                                "SIZE": NECFG[cmd["TID"]]["fileSize"], "CRDAT": "CRDAT", "CRTM": "CRTM",\
                                "SIGNATURE": "SIGNATURE"})

        return (True, ret)

    def handle_get_nsap_addr(self, cmd, data, cmd_config):
        '''
        handles RTRV-TARP-CACHE
        RTRV-TARP-CACHE:{{TID}}:{{DTID}}:C
        follows handle_cpy_mem() comma parsing
        :param cmd: RTRV-TARP-CACHE command and arguments
        :param data: NE executing RTRV-TARP-CACHE
        set post conditions:
         - return TARP cache (NSAP address of DTID)
        '''
        if cmd.get("DTID", "") == "":
             return (False, None)
        if cmd["DTID"] not in NEDATA:
            return (False, None)
        #respond with my own TID|NSAP and DTID|NSAP; do I respond with my own?
        #TODO: verify order of response: the SNE/RNE must be returned first
        return (True, NEDATA[cmd["DTID"]]["nsap"])

    def handle_rtrv_version(self, cmd, data, cmd_config):
        '''
        handles RTRV-VERSION
        RTRV-VERSION:{{TID}}:{{AID}}:C
        AID is ALL, ACT, or STBY
        :param cmd: RTRV-VERSION command and arguments
        :param data: NE executing RTRV-VERSION
        :set post conditions:
        - return version info
        - TODO: what is stored??? currently returns the version in GISSUE and GDBISSUE
        '''
        if cmd["AID"] == NECFG[cmd["TID"]]["ALL"]:
            mem_list = ["ACTIVE", "STANDBY"]
        elif cmd["AID"] in NECFG[cmd["TID"]]["memory"].values():
            for memlocation, memloc in NECFG[cmd["TID"]]["memory"].items():
                if memloc == cmd["AID"]:
                    mem_list = [memlocation]
                    break
        else:
            return (False, "   IIAC\n   /*Input, Invalid Access Identifier*/")
        ret = []
        for mem in mem_list:
            ret.append({"MEMLOC": NECFG[cmd["TID"]]["memory"][mem], "VERSION": data["data"]["version"]})
        return (True, ret)



    def handle_rtrv_nbr(self, cmd, data, cmd_config):
        '''
        handle_rtrv_nbr: Function will return the list of Neibhour nodes details like
        where,
        NBTID  :Neighbour NE TID
        NBNSAP :Neighbour NE NSAP
        CKT    :CircuitID
        LID    :LinkID
        PORT   :Port Number

        Return if GNE: [
          {"NBTID": "LDSCAAAB-0", "NBNSAP": "0", "CKT": 1, "LID": GG(N-1)+(N), "PORT": 1},
          {"NBTID": "LDSCAAAB-2", "NBNSAP": "2", "CKT": 3, "LID": GG(N)+(N+1), "PORT": 2},
          {"NBTID": "LDSCAAAB-1-0", "NBNSAP": "3", "CKT": 5, "LID": GS10, "PORT": 3},
          ,,,
        ]
        Return if SNE: [
          {"NBTID": "LDSCAAAB-1", "NBNSAP": "4", "CKT": 7, "LID": GS11, "PORT": 4},
          ,,,
        ]
        Example::
        '''
        try:
            ret = []
            jump = int(cmd.get("JUMP",2))
            tid_list = cmd.get("TID").split('-')
            netype = NEDATA[cmd.get("TID")]["type"]
            # calculate the toatl number GNE and number of SNE belongs to the set
            nGNE = 0
            nSNE = 0
            for k, v in NEDATA.items():
                if k.startswith(tid_list[0]) and v["type"] == "GNE":
                        nGNE += 1
                elif k.startswith(cmd.get("TID")) and v["type"] == "RNE":
                        nSNE += 1
            # TODO Restrict port to certain number 
            # must be configuarable from model settings file
            # n-[1-9]-[1-9]
            if netype == "GNE":
                # Form neighbor GNE details
                n = 1
                gne_num = str(nGNE-1 if tid_list[1]=="0" else int(tid_list[1])-1)
                nbr_tid = tid_list[0] + "-" + gne_num
                lid = "GG" + (gne_num + tid_list[1]).rjust(6, "0")
                lnbr = {
                    "TID": cmd.get("TID"),
                    "NBTID": nbr_tid,
                    "NBNSAP": NEDATA[nbr_tid]["nsap"],
                    "CKT2": n*jump,
                    "CKT1": n*jump-1,
                    "LID": lid,
                    "PORT": n
                }
                # Construct 2nd neighbor GNE details
                n = n+1
                gne_num = str(0 if int(tid_list[1])==(nGNE-1) else int(tid_list[1])+1)
                nbr_tid = tid_list[0] + "-" + gne_num
                lid = "GG" + (tid_list[1] + gne_num).rjust(6, "0")
                rnbr = {
                    "TID": cmd.get("TID"),
                    "NBTID": nbr_tid,
                    "NBNSAP": NEDATA[nbr_tid]["nsap"],
                    "CKT2": n*jump,
                    "CKT1": n*jump-1,
                    "LID": lid,
                    "PORT": n
                }
                # Swapping CKT, PORT if the main node_id is odd
                if int(tid_list[1])%2==1:
                    lnbr["PORT"], rnbr["PORT"] = rnbr["PORT"], lnbr["PORT"]
                ret.extend([lnbr, rnbr])
                n = n+1
                # insert all neighbor SNE details
                for sne_num in range(0, nSNE):
                    n = n + sne_num
                    nbr_tid = tid_list[0] + "-" + tid_list[1] + "-" + str(sne_num)
                    lid = "GS" + str(sne_num).rjust(6, "0")
                    nbr = {
                      "TID": cmd.get("TID"),
                      "NBTID": nbr_tid,
                      "NBNSAP": NEDATA[nbr_tid]["nsap"],
                      "CKT2": n*jump,
                      "CKT1": n*jump-1,
                      "LID": lid,
                      "PORT": n
                    }
                    ret.append(nbr)

            elif netype == "RNE":
                sne_num = tid_list[2]
                nbr_tid = tid_list[0] + "-" + tid_list[1]
                lid = "GS" + sne_num.rjust(6, "0")
                nbr = {
                    "TID": cmd.get("TID"),
                    "NBTID": nbr_tid,
                    "NBNSAP": NEDATA[nbr_tid]["nsap"],
                    "CKT2": 1,
                    "CKT1": 2,
                    "LID": lid,
                    "PORT": 3 + int(sne_num)
                }
                ret.append(nbr)
            return (True, ret)
        except Exception as err:
            self.log_error("Link Error:{}".format(err))
            return (False, ret)



    def handle_generic_cond(self, cmd, data, cmd_config):
        responses = []

        #thogolta edini configuration values from the config file neconfig_3.json
        num_chunks = cmd_config.get("num_chunks", 5)
        records_per_chunk = cmd_config.get("records_per_chunk", 10)
        aid_format = cmd_config["aid_format"]

        #get header
        header=cmd_config["response_header"]
        #add TID to the header
        header=header.replace("{{TID}}",cmd["TID"])
        #add CTAG to the header
        header = header.replace("{{CTAG}}", cmd["CTAG"])
        # add date to the header
        header = header.replace("{{date}}", datetime.strftime(datetime.now(), \
                                    NECFG[cmd["TID"]]["format"]["date"]))

        # generting AID values for each chunk and record
        for chunk_index in range(num_chunks):
            # add time to the header
            header = header.replace("{{time}}", datetime.strftime(datetime.now(), \
                                    NECFG[cmd["TID"]]["format"]["time"]))
            chunk_response = [header]
            for record_index in range(records_per_chunk):
                aid_value = '1-{}-C{}'.format(chunk_index + 1, record_index + 1)
                aid_string = aid_format.format(aid_value)
                chunk_response.append(aid_string)
            responses.append("\n".join(chunk_response))

        formatted_response = '\n>\n'.join(responses)

        print(formatted_response)
        return (True, formatted_response)


    def handle_generic_mod1(self, cmd, data, cmd_config):
        """
        Handle multi-chunk responses for RTRV-EQPT, focusing on 'msg' fields from 'EQPT' modifier.
        """
        # Configurations from cmd_config, consider adding default values or error handling if not set
        num_chunks = cmd_config.get("num_chunks", 5)
        records_per_chunk = cmd_config.get("records_per_chunk", 10)

        # Retrieve records from 'EQPT' modifier for the given TID
        eqpt_records = NECFG[cmd["TID"]].get("MODIFIER", {}).get("EQPT", {})
        #all_msgs = [record["MSG"] for record in eqpt_records.values() if "MSG" in record ]
        all_msgs = [record["MSG"] for key, record in eqpt_records.items() if
                    "MSG" in record and record["MSG"] and key != "#AID"]

        # Debugging information
        print("Total messages fetched:", len(all_msgs))

        # Calculate total responses and initialize response list
        total_responses = len(all_msgs)
        responses = []

        # Prepare the header from the configuration
        header_template = cmd_config["response_header"]
        formatted_header = header_template.replace("{{TID}}", cmd["TID"])
        formatted_header = formatted_header.replace("{{CTAG}}", cmd["CTAG"])
        formatted_header = formatted_header.replace("{{date}}",
                                                    datetime.now().strftime(NECFG[cmd["TID"]]["format"]["date"]))
        formatted_header = formatted_header.replace("{{time}}",
                                                    datetime.now().strftime(NECFG[cmd["TID"]]["format"]["time"]))

        # Ensure only the specified number of chunks are generated
        chunks_to_generate = min(num_chunks, (total_responses + records_per_chunk - 1) // records_per_chunk)

        # Split messages into chunks
        for i in range(chunks_to_generate):
            start_index = i * records_per_chunk
            end_index = start_index + records_per_chunk
            chunk = all_msgs[start_index:end_index]

            # Debugging information
            print("Generating chunk", i + 1)
            print("Start index:", start_index, "End index:", end_index)
            print("Chunk size:", len(chunk))

            chunk_response = formatted_header + '\n'.join('   "{}"'.format(msg) for msg in chunk)
            responses.append(chunk_response)

        if not responses:
            responses.append(formatted_header + "   /*No Match Alarms Found*/\n;")

        return True, '\n>\n'.join(responses)




    def generic_card_logs(self, cmd, data, cmd_config):
        try:
            # Fetching the configurations from NECFG using cmd["TID"]
            config = NECFG[cmd["TID"]].get("MODIFIER", {})
            attributes = config.get("attributes", {})
            card_names = cmd_config.get('card_Name', [])  # List of card names
            total_slots = len(config['aids']['shelfSlotCards']['shelfSlot'])
            slots_to_fill = min(int(cmd_config.get('no_of_slots', 2)), total_slots)

            # Prepare the header using the current datetime
            header_template = cmd_config["response_header"]
            formatted_header = header_template.replace("{{TID}}", cmd["TID"])
            formatted_header = formatted_header.replace("{{CTAG}}", cmd["CTAG"])
            formatted_header = formatted_header.replace("{{date}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["date"]))
            formatted_header = formatted_header.replace("{{time}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["time"]))

            logs = [formatted_header]  # Start with the header

            def random_value(pattern):
                from string import digits, ascii_uppercase
                # Generates random values based on the provided pattern
                chars = digits + ascii_uppercase
                try:
                    return ''.join(random.choice(chars) for _ in range(int(pattern.split('{')[1].split('}')[0])))
                except IndexError:
                    return ''  # Return empty string if pattern is not as expected

            def random_vendid():
                """Generates a vendor ID in the format 'FC[0-9]{6}-[0-9]{2}'."""
                return "FC" + "".join(str(random.randint(0, 9)) for _ in range(6)) + "-" + "".join(
                    str(random.randint(0, 9)) for _ in range(2))

            def generate_overtemp():
                """Generates a random over temperature value between 0 and 150."""
                return str(random.randint(0, 150))

            def generate_card_current_feed():
                """Generates a random current feed value."""
                current_feed = random.uniform(0.1, 70.0)
                return "{:.1f}A".format(current_feed)

            def generate_current_draw(pattern):
                # Assuming pattern 'xx.xA' means a float with one decimal place from 0.1 to 15.0
                if 'xx.xA' in pattern:
                    return "{:.1f}A".format(random.uniform(0.1, 15.0))
                return pattern

            def generate_serial_number():
                from string import digits, ascii_uppercase
                """Generates a serial number consisting of 5 characters, each can be an uppercase letter or digit."""
                characters = string.ascii_uppercase + string.digits  # Combines uppercase letters and digits
                serial_number = ''.join(random.choice(characters) for _ in range(5))
                return serial_number

            def fetch_attribute_value(attribute_name):
                # Fetch and return the value based on the attribute logic
                if attribute_name == "OVERTEMP":
                    return str(random.randint(0, 150))  # Example: Random over temperature
                elif attribute_name in ["FREQMIN", "FREQMAX"]:
                    # Assuming FREQMIN and FREQMAX are handled similarly
                    return "{:.5f}".format(random.uniform(191.5, 196.5))  # Frequency values
                elif attribute_name == "FREQGRID":
                    return random.choice(["6.25", "50.0", "100.0"])  # Frequency grid values
                elif attribute_name in ["LMBDMIN", "LMBDMAX"]:
                    return "{:.2f}".format(random.uniform(1520, 1620))  # Wavelength values
                elif attribute_name == "MAID":
                    return random.choice(["16", "48"])  # Example: MAID values
                elif attribute_name == "MODE":
                    return random.choice(["SWFO", "SAS"])  # Example: MODE values
                elif attribute_name == "CARDCURRFEED":
                    return "{:.1f}A".format(random.uniform(0.1, 70.0))  # Current feed
                # Add more attributes as needed
                return "Unknown"

            # Log the main shelf card details
            if config['aids']['shelfCards']:
                shelf_card = config['aids']['shelfCards'][0]
                #vend_id = random_value(attributes['vendIdPattern'])
                vend_id = random_vendid()
                #dom = datetime.now().strftime(attributes['domFormat'])
                dom = datetime.now().strftime("%y.%m")
                clei = random_value(attributes['cleiPattern'])
                #serial_no = random_value(attributes['serialNoPattern'])
                serial_no =generate_serial_number()
                usi = random_value(attributes['usiPattern'])
                #usi=random_usi()
                voltage = random.choice(attributes['voltageRange'])
                current_draw = generate_current_draw(attributes['currentDrawFormat'])
                current_draw1 = generate_current_draw(attributes['currentDrawFeed1Pattern'])
                current_draw2 = generate_current_draw(attributes['currentDrawFeed2Pattern'])
                #current_draw1 = random_value(attributes['currentDrawFeed1Pattern'])
                #current_draw2 = random_value(attributes['currentDrawFeed2Pattern'])
                fuse_feed1 = random.choice(attributes['fuseFeedRatings'])
                fuse_feed2 = random.choice(attributes['fuseFeedRatings'])

                shelf_card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},FUSEFEED1={fuse_feed1},FUSEFEED2={fuse_feed2},CURRENTDRAWNFEED={current_draw},CURRENTDRAWNFEED1={current_draw1},CURRENTDRAWNFEED2={current_draw2}:IS-NR,ACT"'.format(
                    aid=shelf_card['aid'], card_name=shelf_card['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                    serial_no=serial_no, usi=usi, voltage=voltage, current_draw=current_draw, current_draw1=current_draw1,
                    current_draw2=current_draw2,
                    fuse_feed1=fuse_feed1, fuse_feed2=fuse_feed2)
                logs.append(shelf_card_log)

            card_attributes = {
                "IFP5-CMD1": ["CARDCURRFEED"],
                "IFP5-EGS1": ["MAID", "AVAILBW"],
                "IFP5-CXF4": ["MODE"],
                "IFP5-TCA2": ["OVERTEMP", "FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-STA2": ["FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-S9B1": [],
                "IFP5-CMS1": ["MODE"]
            }

            # Process slots and generate logs for each card and port
            slot_index = 1
            for card_name in card_names:
                if card_name == "EMPTY":
                    # Log a message indicating that this slot is intentionally left empty
                    empty_log = '"1-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                        slot_index)
                    logs.append(empty_log)
                    slot_index += 1
                    continue  # Skip further processing for this loop iteration

                if slot_index > slots_to_fill:
                    break
                card_info = next((card for card in config['aids']['cards'] if card['cardName'] == card_name), None)
                if not card_info:
                    continue

                aid = "1-{}".format(slot_index)
                #aid = "1-{}".format(card_names.index(card_name) + 1)
                #vend_id = random_value(attributes['vendIdPattern'])
                #dom = datetime.now().strftime(attributes['domFormat'])
                vend_id= random_vendid()
                dom = datetime.now().strftime("%y.%m")
                clei = random_value(attributes['cleiPattern'])
                #serial_no = random_value(attributes['serialNoPattern'])
                serial_no = generate_serial_number()
                usi = random_value(attributes['usiPattern'])
                voltage = random.choice(attributes['voltageRange'])
                current_draw = generate_current_draw(attributes['currentDrawFormat'])
                #current_draw = random_value(attributes['currentDrawFormat'])
                fuse_feed = random.choice(attributes['fuseFeedRatings'])
                overtemp = generate_overtemp()
                maid=random.choice(attributes['MAID'])

                extra_fields = ""
                for attr in card_attributes.get(card_name, []):
                    value = fetch_attribute_value(attr)
                    extra_fields += ", {}={}".format(attr, value)

                card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},CURRENTDRAW={current_draw},FUSEFEED={fuse_feed}{extra}:IS-NR,ACT"'.format(
                    aid=aid, card_name=card_info['cardName'], vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                    usi=usi, voltage=voltage, current_draw=current_draw, fuse_feed=fuse_feed, extra=extra_fields)
                logs.append(card_log)

                # Adjust the function where it processes the ports
                for port_index in range(1, card_info['ports'] + 1):
                    port_aid = "{}-{}".format(aid, port_index)
                    port_type = card_info['portTypes'][(port_index - 1) % len(card_info['portTypes'])] if card_info[
                        'portTypes'] else ''

                    # Adjust the response based on card type and port index
                    if card_name == "IFP5-CMD1":
                        if 1 <= port_index <= 4:
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)
                        elif 5 <= port_index <= 8:
                            status = "OOS-AU,UEQ&ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, status=status)

                    elif card_name == "IFP5-TGD1":
                        if port_index == 1:
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}::ACTTYPE=OC48IR1&OCH27IR1,TYPEINFO01=OC48IR1&OC12IR1&OC3IR1&1GELX10&100LX10&OCH27IR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no, usi=usi,
                                status=status)
                        else:
                            status = "OOS-AUMA,UAS&UEQ"
                            port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, status=status)

                    elif card_name == "IFP5-CXF4":
                        if port_index == 1:
                            status = "OOS-MA,UAS"
                            port_log = '"{port_aid}::ACTTYPE=OC48SR1&OCH27SR1,TYPEINFO01=OC48SR1&OC12SR1&OC3SR1&1GELX&OCH27SR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no, usi=usi,
                                status=status)
                        elif 2 <= port_index <= 13:
                            status = "OOS-AUMA,UAS&UEQ"
                            port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, status=status)

                    elif card_name == "IFP5-TCA2":
                        if port_index == 1:
                            status = "OOS-MA,UAS"
                            port_log = '"{port_aid}::ACTTYPE=OCH430LR4&40GELR4,TYPEINFO01=40GELR4&OCH430LR4,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no, usi=usi,
                                status=status)

                    elif card_name == "IFP5-S9B1":
                        if port_index == 1:
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)
                        elif port_index == 2:
                            status = "OOS-AU,UEQ&ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, status=status)

                    elif card_name == "IFP5-EGS1":
                        status = "OOS-AU,UEQ&ACT"
                        port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                            port_aid=port_aid, port_type=port_type, status=status)

                    elif card_name == "IFP5-CMS1":
                        if 1 <= port_index <= 3:
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=850:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)
                        elif port_index in [4, 6, 8, 9, 10] + list(range(12, 21)):
                            status = "OOS-AU,UEQ&ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, status=status)
                        elif port_index == 11:
                            status = "OOS-AU,MEA&ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)

                    elif card_name == "IFP5-CTC1":
                        if 1 <= port_index <= 4:
                            status = "OOS-MA,UAS"
                            port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                port_aid=port_aid, status=status)

                    elif card_name == "IFP5-EXX1":
                        if port_index == 1:
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)
                        elif port_index == 2:
                            status = "OOS-AUMA,UAS&UEQ"
                            port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                port_aid=port_aid, status=status)

                    else:  # Default case for all other cards and ports
                        status = "IS-NR,ACT"
                        port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                            port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                            serial_no=serial_no, usi=usi, status=status)

                    logs.append(port_log)

                slot_index += 1  # Increment to fill the next slot for the next card

            # Adding empty slots
            while slot_index <= total_slots:
                empty_log = '"1-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                    slot_index)
                logs.append(empty_log)
                slot_index += 1

        except KeyError as e:
            return False, "Configuration error: missing key %s" % e

        # Adding special types after all slots
        for special_type in config['aids']['specialTypes']:
            aid = special_type['aid']
            card_name = special_type['cardName']
            #vend_id = random_value(attributes['vendIdPattern'])
            #dom = datetime.now().strftime(attributes['domFormat'])
            vend_id= random_vendid()
            dom = datetime.now().strftime("%y.%m")
            clei = random_value(attributes['cleiPattern'])
            #serial_no = random_value(attributes['serialNoPattern'])
            serial_no = generate_serial_number()
            usi = random_value(attributes['usiPattern'])
            #overtemp = attributes['OVERTEMP']
            overtemp= generate_overtemp()
            #card_curr_feed = attributes['card_current_feed']
            card_curr_feed=generate_card_current_feed()
            special_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},OVERTEMP={overtemp},CARDCURRFEED={card_curr_feed}:IS-NR,ACT"'.format(
                aid=aid, card_name=card_name, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                usi=usi, overtemp=overtemp, card_curr_feed=card_curr_feed)
            logs.append(special_log)

        return True, "\n".join(logs)








    def generic_card_logs1(self, cmd, data, cmd_config):
        try:
            # Fetching the configurations from NECFG using cmd["TID"]
            config = NECFG[cmd["TID"]].get("MODIFIER", {})
            attributes = config.get("attributes", {})
            card_names = cmd_config.get('card_Name', [])
            #total_slots = len(config['aids']['shelfSlotCards']['shelfSlot'])
            #slots_to_fill = min(int(cmd_config.get('no_of_slots', 2)), total_slots)
            total_shelves = int(cmd_config.get('no_of_shelf', 1))

            # Prepare the header using the current datetime
            header_template = cmd_config["response_header"]
            formatted_header = header_template.replace("{{TID}}", cmd["TID"])
            formatted_header = formatted_header.replace("{{CTAG}}", cmd["CTAG"])
            formatted_header = formatted_header.replace("{{date}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["date"]))
            formatted_header = formatted_header.replace("{{time}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["time"]))

            logs = [formatted_header]  # Start with the header

            def random_value(pattern):
                from string import digits, ascii_uppercase
                # Generates random values based on the provided pattern
                chars = digits + ascii_uppercase
                try:
                    return ''.join(random.choice(chars) for _ in range(int(pattern.split('{')[1].split('}')[0])))
                except IndexError:
                    return ''  # Return empty string if pattern is not as expected

            def random_vendid():
                """Generates a vendor ID in the format 'FC[0-9]{6}-[0-9]{2}'."""
                return "FC" + "".join(str(random.randint(0, 9)) for _ in range(6)) + "-" + "".join(
                    str(random.randint(0, 9)) for _ in range(2))

            def generate_overtemp():
                """Generates a random over temperature value between 0 and 150."""
                return str(random.randint(0, 150))

            def generate_card_current_feed():
                """Generates a random current feed value."""
                current_feed = random.uniform(0.1, 70.0)
                return "{:.1f}A".format(current_feed)

            def generate_current_draw(pattern):
                # Assuming pattern 'xx.xA' means a float with one decimal place from 0.1 to 15.0
                if 'xx.xA' in pattern:
                    return "{:.1f}A".format(random.uniform(0.1, 15.0))
                return pattern

            def generate_serial_number():
                from string import digits, ascii_uppercase
                """Generates a serial number consisting of 5 characters, each can be an uppercase letter or digit."""
                characters = string.ascii_uppercase + string.digits  # Combines uppercase letters and digits
                serial_number = ''.join(random.choice(characters) for _ in range(5))
                return serial_number

            def fetch_attribute_value(attribute_name):
                # Fetch and return the value based on the attribute logic
                if attribute_name == "OVERTEMP":
                    return str(random.randint(0, 150))  # Example: Random over temperature
                elif attribute_name in ["FREQMIN", "FREQMAX"]:
                    # Assuming FREQMIN and FREQMAX are handled similarly
                    return "{:.5f}".format(random.uniform(191.5, 196.5))  # Frequency values
                elif attribute_name == "FREQGRID":
                    return random.choice(["6.25", "50.0", "100.0"])  # Frequency grid values
                elif attribute_name in ["LMBDMIN", "LMBDMAX"]:
                    return "{:.2f}".format(random.uniform(1520, 1620))  # Wavelength values
                elif attribute_name == "MAID":
                    return random.choice(["16", "48"])  # Example: MAID values
                elif attribute_name == "MODE":
                    return random.choice(["SWFO", "SAS"])  # Example: MODE values
                elif attribute_name == "CARDCURRFEED":
                    return "{:.1f}A".format(random.uniform(0.1, 70.0))  # Current feed
                # Add more attributes as needed
                return "Unknown"



            card_attributes = {
                "IFP5-CMD1": ["CARDCURRFEED"],
                "IFP5-EGS1": ["MAID", "AVAILBW","CARDCURRFEED"],
                "IFP5-CXF4": ["MODE"],
                "IFP5-TCA2": ["OVERTEMP", "FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-STA2": ["FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-S9B1": [],
                "IFP5-CMS1": ["MODE"]
            }
            for shelf_number in range(1, total_shelves + 1):
                # Log the main shelf card details for the current shelf
                shelf_card_entries = config['aids']['shelfCards'].get('shelf{}'.format(shelf_number), [])
                for shelf_card in shelf_card_entries:
                    vend_id = self.random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = self.random_value(attributes['cleiPattern'])
                    serial_no = self.generate_serial_number()
                    usi = self.random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = self.generate_current_draw(attributes['currentDrawFormat'])
                    current_draw1 = self.generate_current_draw(attributes['currentDrawFeed1Pattern'])
                    current_draw2 = self.generate_current_draw(attributes['currentDrawFeed2Pattern'])
                    fuse_feed1 = random.choice(attributes['fuseFeedRatings'])
                    fuse_feed2 = random.choice(attributes['fuseFeedRatings'])

                    shelf_card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},FUSEFEED1={fuse_feed1},FUSEFEED2={fuse_feed2},CURRENTDRAWNFEED={current_draw},CURRENTDRAWNFEED1={current_draw1},CURRENTDRAWNFEED2={current_draw2}:IS-NR,ACT"'.format(
                        aid=shelf_card['aid'], card_name=shelf_card['cardName'], vend_id=vend_id, dom=dom,
                        clei=clei, serial_no=serial_no, usi=usi, voltage=voltage, current_draw=current_draw,
                        current_draw1=current_draw1, current_draw2=current_draw2, fuse_feed1=fuse_feed1,
                        fuse_feed2=fuse_feed2)
                    logs.append(shelf_card_log)


                card_names = cmd_config.get('card_Name_shelf{}'.format(shelf_number), [])
                slots_to_fill = len(config['aids']['shelfSlotCards']['shelf{}'.format(shelf_number)])
                # Process slots and generate logs for each card and port
                slot_index = 1
                for card_name in card_names:
                    if card_name == "EMPTY":
                        # empty card
                        empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                            shelf_number,slot_index)
                        logs.append(empty_log)
                        slot_index += 1
                        continue

                    if slot_index > slots_to_fill:
                        break
                    card_info = next((card for card in config['aids']['cards'] if card['cardName'] == card_name), None)
                    if not card_info:
                        continue

                    #aid = "1-{}".format(slot_index)
                    aid = "{}-{}".format(shelf_number, slot_index)
                    # vend_id = random_value(attributes['vendIdPattern'])
                    # dom = datetime.now().strftime(attributes['domFormat'])
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    # serial_no = random_value(attributes['serialNoPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = generate_current_draw(attributes['currentDrawFormat'])
                    # current_draw = random_value(attributes['currentDrawFormat'])
                    fuse_feed = random.choice(attributes['fuseFeedRatings'])
                    overtemp = generate_overtemp()
                    maid = random.choice(attributes['MAID'])

                    extra_fields = ""
                    for attr in card_attributes.get(card_name, []):
                        value = fetch_attribute_value(attr)
                        extra_fields += ", {}={}".format(attr, value)

                    card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},CURRENTDRAW={current_draw},FUSEFEED={fuse_feed}{extra}:IS-NR,ACT"'.format(
                        aid=aid, card_name=card_info['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                        serial_no=serial_no,
                        usi=usi, voltage=voltage, current_draw=current_draw, fuse_feed=fuse_feed, extra=extra_fields)
                    logs.append(card_log)

                    # Adjust the function where it processes the ports
                    for port_index in range(1, card_info['ports'] + 1):
                        port_aid = "{}-{}".format(aid, port_index)
                        port_type = card_info['portTypes'][(port_index - 1) % len(card_info['portTypes'])] if card_info[
                            'portTypes'] else ''

                        # Adjust the response based on card type and port index
                        if card_name == "IFP5-CMD1":
                            if 1 <= port_index <= 4:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif 5 <= port_index <= 8:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-TGD1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}::ACTTYPE=OC48IR1&OCH27IR1,TYPEINFO01=OC48IR1&OC12IR1&OC3IR1&1GELX10&100LX10&OCH27IR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)
                            else:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-CXF4":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OC48SR1&OCH27SR1,TYPEINFO01=OC48SR1&OC12SR1&OC3SR1&1GELX&OCH27SR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)
                            elif 2 <= port_index <= 13:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-TCA2":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OCH430LR4&40GELR4,TYPEINFO01=40GELR4&OCH430LR4,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)

                        elif card_name == "IFP5-S9B1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-EGS1":
                            status = "OOS-AU,UEQ&ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-CMS1":
                            if 1 <= port_index <= 3:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=850:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                            elif port_index == 5:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                            elif port_index == 7:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1550:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                            elif port_index in [4, 6, 8, 9, 10] + list(range(12, 21)):
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)
                            elif port_index == 11:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                        elif card_name == "IFP5-CTC1":
                            if 1 <= port_index <= 4:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-EXX1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        else:  # Default case for all other cards and ports
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)

                        logs.append(port_log)
                    slot_index += 1  # Increment to fill the next slot for the next card

                # Adding empty slots
                while slot_index <= slots_to_fill:
                    empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                        shelf_number, slot_index)
                    logs.append(empty_log)
                    slot_index += 1

            for special_type in config['aids']['specialTypes'].get('shelf{}'.format(shelf_number), []):
                aid = special_type['aid']
                card_name = special_type['cardName']
                # vend_id = random_value(attributes['vendIdPattern'])
                # dom = datetime.now().strftime(attributes['domFormat'])
                vend_id = random_vendid()
                dom = datetime.now().strftime("%y.%m")
                clei = random_value(attributes['cleiPattern'])
                # serial_no = random_value(attributes['serialNoPattern'])
                serial_no = generate_serial_number()
                usi = random_value(attributes['usiPattern'])
                # overtemp = attributes['OVERTEMP']
                overtemp = generate_overtemp()
                # card_curr_feed = attributes['card_current_feed']
                card_curr_feed = generate_card_current_feed()
                special_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},OVERTEMP={overtemp},CARDCURRFEED={card_curr_feed}:IS-NR,ACT"'.format(
                    aid=aid, card_name=card_name, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                    usi=usi, overtemp=overtemp, card_curr_feed=card_curr_feed)
                logs.append(special_log)
            full_log = "\n".join("   " + log for log in logs)
            chunks = []
            chunk_size = 4000

            # Splitting madta edini to chunks
            while len(full_log) > chunk_size:
                last_newline = full_log.rfind('\n', 0, chunk_size)
                if last_newline == -1:
                    last_newline = chunk_size
                chunks.append(full_log[:last_newline])
                full_log = formatted_header + "\n" + full_log[
                                                     last_newline + 1:]
            if full_log:
                chunks.append(full_log)

            return True, "\n\n>\n".join(chunks)

        except KeyError as e:
            return False, "Configuration error: missing key %s" % e





    def generic_card_logs2(self, cmd, data, cmd_config):
        try:
            config = NECFG[cmd["TID"]].get("MODIFIER", {})
            attributes = config.get("attributes", {})
            total_shelves = int(cmd_config.get('no_of_shelf', 1))

            # Prepare the header using the current datetime
            header_template = cmd_config["response_header"]
            formatted_header = header_template.replace("{{TID}}", cmd["TID"])
            formatted_header = formatted_header.replace("{{CTAG}}", cmd["CTAG"])
            formatted_header = formatted_header.replace("{{date}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["date"]))
            formatted_header = formatted_header.replace("{{time}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["time"]))

            logs = [formatted_header]  # Start with the header


            card_attributes = {
                "IFP5-CMD1": ["CARDCURRFEED"],
                "IFP5-EGS1": ["MAID", "AVAILBW", "CARDCURRFEED"],
                "IFP5-CXF4": ["MODE"],
                "IFP5-TCA2": ["OVERTEMP", "FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-STA2": ["FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-S9B1": [],
                "IFP5-CMS1": ["MODE"]
            }

            def random_vendid():
                """Generates a vendor ID in the format 'FC[0-9]{6}-[0-9]{2}'."""
                return "FC" + "".join(str(random.randint(0, 9)) for _ in range(6)) + "-" + "".join(
                    str(random.randint(0, 9)) for _ in range(2))

            def generate_serial_number():
                """Generates a serial number consisting of 5 characters, each can be an uppercase letter or digit."""
                characters = string.ascii_uppercase + string.digits
                serial_number = ''.join(random.choice(characters) for _ in range(5))
                return serial_number

            def random_value(pattern):
                chars = string.digits + string.ascii_uppercase
                try:
                    return ''.join(random.choice(chars) for _ in range(int(pattern.split('{')[1].split('}')[0])))
                except IndexError:
                    return ''  # Return empty string if pattern is not as expected

            def generate_current_draw(pattern):
                # Assuming pattern 'xx.xA' means a float with one decimal place from 0.1 to 15.0
                if 'xx.xA' in pattern:
                    return "{:.1f}A".format(random.uniform(0.1, 15.0))
                return pattern

            def generate_overtemp():
                """Generates a random over temperature value between 0 and 150."""
                return str(random.randint(0, 150))

            def generate_card_current_feed():
                """Generates a random current feed value."""
                current_feed = random.uniform(0.1, 70.0)
                return "{:.1f}A".format(current_feed)

            def fetch_attribute_value(attribute_name):
                # Fetch and return the value based on the attribute logic
                if attribute_name == "OVERTEMP":
                    return str(random.randint(0, 150))  # Example: Random over temperature
                elif attribute_name in ["FREQMIN", "FREQMAX"]:
                    # Assuming FREQMIN and FREQMAX are handled similarly
                    return "{:.5f}".format(random.uniform(191.5, 196.5))  # Frequency values
                elif attribute_name == "FREQGRID":
                    return random.choice(["6.25", "50.0", "100.0"])  # Frequency grid values
                elif attribute_name in ["LMBDMIN", "LMBDMAX"]:
                    return "{:.2f}".format(random.uniform(1520, 1620))  # Wavelength values
                elif attribute_name == "MAID":
                    return random.choice(["16", "48"])  # Example: MAID values
                elif attribute_name == "MODE":
                    return random.choice(["SWFO", "SAS"])  # Example: MODE values
                elif attribute_name == "CARDCURRFEED":
                    return "{:.1f}A".format(random.uniform(0.1, 70.0))  # Current feed
                # Add more attributes as needed
                return "Unknown"

            for shelf_number in range(1, total_shelves + 1):
                # Log the main shelf card details for the current shelf
                shelf_card_entries = config['aids']['shelfCards'].get('shelf{}'.format(shelf_number), [])
                for shelf_card in shelf_card_entries:
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = generate_current_draw(attributes['currentDrawFormat'])
                    current_draw1 = generate_current_draw(attributes['currentDrawFeed1Pattern'])
                    current_draw2 = generate_current_draw(attributes['currentDrawFeed2Pattern'])
                    fuse_feed1 = random.choice(attributes['fuseFeedRatings'])
                    fuse_feed2 = random.choice(attributes['fuseFeedRatings'])

                    shelf_card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},FUSEFEED1={fuse_feed1},FUSEFEED2={fuse_feed2},CURRENTDRAWNFEED={current_draw},CURRENTDRAWNFEED1={current_draw1},CURRENTDRAWNFEED2={current_draw2}:IS-NR,ACT"'.format(
                        aid=shelf_card['aid'], card_name=shelf_card['cardName'], vend_id=vend_id, dom=dom,
                        clei=clei, serial_no=serial_no, usi=usi, voltage=voltage, current_draw=current_draw,
                        current_draw1=current_draw1, current_draw2=current_draw2, fuse_feed1=fuse_feed1,
                        fuse_feed2=fuse_feed2)
                    logs.append(shelf_card_log)

                card_names = cmd_config.get('card_Name_shelf{}'.format(shelf_number), [])
                slots_to_fill = len(config['aids']['shelfSlotCards']['shelf{}'.format(shelf_number)])

                slot_index = 1
                for card_name in card_names:
                    if card_name == "EMPTY":
                        empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                            shelf_number, slot_index)
                        logs.append(empty_log)
                        slot_index += 1
                        continue

                    if slot_index > slots_to_fill:
                        break

                    card_info = next((card for card in config['aids']['cards'] if card['cardName'] == card_name), None)
                    if not card_info:
                        continue

                    aid = "{}-{}".format(shelf_number, slot_index)
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = generate_current_draw(attributes['currentDrawFormat'])
                    fuse_feed = random.choice(attributes['fuseFeedRatings'])
                    extra_fields = ""
                    for attr in card_attributes.get(card_name, []):
                        value = fetch_attribute_value(attr)
                        extra_fields += ", {}={}".format(attr, value)

                    card_log = '"{}:{}:ACTTYPE={},VENDID={},DOM={},CLEI={},SERIALNO={},USI={},VOLTAGE={},CURRENTDRAW={},FUSEFEED={}{}:IS-NR,ACT"'.format(
                        aid, card_name, card_name, vend_id, dom, clei, serial_no, usi, voltage, current_draw, fuse_feed,
                        extra_fields)
                    logs.append(card_log)

                    # Process ports
                    for port_index in range(1, card_info['ports'] + 1):
                        port_aid = "{}-{}".format(aid, port_index)
                        port_type = card_info['portTypes'][(port_index - 1) % len(card_info['portTypes'])] if card_info[
                            'portTypes'] else ''

                        if card_name == "IFP5-CMD1":
                            if 1 <= port_index <= 4:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif 5 <= port_index <= 8:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-TGD1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}::ACTTYPE=OC48IR1&OCH27IR1,TYPEINFO01=OC48IR1&OC12IR1&OC3IR1&1GELX10&100LX10&OCH27IR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi, status=status)
                            else:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-CXF4":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OC48SR1&OCH27SR1,TYPEINFO01=OC48SR1&OC12SR1&OC3SR1&1GELX&OCH27SR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi, status=status)
                            elif 2 <= port_index <= 13:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-TCA2":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OCH430LR4&40GELR4,TYPEINFO01=40GELR4&OCH430LR4,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi, status=status)

                        elif card_name == "IFP5-S9B1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-EGS1":
                            status = "OOS-AU,UEQ&ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-CMS1":
                            if 1 <= port_index <= 3:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=850:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                            elif port_index == 5:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                            elif port_index == 7:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1550:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                            elif port_index in [4, 6, 8, 9, 10] + list(range(12, 21)):
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)
                            elif port_index == 11:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                        elif card_name == "IFP5-CTC1":
                            if 1 <= port_index <= 4:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-EXX1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        else:  # Default case for all other cards and ports
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)

                        logs.append(port_log)

                    slot_index += 1  # Increment to fill the next slot for the next card

                # Adding empty slots
                while slot_index <= slots_to_fill:
                    empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                        shelf_number, slot_index)
                    logs.append(empty_log)
                    slot_index += 1

                # Adding special types for the current shelf
                for special_type in config['aids']['specialTypes'].get('shelf{}'.format(shelf_number), []):
                    aid = special_type['aid']
                    card_name = special_type['cardName']
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    overtemp = generate_overtemp()
                    card_curr_feed = generate_card_current_feed()
                    special_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},OVERTEMP={overtemp},CARDCURRFEED={card_curr_feed}:IS-NR,ACT"'.format(
                        aid=aid, card_name=card_name, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                        usi=usi, overtemp=overtemp, card_curr_feed=card_curr_feed)
                    logs.append(special_log)

            full_log = "\n".join("   " + log for log in logs)
            chunks = []
            chunk_size = 4000

            # Splitting madta edini to chunks
            while len(full_log) > chunk_size:
                last_newline = full_log.rfind('\n', 0, chunk_size)
                if last_newline == -1:
                    last_newline = chunk_size
                chunks.append(full_log[:last_newline])
                full_log = formatted_header + "\n" + full_log[last_newline + 1:]
            if full_log:
                chunks.append(full_log)

            return True, "\n\n>\n".join(chunks)

        except KeyError as e:
            return False, "Configuration error: missing key %s" % e


    def generic_card_logs3(self, cmd, data, cmd_config):
        try:
            config = NECFG[cmd["TID"]].get("MODIFIER", {})
            attributes = config.get("attributes", {})
            total_shelves = int(cmd_config.get('no_of_shelf', 1))

            # Prepare the header using the current datetime
            header_template = cmd_config["response_header"]
            formatted_header = header_template.replace("{{TID}}", cmd["TID"])
            formatted_header = formatted_header.replace("{{CTAG}}", cmd["CTAG"])
            formatted_header = formatted_header.replace("{{date}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["date"]))
            formatted_header = formatted_header.replace("{{time}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["time"]))

            logs = [formatted_header]  # Start with the header

            card_attributes = {
                "IFP5-CMD1": ["CARDCURRFEED"],
                "IFP5-EGS1": ["MAID", "AVAILBW", "CARDCURRFEED"],
                "IFP5-CXF4": ["MODE"],
                "IFP5-TCA2": ["OVERTEMP", "FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-STA2": ["FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-S9B1": [],
                "IFP5-CMS1": ["MODE"],
                "IFP5-CTC1": ["MODE","OVERTEMP"],
                "IFP5-TMD1": ["MODE","FREQMIN","FREQMAX","FREQGRID","LMBDMIN","LAMDMAX","LAMBDAGRID","CARDCURRFEED"]
            }

            def random_value(pattern):
                from string import digits, ascii_uppercase
                chars = digits + ascii_uppercase
                return ''.join(random.choice(chars) for _ in range(int(pattern.split('{')[1].split('}')[0])))

            def random_vendid():
                return "FC" + "".join(str(random.randint(0, 9)) for _ in range(6)) + "-" + "".join(
                    str(random.randint(0, 9)) for _ in range(2))

            def generate_overtemp():
                return str(random.randint(0, 150))

            def generate_card_current_feed():
                current_feed = random.uniform(0.1, 70.0)
                return "{:.1f}A".format(current_feed)

            def generate_current_draw(pattern):
                if 'xx.xA' in pattern:
                    return "{:.1f}A".format(random.uniform(0.1, 15.0))
                return pattern

            def generate_serial_number():
                from string import digits, ascii_uppercase
                characters = ascii_uppercase + digits
                serial_number = ''.join(random.choice(characters) for _ in range(5))
                return serial_number

            def fetch_attribute_value(attribute_name):
                if attribute_name == "OVERTEMP":
                    return str(random.randint(0, 150))
                elif attribute_name in ["FREQMIN", "FREQMAX"]:
                    return "{:.5f}".format(random.uniform(191.5, 196.5))
                elif attribute_name == "FREQGRID":
                    return random.choice(["6.25", "50.0", "100.0"])
                elif attribute_name in ["LMBDMIN", "LMBDMAX"]:
                    return "{:.2f}".format(random.uniform(1520, 1620))
                elif attribute_name == "MAID":
                    return random.choice(["16", "48"])
                elif attribute_name == "MODE":
                    return random.choice(["SWFO", "SAS"])
                elif attribute_name == "CARDCURRFEED":
                    return "{:.1f}A".format(random.uniform(0.1, 70.0))
                return "Unknown"

            for shelf_number in range(1, total_shelves + 1):
                shelf_card_entries = config['aids']['shelfCards'].get('shelf{}'.format(shelf_number), [])
                for shelf_card in shelf_card_entries:
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = generate_current_draw(attributes['currentDrawFormat'])
                    current_draw1 = generate_current_draw(attributes['currentDrawFeed1Pattern'])
                    current_draw2 = generate_current_draw(attributes['currentDrawFeed2Pattern'])
                    fuse_feed1 = random.choice(attributes['fuseFeedRatings'])
                    fuse_feed2 = random.choice(attributes['fuseFeedRatings'])

                    shelf_card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},FUSEFEED1={fuse_feed1},FUSEFEED2={fuse_feed2},CURRENTDRAWNFEED={current_draw},CURRENTDRAWNFEED1={current_draw1},CURRENTDRAWNFEED2={current_draw2}:IS-NR,ACT"'.format(
                        aid=shelf_card['aid'], card_name=shelf_card['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                        serial_no=serial_no, usi=usi, voltage=voltage, current_draw=current_draw,
                        current_draw1=current_draw1,
                        current_draw2=current_draw2, fuse_feed1=fuse_feed1, fuse_feed2=fuse_feed2)
                    logs.append(shelf_card_log)

                card_names = cmd_config.get('card_Name_shelf{}'.format(shelf_number), [])
                slots_to_fill = int(cmd_config.get('no_of_slots_shelf{}'.format(shelf_number), 24))
                total_slots = 24  # Ensure that each shelf always has 24 slots printed

                slot_index = 1
                for card_name in card_names:
                    if card_name == "EMPTY":
                        empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                            shelf_number, slot_index)
                        logs.append(empty_log)
                        slot_index += 1
                        continue

                    if slot_index > slots_to_fill:
                        break
                    card_info = next((card for card in config['aids']['cards'] if card['cardName'] == card_name), None)
                    if not card_info:
                        continue

                    aid = "{}-{}".format(shelf_number, slot_index)
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = generate_current_draw(attributes['currentDrawFormat'])
                    fuse_feed = random.choice(attributes['fuseFeedRatings'])
                    overtemp = generate_overtemp()
                    maid = random.choice(attributes['MAID'])

                    if card_name == "IFP5-CTC1":
                        status = "OOS-AU,UEQ&ACT"
                        card_log = '"{aid}:{card_name}:ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,MODE=SWFO,OVERTEMP=-99.9,CARDCURRFEED=3.1A:{status}"'.format(
                            aid=aid, card_name=card_info['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                            serial_no=serial_no, usi=usi, status=status)
                    else:
                        extra_fields = ""
                        for attr in card_attributes.get(card_name, []):
                            value = fetch_attribute_value(attr)
                            extra_fields += ", {}={}".format(attr, value)

                        card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},CURRENTDRAW={current_draw},FUSEFEED={fuse_feed}{extra}:IS-NR,ACT"'.format(
                            aid=aid, card_name=card_info['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                            serial_no=serial_no, usi=usi, voltage=voltage, current_draw=current_draw,
                            fuse_feed=fuse_feed, extra=extra_fields)

                    logs.append(card_log)

                    for port_index in range(1, card_info['ports'] + 1):
                        port_aid = "{}-{}".format(aid, port_index)
                        if card_name == "IFP5-CMD1" and port_index == 1:
                            port_type = "OC3IR1"
                        elif card_name == "IFP5-CMD1":
                            port_type = "OC12IR1"
                        else:
                            port_type = card_info['portTypes'][(port_index - 1) % len(card_info['portTypes'])] if card_info[
                            'portTypes'] else ''


                        if card_name == "IFP5-CMD1":
                            if 1 <= port_index <= 4:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif 5 <= port_index <= 8:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-TGD1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}::ACTTYPE=OC48IR1&OCH27IR1,TYPEINFO01=OC48IR1&OC12IR1&OC3IR1&1GELX10&100LX10&OCH27IR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)
                            else:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-CXF4":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OC48SR1&OCH27SR1,TYPEINFO01=OC48SR1&OC12SR1&OC3SR1&1GELX&OCH27SR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)
                            elif 2 <= port_index <= 14:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-TCA2":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OCH430LR4&40GELR4,TYPEINFO01=40GELR4&OCH430LR4,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)

                        elif card_name == "IFP5-S9B1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-EGS1":
                            status = "OOS-AU,UEQ&ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-CMS1":
                            if 1 <= port_index <= 3:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=850:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 5:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 7:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1550:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index in [4, 6, 8, 9, 10] + list(range(12, 21)):
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)
                            elif port_index == 11:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                        elif card_name =="IFP5-TMD1":
                            if 1<= port_index <=8:
                                status="OOS-AUMA,UAS&UEQ"
                                port_log='"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-CTC1":
                            if 1 <= port_index <= 4:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-EXX1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        else:
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)

                        logs.append(port_log)
                    slot_index += 1

                while slot_index <= total_slots:
                    empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                        shelf_number, slot_index)
                    logs.append(empty_log)
                    slot_index += 1

                for special_type in config['aids']['specialTypes'].get('shelf{}'.format(shelf_number), []):
                    aid = special_type['aid']
                    card_name = special_type['cardName']
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    overtemp = generate_overtemp()
                    card_curr_feed = generate_card_current_feed()

                    special_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},OVERTEMP={overtemp},CARDCURRFEED={card_curr_feed}:IS-NR,ACT"'.format(
                        aid=aid, card_name=card_name, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                        usi=usi, overtemp=overtemp, card_curr_feed=card_curr_feed)
                    logs.append(special_log)

            full_log = "\n".join("   " + log for log in logs)
            chunks = []
            chunk_size = 4000

            while len(full_log) > chunk_size:
                last_newline = full_log.rfind('\n', 0, chunk_size)
                if last_newline == -1:
                    last_newline = chunk_size
                chunks.append(full_log[:last_newline])
                full_log = formatted_header + "\n" + full_log[last_newline + 1:]
            if full_log:
                chunks.append(full_log)

            return True, "\n\n>\n".join(chunks)


        except KeyError as e:
            return False, "Configuration error: missing key %s" % e




    def generic_card_logs4(self, cmd, data, cmd_config):
        try:
            config = NECFG[cmd["TID"]].get("MODIFIER", {})
            attributes = config.get("attributes", {})
            total_shelves = int(cmd_config.get('no_of_shelf', 1))

            # Prepare the header using the current datetime
            header_template = cmd_config["response_header"]
            formatted_header = header_template.replace("{{TID}}", cmd["TID"])
            formatted_header = formatted_header.replace("{{CTAG}}", cmd["CTAG"])
            formatted_header = formatted_header.replace("{{date}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["date"]))
            formatted_header = formatted_header.replace("{{time}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["time"]))

            logs = [formatted_header]  # Start with the header

            card_attributes = {
                "IFP5-CMD1": ["CARDCURRFEED"],
                "IFP5-EGS1": ["MAID", "AVAILBW", "CARDCURRFEED"],
                "IFP5-CXF4": ["MODE"],
                "IFP5-TCA2": ["OVERTEMP", "FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-STA2": ["FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-S9B1": [],
                "IFP5-CMS1": ["MODE"],
                "IFPS-CTC1": ["MODE", "OVERTEMP"]
            }

            def random_value(pattern):
                from string import digits, ascii_uppercase
                chars = digits + ascii_uppercase
                return ''.join(random.choice(chars) for _ in range(int(pattern.split('{')[1].split('}')[0])))

            def random_vendid():
                return "FC" + "".join(str(random.randint(0, 9)) for _ in range(6)) + "-" + "".join(
                    str(random.randint(0, 9)) for _ in range(2))

            def generate_overtemp():
                return str(random.randint(0, 150))

            def generate_card_current_feed():
                current_feed = random.uniform(0.1, 70.0)
                return "{:.1f}A".format(current_feed)

            def generate_current_draw(pattern):
                if 'xx.xA' in pattern:
                    return "{:.1f}A".format(random.uniform(0.1, 15.0))
                return pattern

            def generate_serial_number():
                from string import digits, ascii_uppercase
                characters = ascii_uppercase + digits
                serial_number = ''.join(random.choice(characters) for _ in range(5))
                return serial_number

            def fetch_attribute_value(attribute_name):
                if attribute_name == "OVERTEMP":
                    return str(random.randint(0, 150))
                elif attribute_name in ["FREQMIN", "FREQMAX"]:
                    return "{:.5f}".format(random.uniform(191.5, 196.5))
                elif attribute_name == "FREQGRID":
                    return random.choice(["6.25", "50.0", "100.0"])
                elif attribute_name in ["LMBDMIN", "LMBDMAX"]:
                    return "{:.2f}".format(random.uniform(1520, 1620))
                elif attribute_name == "MAID":
                    return random.choice(["16", "48"])
                elif attribute_name == "MODE":
                    return random.choice(["SWFO", "SAS"])
                elif attribute_name == "CARDCURRFEED":
                    return "{:.1f}A".format(random.uniform(0.1, 70.0))
                return "Unknown"

            for shelf_number in range(1, total_shelves + 1):
                shelf_card_entries = config['aids']['shelfCards'].get('shelf{}'.format(shelf_number), [])
                for shelf_card in shelf_card_entries:
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = generate_current_draw(attributes['currentDrawFormat'])
                    current_draw1 = generate_current_draw(attributes['currentDrawFeed1Pattern'])
                    current_draw2 = generate_current_draw(attributes['currentDrawFeed2Pattern'])
                    fuse_feed1 = random.choice(attributes['fuseFeedRatings'])
                    fuse_feed2 = random.choice(attributes['fuseFeedRatings'])

                    shelf_card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},FUSEFEED1={fuse_feed1},FUSEFEED2={fuse_feed2},CURRENTDRAWNFEED={current_draw},CURRENTDRAWNFEED1={current_draw1},CURRENTDRAWNFEED2={current_draw2}:IS-NR,ACT"'.format(
                        aid=shelf_card['aid'], card_name=shelf_card['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                        serial_no=serial_no, usi=usi, voltage=voltage, current_draw=current_draw,
                        current_draw1=current_draw1, current_draw2=current_draw2, fuse_feed1=fuse_feed1,
                        fuse_feed2=fuse_feed2)
                    logs.append(shelf_card_log)

                card_names_str = cmd_config.get('card_names').get('shelf_{}'.format(shelf_number), "")
                card_names = [name if name else None for name in card_names_str.split(',')]
                slots_to_fill = int(cmd_config.get('no_of_slots', 24))
                total_slots = 24  # Ensure that each shelf always has 24 slots printed

                slot_index = 1
                for card_name in card_names:
                    if not card_name:
                        empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                            shelf_number, slot_index)
                        logs.append(empty_log)
                        slot_index += 1
                        continue

                    if slot_index > slots_to_fill:
                        break
                    card_info = next((card for card in config['aids']['cards'] if card['cardName'] == card_name), None)
                    if not card_info:
                        continue

                    aid = "{}-{}".format(shelf_number, slot_index)
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = generate_current_draw(attributes['currentDrawFormat'])
                    fuse_feed = random.choice(attributes['fuseFeedRatings'])
                    overtemp = generate_overtemp()
                    maid = random.choice(attributes['MAID'])

                    if card_name == "IFP5-CTC1":
                        status = "OOS-AU,UEQ&ACT"
                        card_log = '"{aid}:{card_name}:ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,MODE=SWFO,OVERTEMP=-99.9,CARDCURRFEED=3.1A:{status}"'.format(
                            aid=aid, card_name=card_info['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                            serial_no=serial_no, usi=usi, status=status)
                    else:
                        extra_fields = ""
                        for attr in card_attributes.get(card_name, []):
                            value = fetch_attribute_value(attr)
                            extra_fields += ", {}={}".format(attr, value)

                        card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},CURRENTDRAW={current_draw},FUSEFEED={fuse_feed}{extra}:IS-NR,ACT"'.format(
                            aid=aid, card_name=card_info['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                            serial_no=serial_no, usi=usi, voltage=voltage, current_draw=current_draw,
                            fuse_feed=fuse_feed,
                            extra=extra_fields)

                    logs.append(card_log)

                    for port_index in range(1, card_info['ports'] + 1):
                        port_aid = "{}-{}".format(aid, port_index)
                        if card_name == "IFP5-CMD1" and port_index == 1:
                            port_type = "OC3IR1"
                        elif card_name == "IFP5-CMD1":
                            port_type = "OC12IR1"
                        else:
                            port_type = card_info['portTypes'][(port_index - 1) % len(card_info['portTypes'])] if \
                            card_info[
                                'portTypes'] else ''

                        if card_name == "IFP5-CMD1":
                            if 1 <= port_index <= 4:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif 5 <= port_index <= 8:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-TGD1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}::ACTTYPE=OC48IR1&OCH27IR1,TYPEINFO01=OC48IR1&OC12IR1&OC3IR1&1GELX10&100LX10&OCH27IR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)
                            else:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-CXF4":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OC48SR1&OCH27SR1,TYPEINFO01=OC48SR1&OC12SR1&OC3SR1&1GELX&OCH27SR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)
                            elif 2 <= port_index <= 14:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-TCA2":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OCH430LR4&40GELR4,TYPEINFO01=40GELR4&OCH430LR4,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)

                        elif card_name == "IFP5-S9B1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-EGS1":
                            status = "OOS-AU,UEQ&ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-CMS1":
                            if 1 <= port_index <= 3:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=850:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 5:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 7:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1550:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index in [4, 6, 8, 9, 10] + list(range(12, 21)):
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)
                            elif port_index == 11:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                        elif card_name == "IFP5-CTC1":
                            if 1 <= port_index <= 4:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-EXX1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        else:
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)

                        logs.append(port_log)
                    slot_index += 1

                while slot_index <= total_slots:
                    empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                        shelf_number, slot_index)
                    logs.append(empty_log)
                    slot_index += 1

                for special_type in config['aids']['specialTypes'].get('shelf{}'.format(shelf_number), []):
                    aid = special_type['aid']
                    card_name = special_type['cardName']
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    overtemp = generate_overtemp()
                    card_curr_feed = generate_card_current_feed()

                    if card_name == "MPP5-MPE2" and aid.endswith("1"):
                        status = "IS-NR,ACT"
                        special_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},OVERTEMP={overtemp},CARDCURRFEED={card_curr_feed}:{status}"'.format(
                            aid=aid, card_name=card_name, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                            usi=usi, overtemp=overtemp, card_curr_feed=card_curr_feed, status=status)
                    elif card_name == "MPP5-MPE2" and aid.endswith("2"):
                        status = "OOS-AU,UEQ&STBYH"
                        special_log = '"{aid}:{card_name}:ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,OVERTEMP=-99.9,CARDCURRFEED={card_curr_feed}:{status}"'.format(
                            aid=aid, card_name=card_name, card_curr_feed=card_curr_feed, status=status)
                    else:
                        special_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},OVERTEMP={overtemp},CARDCURRFEED={card_curr_feed}:IS-NR,ACT"'.format(
                            aid=aid, card_name=card_name, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                            usi=usi, overtemp=overtemp, card_curr_feed=card_curr_feed)

                    logs.append(special_log)

            full_log = "\n".join("   " + log for log in logs)
            chunks = []
            chunk_size = 4000

            while len(full_log) > chunk_size:
                last_newline = full_log.rfind('\n', 0, chunk_size)
                if last_newline == -1:
                    last_newline = chunk_size
                chunks.append(full_log[:last_newline])
                full_log = formatted_header + "\n" + full_log[last_newline + 1:]
            if full_log:
                chunks.append(full_log)

            return True, "\n\n>\n".join(chunks)

        except KeyError as e:
            return False, "Configuration error: missing key %s" % e


    def generic_card_logs5(self, cmd, data, cmd_config):
        try:
            config = NECFG[cmd["TID"]].get("MODIFIER", {})
            attributes = config.get("attributes", {})
            total_shelves = int(cmd_config.get('no_of_shelf', 1))

            # Prepare the header using the current datetime
            header_template = cmd_config["response_header"]
            formatted_header = header_template.replace("{{TID}}", cmd["TID"])
            formatted_header = formatted_header.replace("{{CTAG}}", cmd["CTAG"])
            formatted_header = formatted_header.replace("{{date}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["date"]))
            formatted_header = formatted_header.replace("{{time}}",
                                                        datetime.now().strftime(NECFG[cmd["TID"]]["format"]["time"]))

            logs = [formatted_header]  # Start with the header

            card_attributes = {
                "IFP5-CMD1": ["CARDCURRFEED"],
                "IFP5-EGS1": ["MAID", "AVAILBW", "CARDCURRFEED"],
                "IFP5-CXF4": ["MODE"],
                "IFP5-TCA2": ["OVERTEMP", "FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-STA2": ["FREQMIN", "FREQMAX", "FREQGRID", "LMBDMIN", "LMBDMAX", "LMBDGRID"],
                "IFP5-S9B1": [],
                "IFP5-CMS1": ["MODE"],
                "IFPS-CTC1": ["MODE", "OVERTEMP"]
            }

            def random_value(pattern):
                from string import digits, ascii_uppercase
                chars = digits + ascii_uppercase
                return ''.join(random.choice(chars) for _ in range(int(pattern.split('{')[1].split('}')[0])))

            def random_vendid():
                return "FC" + "".join(str(random.randint(0, 9)) for _ in range(6)) + "-" + "".join(
                    str(random.randint(0, 9)) for _ in range(2))

            def generate_overtemp():
                return str(random.randint(0, 150))

            def generate_card_current_feed():
                current_feed = random.uniform(0.1, 70.0)
                return "{:.1f}A".format(current_feed)

            def generate_current_draw(pattern):
                if 'xx.xA' in pattern:
                    return "{:.1f}A".format(random.uniform(0.1, 15.0))
                return pattern

            def generate_serial_number():
                from string import digits, ascii_uppercase
                characters = ascii_uppercase + digits
                serial_number = ''.join(random.choice(characters) for _ in range(5))
                return serial_number

            def fetch_attribute_value(attribute_name):
                if attribute_name == "OVERTEMP":
                    return str(random.randint(0, 150))
                elif attribute_name in ["FREQMIN", "FREQMAX"]:
                    return "{:.5f}".format(random.uniform(191.5, 196.5))
                elif attribute_name == "FREQGRID":
                    return random.choice(["6.25", "50.0", "100.0"])
                elif attribute_name in ["LMBDMIN", "LMBDMAX"]:
                    return "{:.2f}".format(random.uniform(1520, 1620))
                elif attribute_name == "MAID":
                    return random.choice(["16", "48"])
                elif attribute_name == "MODE":
                    return random.choice(["SWFO", "SAS"])
                elif attribute_name == "CARDCURRFEED":
                    return "{:.1f}A".format(random.uniform(0.1, 70.0))
                return "Unknown"

            for shelf_number in range(1, total_shelves + 1):
                shelf_card_entries = config['aids']['shelfCards'].get('shelf{}'.format(shelf_number), [])
                for shelf_card in shelf_card_entries:
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = generate_current_draw(attributes['currentDrawFormat'])
                    current_draw1 = generate_current_draw(attributes['currentDrawFeed1Pattern'])
                    current_draw2 = generate_current_draw(attributes['currentDrawFeed2Pattern'])
                    fuse_feed1 = random.choice(attributes['fuseFeedRatings'])
                    fuse_feed2 = random.choice(attributes['fuseFeedRatings'])

                    shelf_card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},FUSEFEED1={fuse_feed1},FUSEFEED2={fuse_feed2},CURRENTDRAWNFEED={current_draw},CURRENTDRAWNFEED1={current_draw1},CURRENTDRAWNFEED2={current_draw2}:IS-NR,ACT"'.format(
                        aid=shelf_card['aid'], card_name=shelf_card['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                        serial_no=serial_no, usi=usi, voltage=voltage, current_draw=current_draw,
                        current_draw1=current_draw1, current_draw2=current_draw2, fuse_feed1=fuse_feed1,
                        fuse_feed2=fuse_feed2)
                    logs.append(shelf_card_log)

                card_names_str = cmd_config.get('card_names').get('shelf_{}'.format(shelf_number), "")
                card_names = [name if name else None for name in card_names_str.split(',')]
                slots_to_fill = int(cmd_config.get('no_of_slots', 24))
                total_slots = 24  # Ensure that each shelf always has 24 slots printed

                slot_index = 1
                for card_name in card_names:
                    if not card_name:
                        empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                            shelf_number, slot_index)
                        logs.append(empty_log)
                        slot_index += 1
                        continue

                    if slot_index > slots_to_fill:
                        break
                    card_info = next((card for card in config['aids']['cards'] if card['cardName'] == card_name), None)
                    if not card_info:
                        continue

                    aid = "{}-{}".format(shelf_number, slot_index)
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    voltage = random.choice(attributes['voltageRange'])
                    current_draw = generate_current_draw(attributes['currentDrawFormat'])
                    fuse_feed = random.choice(attributes['fuseFeedRatings'])
                    overtemp = generate_overtemp()
                    maid = random.choice(attributes['MAID'])

                    if card_name == "IFP5-CTC1":
                        status = "OOS-AU,UEQ&ACT"
                        card_log = '"{aid}:{card_name}:ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,MODE=SWFO,OVERTEMP=-99.9,CARDCURRFEED=3.1A:{status}"'.format(
                            aid=aid, card_name=card_info['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                            serial_no=serial_no, usi=usi, status=status)
                    else:
                        extra_fields = ""
                        for attr in card_attributes.get(card_name, []):
                            value = fetch_attribute_value(attr)
                            extra_fields += ", {}={}".format(attr, value)

                        card_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},VOLTAGE={voltage},CURRENTDRAW={current_draw},FUSEFEED={fuse_feed}{extra}:IS-NR,ACT"'.format(
                            aid=aid, card_name=card_info['cardName'], vend_id=vend_id, dom=dom, clei=clei,
                            serial_no=serial_no, usi=usi, voltage=voltage, current_draw=current_draw,
                            fuse_feed=fuse_feed,
                            extra=extra_fields)

                    logs.append(card_log)

                    for port_index in range(1, card_info['ports'] + 1):
                        port_aid = "{}-{}".format(aid, port_index)
                        if card_name == "IFP5-CMD1" and port_index == 1:
                            port_type = "OC3IR1"
                        elif card_name == "IFP5-CMD1":
                            port_type = "OC12IR1"
                        else:
                            port_type = card_info['portTypes'][(port_index - 1) % len(card_info['portTypes'])] if \
                                card_info[
                                    'portTypes'] else ''

                        if card_name == "IFP5-CMD1":
                            if 1 <= port_index <= 4:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif 5 <= port_index <= 8:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-TGD1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}::ACTTYPE=OC48IR1&OCH27IR1,TYPEINFO01=OC48IR1&OC12IR1&OC3IR1&1GELX10&100LX10&OCH27IR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)
                            else:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-CXF4":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OC48SR1&OCH27SR1,TYPEINFO01=OC48SR1&OC12SR1&OC3SR1&1GELX&OCH27SR1,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)
                            elif 2 <= port_index <= 14:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-TCA2":
                            if port_index == 1:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=OCH430LR4&40GELR4,TYPEINFO01=40GELR4&OCH430LR4,COMPLTYPE=,VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=,LAMBDAINFO=UNKNOWN:{status}"'.format(
                                    port_aid=port_aid, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                                    usi=usi,
                                    status=status)

                        elif card_name == "IFP5-S9B1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-EGS1":
                            status = "OOS-AU,UEQ&ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, status=status)

                        elif card_name == "IFP5-CMS1":
                            if 1 <= port_index <= 3:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=850:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 5:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 7:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1550:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index in [4, 6, 8, 9, 10] + list(range(12, 21)):
                                status = "OOS-AU,UEQ&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=UNSPEC,LAMBDAINFO=:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, status=status)
                            elif port_index == 11:
                                status = "OOS-AU,MEA&ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE=,TYPEINFO01=,COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)

                        elif card_name == "IFP5-CTC1":
                            if 1 <= port_index <= 4:
                                status = "OOS-MA,UAS"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        elif card_name == "IFP5-EXX1":
                            if port_index == 1:
                                status = "IS-NR,ACT"
                                port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                    port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                    serial_no=serial_no, usi=usi, status=status)
                            elif port_index == 2:
                                status = "OOS-AUMA,UAS&UEQ"
                                port_log = '"{port_aid}::ACTTYPE=,TYPEINFO01=,COMPLTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,LAMBDA=:{status}"'.format(
                                    port_aid=port_aid, status=status)

                        else:
                            status = "IS-NR,ACT"
                            port_log = '"{port_aid}:{port_type}:ACTTYPE={port_type},TYPEINFO01={port_type},COMPLTYPE={port_type},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},LAMBDA=UNSPEC,LAMBDAINFO=1310:{status}"'.format(
                                port_aid=port_aid, port_type=port_type, vend_id=vend_id, dom=dom, clei=clei,
                                serial_no=serial_no, usi=usi, status=status)

                        logs.append(port_log)
                    slot_index += 1

                while slot_index <= total_slots:
                    empty_log = '"{}-{}::ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,CARDCURRFEED=0.0A:OOS-AUMA,UAS&UEQ"'.format(
                        shelf_number, slot_index)
                    logs.append(empty_log)
                    slot_index += 1

                if not card_names_str.strip():
                    continue

                for special_type in config['aids']['specialTypes'].get('shelf{}'.format(shelf_number), []):
                    aid = special_type['aid']
                    card_name = special_type['cardName']
                    vend_id = random_vendid()
                    dom = datetime.now().strftime("%y.%m")
                    clei = random_value(attributes['cleiPattern'])
                    serial_no = generate_serial_number()
                    usi = random_value(attributes['usiPattern'])
                    overtemp = generate_overtemp()
                    card_curr_feed = generate_card_current_feed()

                    if card_name == "MPP5-MPE2" and aid.endswith("1"):
                        status = "IS-NR,ACT"
                        special_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},OVERTEMP={overtemp},CARDCURRFEED={card_curr_feed}:{status}"'.format(
                            aid=aid, card_name=card_name, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                            usi=usi, overtemp=overtemp, card_curr_feed=card_curr_feed, status=status)
                    elif card_name == "MPP5-MPE2" and aid.endswith("2"):
                        status = "OOS-AU,UEQ&STBYH"
                        special_log = '"{aid}:{card_name}:ACTTYPE=,VENDID=,DOM=,CLEI=,SERIALNO=,USI=,OVERTEMP={overtemp},CARDCURRFEED={card_curr_feed}:{status}"'.format(
                            aid=aid, card_name=card_name, overtemp=overtemp,card_curr_feed=card_curr_feed, status=status)

                    else:
                        special_log = '"{aid}:{card_name}:ACTTYPE={card_name},VENDID={vend_id},DOM={dom},CLEI={clei},SERIALNO={serial_no},USI={usi},OVERTEMP={overtemp},CARDCURRFEED={card_curr_feed}:IS-NR,ACT"'.format(
                            aid=aid, card_name=card_name, vend_id=vend_id, dom=dom, clei=clei, serial_no=serial_no,
                            usi=usi, overtemp=overtemp, card_curr_feed=card_curr_feed)

                    logs.append(special_log)

            full_log = "\n".join("   " + log for log in logs)
            chunks = []
            chunk_size = 4000

            while len(full_log) > chunk_size:
                last_newline = full_log.rfind('\n', 0, chunk_size)
                if last_newline == -1:
                    last_newline = chunk_size
                chunks.append(full_log[:last_newline])
                full_log = formatted_header + "\n" + full_log[last_newline + 1:]
            if full_log:
                chunks.append(full_log)

            return True, "\n\n>\n".join(chunks)


        except KeyError as e:
            return False, "Configuration error: missing key %s" % e

