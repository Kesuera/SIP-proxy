#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

#    Source: https://github.com/tirfil/PySipFullProxy


from datetime import datetime
import logging
import socketserver
import socket
import re
import time

HOST, PORT = '0.0.0.0', 5060
rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^CANCEL")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

# global dictionnary
recordroute = ""
topvia = ""
registrar = {}
calls = []

class Call:
    def __init__(self, call_id):
        self.call_id = call_id
        self.call_status = 'invite'

    def changeStatus(self, call_status):
        self.call_status = call_status

class UDPHandler(socketserver.BaseRequestHandler):

    def findCall(self, call_id):
        for call in calls:
            if call.call_id == self.data[5]:
                return call
        return None

    def logInvite(self):        
        curr_call = self.findCall(self.data[5])

        if curr_call:
            if curr_call.call_status in ['invite', 'calling']:
                return
        else:
            curr_call = Call(self.data[5])
            calls.append(curr_call)

        now = datetime.now()
        logging.info('%s - %s -> INVITE from %s to %s', now.strftime("%m/%d/%Y, %H:%M:%S"), curr_call.call_id, self.getOrigin(), self.getDestination())

    def logInviteResponse(self, code):
        curr_call = self.findCall(self.data[5])

        if not curr_call or curr_call.call_status != 'invite':
            return

        now = datetime.now()

        if code == 200:
            logging.info('%s - %s -> %s ACCEPTED by %s', now.strftime("%m/%d/%Y, %H:%M:%S"), curr_call.call_id, code, self.getDestination())
            curr_call.changeStatus('calling')
            return

        elif code == 603:
            logging.info('%s - %s -> %s DECLINED by %s', now.strftime("%m/%d/%Y, %H:%M:%S"), curr_call.call_id, code, self.getDestination())
        elif code == 486:
            logging.info('%s - %s -> %s %s is BUSY', now.strftime("%m/%d/%Y, %H:%M:%S"), curr_call.call_id, code, self.getDestination())
        elif code == 487:
            logging.info('%s - %s -> %s TERMINATED by %s', now.strftime("%m/%d/%Y, %H:%M:%S"), code, curr_call.call_id, self.getOrigin())
        
        calls.remove(curr_call)

    def logBye(self):
        curr_call = self.findCall(self.data[5])

        if not curr_call or curr_call.call_status != 'calling':
            return
        
        now = datetime.now()
        logging.info('%s - %s -> BYE from %s', now.strftime("%m/%d/%Y, %H:%M:%S"), curr_call.call_id, self.getOrigin())
        calls.remove(curr_call)

    def logInviteError(self, code):
        curr_call = self.findCall(self.data[5])

        if not curr_call or curr_call.call_status != 'invite':
            return

        now = datetime.now()

        if code == 400:
            logging.info('%s - %s -> %s BAD REQUEST', now.strftime("%m/%d/%Y, %H:%M:%S"), curr_call.call_id, code)
        elif code == 480:
            logging.info('%s - %s -> %s TEMPORARILY UNAVAILABLE', now.strftime("%m/%d/%Y, %H:%M:%S"), curr_call.call_id, code)
        elif code == 500:
            logging.info('%s - %s -> %s INTERNAL SERVER ERROR', now.strftime("%m/%d/%Y, %H:%M:%S"), curr_call.call_id, code)

        calls.remove(curr_call)

    def changeRequestUri(self):
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar:
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method, uri)

    def removeRouteHeader(self):
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data

    def addTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch = md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    data.append(via)
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line, text)
                data.append(via)
            else:
                data.append(line)
        return data

    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(topvia):
                    data.append(line)
            else:
                data.append(line)
        return data

    def checkValidity(self, uri):
        global registrar
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del registrar[uri]
            return False

    def getSocketInfo(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        return (socket, client_addr)

    def getDestination(self):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" % (md.group(1), md.group(2))
                break
        return destination

    def getOrigin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" % (md.group(1), md.group(2))
                break
        return origin

    def sendResponse(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line, ";tag=123456")
            if rx_via.search(line) or rx_cvia.search(line):
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (line, text)
            if rx_contentlength.search(line):
                data[index] = "Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index] = "l: 0"
            index += 1
            if line == "":
                break
        data.append("")
        text = "\r\n".join(data)
        self.socket.sendto(text.encode('utf-8'), self.client_address)

    def processRegister(self):
        global registrar
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = "%s@%s" % (md.group(1), md.group(2))
            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)

        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        if expires == 0:
            if fromm in registrar:
                del registrar[fromm]
                self.sendResponse("200 V Poriadku")
                return
        else:
            now = int(time.time())
            validity = now + expires

        registrar[fromm] = [contact, self.socket, self.client_address, validity]
        self.sendResponse("200 V Poriadku")

    def processInvite(self):
        origin = self.getOrigin()
        if len(origin) == 0 or origin not in registrar:
            self.sendResponse("400 Zlá Požiadavka")
            self.logInviteError(400)
            return
        destination = self.getDestination()
        if len(destination) > 0:
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                data.insert(1, recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode('utf-8'), claddr)
            else:
                self.sendResponse("480 Dočasne Nedostupné")
                self.logInviteError(480)
        else:
            self.sendResponse("500 Interná Chyba Servera")
            self.logInviteError(500)

    def processAck(self):
        destination = self.getDestination()
        if len(destination) > 0:
            if destination in registrar:
                socket, claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                data.insert(1, recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode('utf-8'), claddr)

    def processNonInvite(self):
        origin = self.getOrigin()
        if len(origin) == 0 or origin not in registrar:
            self.sendResponse("400 Zlá Požiadavka")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                data.insert(1, recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode('utf-8'), claddr)
            else:
                self.sendResponse("406 Neakceptovateľné")
        else:
            self.sendResponse("500 Interná Chyba Servera")

    def processCode(self):
        origin = self.getOrigin()
        if len(origin) > 0:
            if origin in registrar:
                socket, claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()
                text = "\r\n".join(data)
                socket.sendto(text.encode('utf-8'), claddr)

                if data[5].find('INVITE') >= 0:
                    if data[0].find('200') >= 0:
                        self.logInviteResponse(200)
                    elif data[0].find('603') >= 0:
                        self.logInviteResponse(603)
                    elif data[0].find('486') >= 0:
                        self.logInviteResponse(486)

    def processRequest(self):
        if len(self.data) > 0:
            request_uri = self.data[0]
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.logInvite()
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.logBye()
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
                self.logInviteResponse(487)
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.sendResponse("200 V Poriadku")
            elif rx_publish.search(request_uri):
                self.sendResponse("200 V Poriadku")
            elif rx_notify.search(request_uri):
                self.sendResponse("200 V Poriadku")
            elif rx_code.search(request_uri):
                self.processCode()

    def handle(self):
        try:
            data = self.request[0].decode('utf-8')
        except UnicodeDecodeError:
            return
        self.data = data.split("\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            self.processRequest()

def start_server():
    global recordroute, topvia
    logging.basicConfig(filename='call.log', filemode='w', encoding='utf-8', format='%(message)s', level=logging.INFO)
    ipaddress = socket.gethostbyname(socket.gethostname())
    recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress, PORT)
    topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress, PORT)
    server = socketserver.UDPServer((HOST, PORT), UDPHandler)
    print('Server is running at: \nIP: {}\nPort: {}\n'.format(ipaddress, PORT))
    server.serve_forever()
