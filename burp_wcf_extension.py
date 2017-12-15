# -*- coding: utf-8 -*-
"""
Created on Thu Jan 10 08:20:14 2013

@author: Nick Coblentz
@author: Vincent D.
"""

from burp import IBurpExtender
from burp import IMessageEditorTabFactory, IMessageEditorTab
from java.io import PrintWriter
import subprocess
import base64
from subprocess import CalledProcessError
import sys
import xml.sax
from xml.dom import minidom


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        #Used to debug plugin
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        # set our extension name
        callbacks.setExtensionName("WCF Binary Scan Insertion Point")
        callbacks.registerMessageEditorTabFactory(self)
        return        

    #
    # implement IMessageEditorTabFactory
    #
    def createNewInstance(self, controller, editable):
        return JavaSerializeXMLInputTab(self, controller, editable)


class JavaSerializeXMLInputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable

        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender.callbacks.createTextEditor()
        self._txtInput.setEditable(False)

        return

    def getTabCaption(self):
        return "WCF Serialized XML viewer"    

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        # enable this tab for requests containing a data parameter
        return WCFBinaryHelper.is_msbin1(self._extender, content)

    def setMessage(self, content, isRequest):
        if (Content-Type is None):
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            try:
                request_info = self._extender.helpers.analyzeRequest(content)
                bodyoffset = request_info.getBodyOffset()
                body_bytes = content[bodyoffset:]

                print 1
                decoded_wcf_body = WCFBinaryHelper.DecodeWCF(self._extender, body_bytes)
                print 2
                xml_body = minidom.parseString(decoded_wcf_body)

                if not isRequest:
                    # prettify is it's a response
                    pretty_xml = xml_body.toprettyxml()
                else:
                    pretty_xml = xml_body.toxml()

                # deserialize the parameter value
                self._txtInput.setText(pretty_xml)

                # we can edit the request
                self._txtInput.setEditable(isRequest)

            except Exception as e:
                print "Can't set message"
                print e

        # remember the displayed content
        self._currentMessage = content
        return

    def getMessage(self):
        if self.isModified():
            wcf_binary_body = WCFBinaryHelper.EncodeWCF(self._extender, self._txtInput.getText())

            request_info = self._extender.helpers.analyzeRequest(self._currentMessage)
            bodyoffset = request_info.getBodyOffset()

            new_request_bytes = list(self._currentMessage)
            new_request_bytes[bodyoffset:] = wcf_binary_body

            return new_request_bytes
        else:
            return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()


class WCFBinaryHelper:

    @classmethod
    def GetHeadersContaining(cls, findValue, headers):
        if(findValue!=None and headers!=None and len(headers)>0):
            return [s for s in headers if findValue in s]
        return None
    
    @classmethod
    def is_msbin1(cls, extender, request_bytes):
        request_info = extender.helpers.analyzeRequest(request_bytes)
        headers = request_info.getHeaders()
        if(headers!=None and len(headers)>0):
            matched_headers = cls.GetHeadersContaining('Content-Type', headers)
            if(matched_headers!=None):
                for matched_header in matched_headers:
                    if('msbin1' in matched_header):
                        return True
        return False            
    
    @classmethod
    def DecodeWCF(cls, extender, body_bytes):
        base64EncodedBody = base64.b64encode(extender.helpers.bytesToString(body_bytes))
        try:
            proc = subprocess.Popen(['NBFS.exe', 'decode', base64EncodedBody], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #proc.wait()
            output = proc.stdout.read()
            extender.stdout.println(output)
            extender.stdout.println(proc.stderr.read())
            return base64.b64decode(output)

        except CalledProcessError, e:
            extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        except:
            extender.stdout.println("Unexpected error: %s: %s\n%s" % (sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2]))        
        return None
     
    @classmethod
    def EncodeWCF(cls, extender, xmlContent):       
        base64EncodedXML = base64.b64encode(xmlContent)
        try:
            proc = subprocess.Popen(['NBFS.exe', 'encode', base64EncodedXML],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            #proc.wait()
            output = proc.stdout.read()
            extender.stdout.println(output)
            extender.stdout.println(proc.stderr.read())
            return extender.helpers.stringToBytes(base64.b64decode(output))

        except CalledProcessError, e:
            extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        except:
            extender.stdout.println("Unexpected error: %s: %s\n%s" % (sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2]))
        return None

