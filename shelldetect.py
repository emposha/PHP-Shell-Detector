# encoding: utf-8
"""
 Shell Detector  v1.0 
 Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>

 https://github.com/emposha/PHP-Shell-Detector
"""

import hashlib, sys, re, pickle, json
import os, optparse, base64, codecs, stat
import fnmatch, time

from hashlib import md5
from phpserialize import PHP_Serializer
from urllib.request import urlopen
from datetime import datetime, date

ssl_support = True
try:
  import ssl
except ImportError :
  ssl_support = False

class shellDetector :
  _extension = ["php", "asp", "txt"]
  
  #settings: show line number where suspicious function used
  _showlinenumbers = True
  #settings: used with access time & modified time
  _dateformat = "H:i:s d/m/Y"
  #settings: scan specific directory
  _directory = '.'
  #settings: scan hidden files & directories
  _scan_hidden = True
  #settings: used with is_cron(true) file format for report file
  _report_format = 'shelldetector_%d-%m-%Y_%H%M%S.html'
  #settings: get shells signatures db by remote
  _remotefingerprint = False

  #default ouput 
  _output = ""
  _files = []
  _badfiles = []
  _fingerprints = []
  
  #system: title
  _title = 'Shell Detector'
  #system: version of shell detector
  _version = '1.0'
  #system: regex for detect Suspicious behavior
  _regex = r"(?si)(\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)"
  #system: public key to encrypt file content
  _public_key = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JR2ZNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRRDZCNWZaY2NRN2dROS93TitsWWdONUViVU4NClNwK0ZaWjcyR0QvemFrNEtDWkZISEwzOHBYaS96bVFBU1hNNHZEQXJjYllTMUpodERSeTFGVGhNb2dOdzVKck8NClA1VGprL2xDcklJUzVONWVhYUQvK1NLRnFYWXJ4bWpMVVhmb3JIZ25rYUIxQzh4dFdHQXJZWWZWN2lCVm1mRGMNCnJXY3hnbGNXQzEwU241ZDRhd0lEQVFBQg0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tDQo="

  def __init__(self, options) :
    #set arguments
    if options.extension != None :
      self._extension = options.extension.split(',')
    
    self._showlinenumbers = options.linenumbers
    
    if options.directory != None :
      self._directory = options.directory
    
    if options.dateformat != None :
      self._dateformat = options.dateformat
    
    if options.format != None :
      self._report_format = options.format
    
    self._remotefingerprint = options.remote
    
    serial = PHP_Serializer()
    if (self._remotefingerprint == True) :
      url = 'http://www.websecure.co.il/phpshelldetector/api/?task=getlatest'
      self._fingerprints = urlopen(url).read()
      self._fingerprints = serial.unserialize(str(base64.b64decode(bytes(self._fingerprints))))
    else :
      if(os.path.isfile("shelldetect.db")) :
        try :
          self._fingerprints = serial.unserialize(str(base64.b64decode(bytes(open('shelldetect.db', 'rt').read(), 'utf-8')), 'utf-8'))
        except IOError as e :
          print("({})".format(e))
  
  def start(self) :
    self.header()
    if ssl_support == False :
      print('Please note ssl library not found, suspicious files will be included in html without encryption.')
    if self._fingerprints.__len__ == 0 :
      print('Please note, shells signature database not found, suspicious files will be scan only by behavior.')

    #start
    self.version()
    self.filescan()
    self.anaylize()
    #end

    self.flush()
    return None

  def anaylize(self) :
    _counter = 0
    for _filename in self._files :
      _content = open(_filename , 'rt', -1 ,'utf-8').read()
      _regex = re.compile(self._regex)
      _match = _regex.findall(_content)
      print(_match)
      if _match :
        _fileinfo = self.getfileinfo (_filename)
        if self._showlinenumbers :
          self.output('<dt>suspicious functions used:</dt><dd>', '', False)
          _lines = _content.split("\n")
          _linecounter = 1
          for _line in _lines :
            _match_line = _regex.findall(_line)
            if _match_line :
              _lineid = md5(_line + _filename)
              self.output(_match_line.implode(', ')  + ' (<a href="#" class="showline" id="ne_' + _lineid + '">line:' + _linecounter + '</a>)', '', False)
              self.output('<div class="hidden source" id="line_' + _lineid + '"><code>' + escape(_line) + '</code></div>', '', False)
              self.output('&nbsp;</dd>', '', False)
              _linecounter += 1
        else :
          self.output('<dt>suspicious functions used:</dt><dd>' + _match.implode(', ') + '&nbsp;</dd>', '', False)
        _counter += 1
        self.fingerprint(_filename, _content, _flag)
    self.output('', 'clearer')
    if (len(self._badfiles) == 0) :
      _bad_files = str(len(self._badfiles))
      _class = 'success'
    else :
      _bad_files = '<strong>' + str(len(self._badfiles)) + '</strong>'
      _class = 'error'
    self.output('<strong>Status</strong>: ' + str(_counter) + ' suspicious files found and ' + _bad_files + ' shells found', 'success')
    
  
  def fingerprint(self, _filename, _content, _flag) :
    print ('test')

  def getfileinfo(self, _file) :
    _file_stats = os.stat(_file)
    self.output('<dl><dt>Suspicious behavior found in: ' + _file + '<span class="plus">-</span></dt>', '', False)
    self.output('<dd><dl><dt>Full path:</dt><dd>' + _file + '</dd>', '', False)
    self.output('<dt>Owner:</dt><dd>' + str(_file_stats.st_uid) + '</dd>', '', False)
    self.output('<dt>Permission:</dt><dd>'  +  oct(_file_stats[stat.ST_MODE])[-3:] +  '</dd>', '', False)
    self.output('<dt>Last accessed:</dt><dd>' + time.strftime(self._dateformat, time.localtime(_file_stats[stat.ST_ATIME])) + '</dd>', '', False)
    self.output('<dt>Last modified:</dt><dd>' + time.strftime(self._dateformat, time.localtime(_file_stats[stat.ST_MTIME])) + '</dd>', '', False)
    self.output('<dt>Filesize:</dt><dd>' + str(_file_stats [stat.ST_SIZE]) +  '</dd>', '', False)

  def version(self) :
    try :
      _version = self._fingerprints['version']
    except ValueError :
      _version = 0
    try :
      _server_version = int(urlopen('http://www.websecure.co.il/phpshelldetector/api/?task=checkver').read(), 10)
    except ValueError :
      _server_version = 0

    if (_server_version == 0) :
      self.alert('Cant connect to server! Version check failed!', 'error')
    else :
      if (_server_version < int(_version)) :
        self.alert('New version of shells signature database found. Please update!', 'error')

  def filescan(self) :
    self.alert('Starting file scanner, please be patient file scanning can take some time.')
    self.alert('Number of known shells in database is: ' + str(len(self._fingerprints)))
    self.listdir()
    self.alert('File scan done, we have: ' + str(len(self._files)) + ' files to analize')

  def listdir(self) :
    for root, dirnames, filenames in os.walk(self._directory) :
      for extension in self._extension:
        for filename in fnmatch.filter(filenames, '*.' + extension) :
          self._files.append(os.path.join(root, filename))
    return None

  def header(self) :
    _style = '<style type="text/css" media="all">body{background-color:#ccc;font:13px tahoma,arial;color:#151515;direction:ltr}h1{text-align:center;font-size:24px}dl{margin:0;padding:0}#content{width:1024px;margin:0 auto;padding:35px 40px;border:1px solid #e8e8e8;background:#fff;overflow:hidden;-webkit-border-radius:7px;-moz-border-radius:7px;border-radius:7px}dl dt{cursor:pointer;background:#5f9be3;color:#fff;float:left;font-weight:700;margin-right:10px;width:99%;position:relative;padding:5px}dl dt .plus{position:absolute;right:4px}dl dd{margin:2px 0;padding:5px 0}dl dd dl{margin-top:24px;margin-left:60px}dl dd dl dt{background:#4fcba3!important;width:180px!important}.error{background-color:#ffebe8;border:1px solid #dd3c10;padding:4px 10px;margin:5px 0}.success{background-color:#fff;border:1px solid #bdc7d8;padding:4px 10px;margin:5px 0}.info{background-color:#fff9d7;border:1px solid #e2c822;padding:4px 10px;margin:5px 0}.clearer{clear:both;height:0;font-size:0}.hidden{display:none}.green{font-weight:700;color:#92b901}.red{font-weight:700;color:#dd3c10}.green small{font-weight:400!important;color:#151515!important}.filesfound{position:relative}.files{position:absolute;left:4px;background-color:#fff9d7}iframe{border:0px;height:24px;width:100%}.small{font-size: 10px;font-weight:normal;}.ui-widget-content dl dd dl {margin-left: 0px !important;}.ui-widget-content input {width: 310px;margin-top: 4px;}</style>'
    _script = 'function init(){$("dt").click(function(){var text=$(this).children(".plus");if(text.length){$(this).next("dd").slideToggle();if(text.text()=="+"){text.text("-")}else{text.text("+")}}});$(".showline").click(function(){var id="li"+$(this).attr("id");$("#"+id).dialog({height:440,modal:true,width:600,title:"Source code"});return false});$(".source_submit").click(function(){var id="for"+$(this).attr("id");$("#wrap"+id).dialog({autoOpen:false,height:200,width:550,modal:true,resizable: false,title:"File submission",buttons:{"Submit file":function(){if($(".ui-dialog-content form").length){$("#i"+id).removeClass("hidden");$("#"+id).submit();$(".ui-dialog-content form").remove()}else{alert("This file already submited")}}}});$("#wrap"+id).dialog("open");return false})}$(document).ready(init);'
    self.output('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><title>Web Shell Detector</title>' + _style + '<link rel="stylesheet" href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/themes/base/jquery-ui.css" type="text/css" media="all" /><script src="http://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js" type="text/javascript" charset="utf-8"></script><script src="https://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/jquery-ui.min.js" type="text/javascript" charset="utf-8"></script><script type="text/javascript">' + _script + '</script></head><body><h1>' + self._title + ' ' + self._version +'</h1><div id="content">', '', False)

  def alert(self, _content, _class='info', _html = True) :
    print (_content)
    self.output(_content, _class, _html)

  def output(self, _content, _class='info', _html = True) :
    if(_html) :
      self._output += '<div class="' + _class + '">' + _content + '</div>'
    else:
      self._output += _content

  def flush(self) :
    print("Flush")
    #filename = datetime.now().strftime(self._report_format)
    #file = open(filename, "w", -1,'utf-8')
    #file.write(self._output)

#Start
parser = optparse.OptionParser()
parser.add_option('--extension', '-e', type="string", default="php,txt,asp", help="file extensions that should be scanned")
parser.add_option('--linenumbers', '-l', default=True, help="show line number where suspicious function used")
parser.add_option('--directory', '-d', type="string", help="used with access time & modified time")
parser.add_option('--dateformat', '-a', type="string", help="scan specific directory")
parser.add_option('--format', '-f', type="string", help="file format for report file")
parser.add_option('--remote', '-r', default=False, help="get shells signatures db by remote")
(options, args) = parser.parse_args()

if len(sys.argv) == 0 :
  parser.print_usage()
  parser.print_help()
else :
  shell = shellDetector(options)
  shell.start()
#End