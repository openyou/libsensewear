#!/usr/bin/env python
#
# BodyMedia ArmBand Device Library
#
# July 2009 by Centi Benzo centibenzo@gmail.com
#
# THIS CODE IS DECLARED BY THE AUTHOR TO BE IN THE PUBLIC DOMAIN.
# NO WARRANTY OF ANY KIND IS PROVIDED.
#
# See blog for notes: bodybugglinux.blogspot.com
#
# LIBRARY VERSION - z718a
#
# BodyMedia Notes
# FCC ID PV8-MF filings provide internal photos
# Interal photos reveal:
#  -Fractus chip antenna
#  -FTDI QFP-32 - from footprint, FT232BL? (8-bit parallel)
#  -8-pin SSC chip
#  -16-pin chip
#  -16-pin chip
#  -64-pin chip, blurred number *161*(?) - ?MSP430F1612? 16-bit MCU, 5120B RAM, 55kB Flash
#  -LiPoly 3.7V 300mAh battery

import string
import struct
import serial
import sys
import cPickle
import getopt
import time
import math
from numpy import array, ndarray, fromstring, zeros, resize
import numpy

try:
  from PIL import Image
  def ToImage(d):
    return Image.fromarray(d)
except ImportError:
  print "PIL library not found.  ToImage() func unavailable"

def ParseLine(ln):
  ln = ln.rstrip("\r\n")
  if len(ln) == 0:
    return None
  elif ln[0] != ' ':
    return ln[0:3] # will be "Req", "Ans" or something else
  else:
    v = ln[1:48].split(" ")
    return [int(i,16) for i in v if i != '']

def CombineListElements(lst):
  stack=[]
  while True:
    if len(lst) == 0:
      return stack
    elif len(lst) > 1 and type(lst[0]) == list and type(lst[1]) == list:
      e = lst[0] + lst[1]
      lst = [e] + lst[2:]
    else:
      stack += [lst[0]]
      lst = lst[1:]

def ParseFile(f):
  """Parses a 'Free Serial Port Monitor' Request View export file - ie,
  you can use this function to load a sniffed serial port conversation
  between the BodyMedia software and the device."""
  txt = f.readlines()
  lns = [ParseLine(l) for l in txt]
  print len(lns)
  # Combine successive data files
  lns = CombineListElements(lns)
  print len(lns)
  # Filter Null lines
  lns = [x for x in lns if x != None]
  # Change to (type, data) format
  lns = [(lns[i], lns[i+1]) for i in range(0,len(lns)) if lns[i] == 'Req' or lns[i] == 'Ans']
  lns = [(x[0], ListToByteString(x[1])) for x in lns]
  print len(lns)
  return lns

def ListToByteString(l):
  return struct.pack("B" * len(l), *l)

def OpenSerial(fname="/dev/ttyUSB0"):
  ser=serial.Serial(fname,baudrate=921600,timeout=.01)
  ser.open()
  # Device needs some commands to warm up.  Won't always get response to first command (NOT timeout issue)
  fail=0
  while True:
    p=[0x80, 0x01, 0x01]  # simple "register" read
    cmd = CreateSimpleRequest(p)
    try:
      WriteAndReadSerialPacket(ser, cmd)
      break
    except:
      print "Attempting to talk to device, try %i - trying again..." % fail
      fail += 1
    if fail > 5:
      raise Exception("Failed to talk to device!")
  return ser

def ReadSerial(ser, minLen, timeout=3.0, maxLen=2**15):
  """Read at least minLen bytes from serial, with specified timeout.  This
  varies from the Serial.setTimeout() character timeout, since a read may
  return prematurely."""
  s=''
  t0=time.time()
  while True:
    s += ser.read(maxLen - len(s))
    if len(s) >= minLen or len(s) == maxLen:
      return s
    if time.time() - t0 > timeout:
      raise Exception("ReadSerial timeout after %f sec, expected %i bytes, got %i bytes: %s" % (time.time() - t0, minLen, len(s), s))

def WriteAndReadSerialPacket(ser, packet):
  """Write specified packet, and read the response.
     Detects if packet expects a "burst" response, and 
     reads exactly that many response packets.  """
  assert len(packet) == 69, "Exptected a request packet of size 69, not %i" % len(packet)
  parse = ParsePacket2(packet)
  assert parse['type'] == 'Req', "WriteAndReadSerial expect a Req type packet as parameter"
  rlen = parse.get('rlen',1)
  n = int(math.ceil(float(rlen)/44.))
  ser.write(packet)
  return ReadSerial(ser, minLen=n*66, maxLen=n*66)

def CreateMemoryReadPacket(offset, length):
  """Construct a memory request packet for starting address and length"""
  buf = struct.pack('<BBIH', 0x82, 0x0, offset, length)
  return CreateSimpleRequest(buf)

def MemoryDump(ser, offset=0, length=2*(2**20), stopAtFF=True):
  """Produce a memory dump from the serial device.  if stopAtFF==True,
  the stop reading when a response packet of all 0xFF occurs.  length is
  the size of memory to read.  Physical device has a 2MByte address
  space.  GoWearFit software usually reads up until 193,600 bytes."""
  packets=[]
  total=0
  while total < length:
    rlen = min(length - total, 8800)
    pp = CreateMemoryReadPacket(total, rlen)
    packets.append(pp)
    sys.stderr.write(".")
    packets.append(WriteAndReadSerialPacket(ser, pp))
    total += rlen
    if stopAtFF and packets[-1][-66+20:-66+63] == '\xff'*43:
      break
  mem = AssembleDataFromPackets(packets)
  return (packets, mem)

def ClearMemory(ser):
  """Clear sensor data from memory.
     There may be other memory ranges. I also see a 0x89..0x04 command.
     Returns the response from the device."""
  pac = [0x89, 0x85, 0x02] # 85 is just the dumb sequence number
  ser.write(CreateSimpleRequest(pac))
  return ReadSerial(ser, 66)

def FullSerialDump(serialName="/dev/ttyUSB0", banks=set([0x2, 0xb])):
  # Load dump
  req= cPickle.load(open("known_requests.cpickle","r"))
  ser= OpenSerial(serialName)
  log= []
  for p in [x for x in req if ((ord(x[12]) & 0x7F) in banks)]:
    log.append(p)
    sys.stderr.write(".")
    log.append(WriteAndReadSerialPacket(ser, p))
    if len(log[-1])==0:
      ser.close()
      raise Exception("Got empty response.  Try again.")
  ser.close()
  sys.stderr.write("\n")
  return log

def ProtocolAnalysis(ss):
  """Accepts a list of byte strings of uniform length.  
  Returns a list of lists of values seen at each position"""
  c=[set() for x in range(0,len(ss[0]))]
  for s in ss:
    for i in range(0,len(c)):
      if i >= len(s):
        x = None
      else:
        x = s[i]
      c[i].add(x)
  return c

def PrintProtocolAnalysis(c):
  for i in range(0,len(c)):
    print str(i)+":",
    for x in list(c[i])[0:20]:
      print "%02x" % ord(x),
    if len(c[i]) > 20:
      print "...",len(c[i])-20,"more...",
    print

def Checksum(pk):
  chk=0
  for x in pk:
    chk += ord(x)
  return chk

def CreateSimpleRequest(addr):
  """Creates a simple request using an address.
     addr should be a list of four address(?) bytes.
     ex: [0x8B, 0x24, 0x1, 0x11]
     Also will accept a string.
  """
  if type(addr) == list:
    addr = ListToByteString(addr)
  # Unchanging header (at least in any data we've seen)
  # Rudy has identified some fields, but we don't need them
  fromAddr= "\x00\x00\x00\x0e"
  toAddr  = "\xff\xff\xff\xff" # this is usually the device HW address
  pk ='\xab\x03\x3c\x00' + fromAddr + toAddr
  pk += addr
  # Zero pad the rest of payload
  pk += ListToByteString([0]*(64-len(pk)))
  checksum = Checksum(pk[1:]) # sync byte not included
  pk += chr(checksum % 256)
  pk += '\xba\xba\xba\xba'
  return pk

def RecomputeChecksum(packet):
  """Recompute the checksum on an existing packet.  Returns a modified
  packet.  Assumes len(packet)=69"""
  assert len(packet) == 69, "Packet length must equal 69"
  checksum = Checksum(packet[1:64])
  packet = packet[0:64] + chr(checksum % 256) + packet[65:]
  return packet

def HexPrint(s, format="%02X"):
  """Pretty print in Hex the characters in a string"""
  for x in s:
    if ord(x) == 0:
      #sys.stdout.write("__")
      print "__",
    else:
      print format % ord(x),
  print

def AnsiColorRange(x):
  invert= (x >> 7) & 1
  color= (x >> 4) & 7
  bold = (x >> 3) & 1
  s = "\33[%im" % (31 + color)
  if bold:
    s += "\33[1m"
  if invert:
    s += "\33[7m"
  return s


def HexPrintColor(s, format="%02X"):
  """Pretty print in Hex the characters in a string, with color"""
  for x in s:
    color=ord(x) % 7
    bold=ord(x) % 2
    if x <= 'z' and x >= 'A':
      c=x
      bold = 0
    else:
      c=" "
    if ord(x) == 0:
      sys.stdout.write("__ ")
    else:
      sys.stdout.write( ("\33[%im\33[%im"+format+"\33[0m%s") % (31+color,1 + 21*bold, ord(x),c) )
  print


def HexPrintColor2(s, format="%02X"):
  for x in s:
    color=AnsiColorRange(ord(x))
    if x <= 'z' and x >= 'A':
      c=x
      bold = 0
    else:
      c=" "
    if ord(x) == 0:
      sys.stdout.write("__ ")
    else:
      sys.stdout.write( (color + format + "\33[0m%s") % (ord(x), c) )
  sys.stdout.write("\n")


def HexPrintMod(s, mod, format="%2X", color=True, label=True, skip=None, skip2=None, start=0x0, size=None):
  assert skip == None or type(skip) == str,"skip should be a single string character"
  if type(s) == ndarray:
    s = s.tostring()
  skipcnt=0
  if size == None:
    size = len(s)
  else:
    size = start + size
  for i in range(start, size, mod):
    if (skip != None and s[i:i+mod] == skip*mod) \
      or ((skip2 != None) and s[i:i+mod] == skip2*mod):
      skipcnt += mod
      continue
    if skipcnt > 0:
      sys.stdout.write("skipped %i bytes of %x\n" % (skipcnt, ord(skip)))
      skipcnt=0
    if label:
      sys.stdout.write("%4x: " % i)
    if color:
      HexPrintColor2(s[i:i+mod], format)
    else:
      HexPrint(s[i:i+mod], format)

# Mapping from struct module format codes to printf
fmtmap = {'b':'%3i', 'B':'%3i', 'h':'%5i', 'H':'%5i', 'f':'%5f'}

def StructToString(s, fmt, minwidth=0, color=True, hexonly=False):
  """Unpacks and creates a string representation of a python struct in
  an intelligent, fixed field width way"""
  if type(s) == ndarray:
    s=s.tostring()
  d=struct.unpack_from(fmt, s)
  minf="%" + str(minwidth)+"s"
  out=""
  hex=0
  pos=0
  for i in range(0, len(d)):
    while not fmtmap.has_key(fmt[0]):
      if fmt[0] == 'x':
        s=s[1:]
      fmt = fmt[1:]
    if color:
      c = string.join(fmtmap.keys(),"").find(fmt[0])
      out += "\33[%im" % (31 + c)
    if not hexonly:
      out += minf % (fmtmap[fmt[0]] % d[i] + " ")
    else:
      sz = struct.calcsize(fmt[0])
      a = minf % (("%0"+str(2*sz)+"x") % (HexStringToInt(s[:sz])) + " ")
      a = a.replace("00","__")
      out += a
      s = s[sz:]
    if color:
      out += "\33[0m"
    fmt = fmt[1:]
  return out

def PrintMultiLineLabels(labels, width=6):
  one=""
  two=""
  fmt="%"+str(width)+"s" 
  for x in labels:
    if len(x)+1 > width:
      one += fmt % x[:3]
      two += fmt % (x[3:])
    else:
      one += fmt % ""
      two += fmt % x
  sys.stdout.write(one + "\n")
  sys.stdout.write(two + "\n")

def PrintByteLabels(fmt, s4len):
  szFmt = struct.calcsize(fmt)
  pos=0
  ss=[]
  for c in fmt:
    sz = struct.calcsize(c)
    if fmtmap.has_key(c):
      if sz > 1:
        ss.append("%5s" % ("%2i-%i" % (pos, pos+sz-1)))
      elif sz == 1:
        ss.append("%5s" % ("_%i_" % pos))
    pos += sz
  sys.stdout.write(string.join(ss," ") + "\n")

def PrintByteStats(s4, fmt, indent=""):
  szFmt = struct.calcsize(fmt)
  d = array([struct.unpack_from(fmt, row) for row in s4]).transpose()
  stats = dict(CalcStats(d))
  labels=["  MIN","  MAX","  AVG","MDIAN","STDEV"]
  for i in range(0,5):
    ss=[]
    pos=0
    idx=0
    for c in fmt:
      sz = struct.calcsize(c)
      if fmtmap.has_key(c):
        ss.append("%5s" % ("%i" % stats[idx][i]))
        idx += 1
      pos += sz
    sys.stdout.write(labels[i] + " " + string.join(ss," ") + "\n")

def CalcStats(d):
  stats=[]
  i=0
  for col in d:
    avg=sum(col)/len(col)
    med=median(col)
    ssquares=sum([(x - avg)**2. for x in col])
    stddev=sqrt(ssquares/len(col))
    stats.append((i, (min(col), max(col), int(avg), int(med), int(stddev))))
    i+=1
  return stats

def PrintRecords(labels, s4, fmtHead, fmtTail="", printHex=True, printNorm=True):
  fmt = fmtHead
  szHead = struct.calcsize(fmtHead)
  szTail = struct.calcsize(fmtTail)
  printableHead = string.join([x for x in fmtHead if fmtmap.has_key(x)],"")
  printableTail = string.join([x for x in fmtTail if fmtmap.has_key(x)],"")
  if fmtTail != "":
    gap = len(s4[0]) - (struct.calcsize(fmtHead) + struct.calcsize(fmtTail))
    fmt = fmtHead + ("x"*gap) + fmtTail
  labels = ["LINE"] + labels[:len(printableHead)] + labels[len(labels)-len(printableTail):]
  PrintMultiLineLabels(labels,6)
  sys.stdout.write(6*" ")
  PrintByteLabels(fmt, len(s4))
  for i in range(0, len(s4)):
    if printNorm:
      sys.stdout.write("%5i:%s\n" % (i, StructToString(s4[i], fmt, 6)))
    if printHex:
      sys.stdout.write("\33[0m")
      sys.stdout.write("      %s\n" % (StructToString(s4[i], fmt, 6, color=False, hexonly=True)))
    if not ((i+1) % 40) or (i == len(s4) - 1):
      PrintMultiLineLabels(labels,6)
      sys.stdout.write(6*" ")
      PrintByteLabels(fmt, len(s4))
    #HexPrintMod(s4[i][:szHead].tostring() + s4[i][len(s4[i]) - szTail:].tostring(), szHead + szTail)
  PrintByteStats(s4, fmt)

def HexPrintArray(a, format="%2X", color=True):
  for i in range(0, len(a)):
    if color:
      HexPrintColor(a[i].tostring(), format)
    else:
      HexPrint(a[i].tostring(), format)


def SimpleReq(ser, addr):
  pk = CreateSimpleRequest(addr)
  ser.write(pk)
  a=ReadSerial(ser, 66)
  return a

def ReplayReq(ser, pk):
  if type(pk) != str:
    raise Exception("ReplayReq got non-string for packet")
  ser.write(pk)
  a=ReadSerial(ser, 66)
  return a

def SplitBurst(pk):
  """Split a burst packet into its sub-packets.
     Burst packets are always (?) split into 66 byte sub-packets."""
  v=[]
  while len(pk) > 0:
    v.append(pk[0:66])
    pk = pk[66:]
  return v

def ParsePacket2(pk):
  if type(pk) == list:
    return [ParsePacket2(x) for x in pk]
  # Detect and recurse on burst packet
  if len(pk) > 130:
    burst = SplitBurst(pk)
    return dict([("type","Burst"), ("burst", [ParsePacket2(x) for x in burst])])
  d={}
  # split the end and start padding
  if pk[-4:] == '\xba\xba\xba\xba':
    pk = pk[:-4]
  elif pk[-1] == '\xba':
    pk = pk[:-1]
  else:
    raise Exception("Unexpected padding "+pk[-4:])
  assert pk[0] == '\xab',"Sync byte not equal to AB"
  pk= pk[1:]
  # Now perform checksum (w/o padding or checksum field)
  checksum = Checksum(pk[:-1])
  if pk[0] == '\x03':
    d['type']='Req'
  elif pk[0] == '\x04':
    d['type']='Ans'
  else:
    raise Exception("Unkown packet type")
  pk= pk[1:]
  d['len']= 256*ord(pk[1]) + ord(pk[0])
  pk= pk[2:]
  assert d['len'] > 59, "Packet len too short"
  d['fromAddr']= pk[:4]
  pk= pk[4:]
  d['toAddr']= pk[:4]
  pk= pk[4:]
  d['reqbit']= (ord(pk[0]) & 0x80)>>7
  d['bank']= 0x7F&ord(pk[0])
  pk= pk[1:]
  d['n']= ord(pk[0])
  pk= pk[1:]
  # Split off body
  d['body']= pk[0:-1]
  # checksum
  d['chk']= ord(pk[-1])
  if d['chk'] != (checksum % 256):
    raise Exception("ERROR: Checksum mismatch %x != %x" % (d['chk'], checksum % 256))
  #### Read Burst Fields
  if d['type'] == 'Req' and d['bank'] == 0x2:
    d['offset']=fromstring(pk[0] + pk[1]+ pk[2] + pk[3],'uint32')[0]
    pk= pk[4:]
    d['rlen']= fromstring(pk[0] + pk[1],'uint16')[0]
  if d['type'] == 'Ans' and d['bank'] == 0x2:
    d['offset']=fromstring(pk[0] + pk[1]+ pk[2] + pk[3],'uint32')[0]
    pk= pk[4:]
    d['rlen']= fromstring(pk[1] + pk[0],'uint16')[0]
  return d
  #return dict([(n[i],d[i]) for i in range(0,len(d))])

def PrintPacket2(packet, color=True, indent=""):
  if type(packet) == str:
    p = ParsePacket2(packet)
  elif type(packet) == list:
    for x in packet:
      PrintPacket2(x, color, indent)
    return
  else:
    p = packet # already parsed
  if p['type'] == 'Burst':
    for x in p['burst']:
      PrintPacket2(x, color, indent + "  ")
    return
  sys.stdout.write(indent + p['type'][0] + ' ')  # type
  sys.stdout.write("%02x " % p['bank'])
  if p.has_key('offset'):
    sys.stdout.write("%6x %4x " % (p['offset'],p['rlen']))
    remainder= p['body'][6:]
  else:
    remainder= p['body']
  remainder = remainder.rstrip("\x00")
  if color:
    HexPrintColor(remainder)
  else:
    HexPrint(remainder, "%02X")

def FlattenBurstPackets(packets):
  output=[]
  for p in packets:
    if p['type'] == "Burst":
      output.extend(p['burst'])
    else:
      output.append(p)
  return output

def AssembleDataFromPackets(packets):
  """Create a single data array from a set of packets.
    Will operate on a list of parsed packet dictionaries, or a list of raw
    packets in string form"""
  if len(packets) == 0:
    return []
  if type(packets[0]) == str:
    packets = ParsePacket2(packets)
  packets = FlattenBurstPackets(packets)
  ##memsize = 0x30e61
  ##mem = zeros([memsize],'uint8')
  mem = zeros([0],'uint8')
  for p in packets:
    if p['type'] == 'Ans' and p['bank'] == 0x2:
      o=p['offset']
      sz=p['rlen']
      assert len(p['body']) == sz + 6, Exception("body/length mismatch")
      #assert o + sz < memsize, Exception("Memory overflow: assumed memory size too small")
      if (o + sz) > len(mem):
        mem = numpy.resize(mem, (o+sz))
      mem[o:o+sz] = fromstring(p['body'][6:], dtype='uint8')
  return mem 

def HexStringToInt(s):
  """Binary data in MSB string format."""
  n=0
  for x in s:
    n = n*256 + ord(x)
  return n

def HexStringToIntLSB(s):
  """Binary data in LSB string format."""
  n=0
  for x in s[::-1]:
    n = n*256 + ord(x)
  return n
 
def StringCorrespondance(s1, s2):
  l = min(len(s1), len(s2))
  c=0
  for i in range(0, l):
    if s1[i] == s2[i]:
      c+=1
  return c

def ByteFrequencyTransform(s, maxshift):
  """A little trick I invented to discover data record lengths"""
  F=[] # correspondances for range of shift levels
  for i in range(0, maxshift+1):
    sshift = s[i:]
    F.append((i, StringCorrespondance(s, sshift)))
  return F

def MemPrettyPrint(mem, bank=None):
  reg = mem.getMergedRegions()
  for b in reg:
    if bank!=None and b[0] != bank:
      continue
    print
    print "***BANK %04X" % b[0]
    for r in b[1]:
      # Print in 46 byte increments (apparent record size)
      for i in range(r[0], r[1], 46):
        print "%04X %04X:" % (b[0], i),
        HexPrintColor(mem.get(b[0], i, 46), "%02X")

### OBSOLETE
def ReadStruct1(d):
  # Structure 1 (seen at 0x201 offset 0), contains 5 records
  #     Exact copy of this structure also seen at 0x201534
  # (hypothesis - data layout information), record length 22
  #
  # 1 byte unknown, 0x0 except for first entry of 0x1
  # 1 byte record ID number(?)
  # 9 byte null-terminated string field
  # 11 byte data field
  # 16-bit LSB "Div" field ("div" label from HTTP)
  # 8 1-byte channel numbers (from HTTP)
  # 1 byte record size number
  r=[]
  for i in range(0,5):
    v = (ord(d[0]), ord(d[1]), d[2:11].rstrip('\x00'))
    div = HexStringToInt(d[12] + d[11])
    chan = [ord(x) for x in d[13:21]]
    sz = ord(d[21])
    v = (v[0], v[1], v[2], div, chan, sz)
    r.append(v)
    d = d[22:]
  return r

### OBSOLETE
def ReadStruct2(d):
  # Structure 2 - 0x201 offset 106
  #
  # String or column name list
  # Records of length 10
  # 9 byte string null terminated (pad?), 1 byte sequential ID or column number(?)
  # We don't know how to determine list length.  We assume fixed 30 entries
  # A fresh device will have no table.  We check.
  if d[0] == '\xFF':
    sys.stderr.write("ReadStruct2: No name list found - the device contains no data(?)\n")
    return []
  prefix=d[0:8] # TODO: Unidentified fields
  d=d[8:]
  r=[] # result
  for i in range(0,42):
    #r.append((ord(d[10*i + 9]), d[10*i:10*i + 8].rstrip('\x00')))
    r.append((ord(d[10*i]), d[10*i+1:10*i + 9].rstrip('\x00')))
  offset = 42*10
  s1= ReadStruct1(d[offset:])
  offset += 5*22 + 1  # Always 5 records
  unk = d[offset] # Always 0x02 ??
  offset += 1
  timestamp=  HexStringToIntLSB( d[offset:offset+4] )
  return {'unk1':prefix, 'fields':r, 'layout':s1, 'unk2':unk, 'timestamp':timestamp}

### OBSOLETE
def ReadStruct4(d,makeArray=True):
  # Structure 4 (0x201: 810 - most of memory)
  # Primary data structure, length 46
  # Recognizable by vertical hex 10, 11, 12, 13
  #
  # Sub-Structure 4.10, length 13 
  # 1 byte == 10
  # 2 bytes == 2 byte MSB integer, usually increasing (but not always)
  # 
  # Sub-Structure 4.11, length 12
  #
  # Sub-Structure 4.12, length 12
  #
  # Sub-Structure 4.13, length 9
  r=[]
  ld=len(d)
  # Scan for starting row - structure between s2 and s4 is occasionally a
  # different size, and I'm not sure of how to parse it.
  start=None
  for i in range(0, min(46, ld-46)):
    if d[i]=='\x10' and d[i+13]=='\x11' and d[i+13+12]=='\x12' and d[i+13+12+12]=='\x13':
      start=i
      break
  if start == None:
    sys.stderr.write("Cannot find any more sensor data on device")
    return (r, 0)
  if start != 0:
    sys.stderr.write("Alignment shifted by "+str(start)+" bytes\n")
  d=d[start:]
  icorrection=0
  for i in range(0, ld, 46):
    if len(d)==0:
      break
    if d[0] != '\x10' and d[0] != '\x35':
      sys.stderr.write("INFO: Struct4 Lost 0x10 marker after %i bytes" % (ld - len(d)) + " on byte 0x%x\n" % ord(d[0]))
      HexPrintMod(d, 46, size=46*3)
      break
    if d[0] == '\x35': # Timestamp
      s35=d[0:11]
      sys.stderr.write("Timestamp: %x " % HexStringToIntLSB(s35[-4:]) + "\n")
      s35 = [ord(x) for x in s35]
      icorrection += 11
    else:
      s35=[0x35]+[0]*10
    s10 = d[0:13]
    s10 = [ord(x) for x in s10]
    s11 = d[13:25]
    s11 = [ord(x) for x in s11]
    s12 = d[25:37]
    s12 = [ord(x) for x in s12]
    s13 = d[37:46]
    s13 = [ord(x) for x in s13]
    if makeArray:
      r.append(s10 + s11 + s12 + s13 + s35)
    else:
      r.append([s10, s11, s12, s13])
    d=d[46:]
  if makeArray:
    return (array(r,dtype='uint8'), i)
  else:
    return (r, i)

class Table:
  def __init__(self):
    s1=None
    s2=None
    s3=None
    s4=None

### UNUSED
def ReadFields(packets):
  parsed = ParsePacket2(packets)
  d=dict()
  for x in parsed:
    if x.has_key('bank') and x['bank'] == 0xb and x['reqbit'] == 0:
      d[ord(x['body'][0])] = x['body'][1:].rstrip('\x00')
  return d

### OBSOLETE
def ReadPackedData(fields, data):
  h = data.tostring().encode('hex')
  pos=0
  v=[]
  for i in range(0,len(fields)):
    if fields[i][0:2] == 'ID':
      # padded to byte aligned
      if (pos % 2) == 1:
        pos += 1
      v.append(int(h[pos:pos+2],16))
      pos += 2
    else:
      v.append(int("0"+h[pos:pos+3],16))
      pos += 3
  return v

def FindAll(mem, sub, before=16, after=16, mod=32):
  """Finds occurances of a substring in a large string.
     Pretty Prints Hex and location of all matches"""
  if type(mem) == ndarray:
    mem = mem.tostring()
  hits=[]
  offset=0
  l=after+before
  while True:
    offset=string.find(mem, sub, offset)
    if offset == -1:
      break
    if l > mod and len(hits) > 0:
      print  # multi-line per hit, make blank
    HexPrintMod(mem, mod, start=offset-before, size=l)
    hits.append(offset)
    offset += len(sub)
  return hits

# struct representation of records
# Number of times the corresponding RecPack record repeats, if any
# second field is initial reading before repeat, if any
RecRepeat={}
# Record structure
RecPack={}
# Type #1 - Advanced Record layouts
RecPack[1] = '<B 9s HB 8B B '
RecRepeat[1] = (5, "")
# Type #6 - Field Names
RecPack[6] = '<B 9s'
RecRepeat[6] = (42, "<BB")
# Type #2 and #3 - Timestamps (whats the difference?)
RecPack[2] = '<I'
RecPack[3] = '<I'
# Type #53 - Timestamp with unknown field (band on, band off?)
RecPack[53] = '<6B I'
# Type #48 - Unknown record discovered by Freak
RecPack[48] = '<I'
# 12-bit field advanced record types (comes from type #1 table)
RecPack[16] = 13
RecPack[17] = 12
RecPack[18] = 12
RecPack[19] = 9

def ReadPacked12Bit(d):
  """Read 12-bit packed array of ints in d"""
  if type(d) == ndarray:
    d=d.tostring()
  h = d.encode('hex')
  v = []
  pos=0
  for pos in range(0, len(h),3):
    if len(h[pos:pos+3]) < 3: # record boundries padded 0xf
      break
    v.append(int("0"+h[pos:pos+3], 16))
  return v

def ReadRecord(d, offset=0x0):
  id = d[0]
  d=d[1:] # Eat id
  if id == 0xff or id == 0x4: # Normal end of Data
    return id, None, None
  sztotal = 1 
  assert RecPack.has_key(id), "Unknown record ID %i at offset %i" % (id, offset)
  if RecRepeat.has_key(id):
    sz = struct.calcsize(RecPack[id])
    init=struct.unpack_from(RecRepeat[id][1], d)
    szinit=struct.calcsize(RecRepeat[id][1])
    d=d[szinit:]
    sztotal += szinit
    res=[]
    for i in range(0, RecRepeat[id][0]):
      res.append(struct.unpack_from(RecPack[id], d))
      d=d[sz:]
      sztotal += sz
  elif type(RecPack[id]) == str:
    sz = struct.calcsize(RecPack[id])
    res = struct.unpack_from(RecPack[id], d)
    sztotal += sz
  elif type(RecPack[id]) == int: # 12-bit field array
    # A padding byte 0xFF may be present
    sz = RecPack[id] - 1
    res = ReadPacked12Bit(d[:sz])
    sztotal += sz
  return id, sztotal, res

def ReadAllRecords(mem):
  offset=0
  v=[]
  while True:
    r = ReadRecord(mem[offset:], offset)
    if r[0] == 0xff or r[0] == 0x4: # Normal end of data
      return v
    v.append(r)
    offset += r[1]

### OBSOLETE
def ReadAllStruct(mem):
  # mem may be an array, a string, or a list of packets
  #
  # Structure 3 (0x201: 658 - ~700 offset)
  # No clear fixed record sizes, oddball info?
  """ Attempt to parse a data table header"""
  if type(mem) == ndarray:
    mem= mem.tostring()
  elif type(mem) == list:
    packets = mem
    mem = AssembleDataFromPackets(packets)
    mem = mem.tostring()
  tab=Table()
  tab.s1=ReadStruct1(mem[0:110])
  offset = 106
  tab.s2=[]
  tab.s4=[]
  while True:
    s2len=750
    s2 = ReadStruct2(mem[offset:offset+s2len])
    offset += s2len
    print offset
    (s4, next) = ReadStruct4(mem[offset:])
    print offset, next
    offset += next
    if next != 0:
      tab.s2.append(s2)
      tab.s4.append(s4)
    else:
      break
  if packets != None:
    tab.fields = ReadFields(packets)
    tab.layout = []
    tab.data = []
    for r in tab.s1:
      if r[3] != 0:
        tab.layout.extend(["ID_"+str(r[1])] + [tab.fields[i] for i in r[4] if i < 42])
    for i in range(0, len(tab.s4)):
      tab.data.append([])
      for r in tab.s4[i]:
        tab.data[i].append(ReadPackedData(tab.layout, r))
  return tab

### OBSOLETE
def Struct1ToTabDelim(table):
  out=[["N","TYPE_ID","NAME","DIV"] + ["CHAN"]*8 + ["BYTES"]]
  for r in table:
    out.append([r[0], r[1], r[2], r[3]] + [x for x in r[4]] + [r[5]])
  return out

def WriteTabDelim(t,fhandle=None):
  if fhandle == None:
    fhandle=sys.stdout
  for r in t:
    for f in r:
      fhandle.write(str(f)+"\t")
    fhandle.write("\n")

### DEPRECATED
def SaveStructTabDelim2(packets,fname=None):
  table=ReadAllStruct(packets)
  if fname != None:
    # Write out
    f=open(fname,"w")
  else:
    f=sys.stdout
  WriteTabDelim( Struct1ToTabDelim(table.s1), f )
  for i in range(0, len(table.data)):
    f.write("UNK\t" + table.s2[i]['unk1'].encode('hex') + "\n") # timestamp?
    f.write(string.join(["EPOCH", "TIME"] + table.layout, "\t") + "\n")
    ts = table.s2[i]['timestamp'] # Timestamp
    tdata = [[ts + 60*y, time.ctime(ts+60*y)] + table.data[i][y] for y in range(0, len(table.data[i]))]
    WriteTabDelim( tdata, f )
    #WriteTabDelim( table.data[i], f )
  sys.stdout = f
  PrintPacket2([x for x in packets if x[12] != '\x02'],color=False)
  sys.stdout = sys.__stdout__
  if fname != None:
    f.close()
  return

def GetFields(type1Layout, type6Names):
  """Return a dictionary of field names for all record types listed in
  type1Layout"""
  fields={}
  for r in type1Layout[2]:
    fields[r[0]] = [type6Names[2][i][1].rstrip('\x00') for i in r[3:11] if i != 254]
  return fields

def RecordTable(packets):
  mem=AssembleDataFromPackets(packets)
  recs=ReadAllRecords(mem)
  assert len(recs) > 3, "No sensor data is currently on the device (or dump)"
  # We record the last encountered
  last={}
  lastTimestamp=None
  lastTimestampRow=None
  fields=None
  out=[]
  for r in recs:
    last[r[0]] = r
    # Output line if we have a 16, 17, and 18, and 19
    if len(set([16,17,18,19]) - set(last.keys())) == 0 and lastTimestamp != None:
      t = lastTimestamp + 60*(len(out) - lastTimestampRow)
      ct = time.strftime("%a %m/%d/%y %H:%M:%S", time.localtime(t))
      out.append([t, ct] + last[16][2] + last[17][2] + last[18][2] + last[19][2])
      last.pop(16)
      last.pop(17)
      last.pop(18)
      last.pop(19)
    if r[0] in set([2,3]):
      lastTimestamp = r[2][0]
      lastTimestampRow = len(out)
    elif r[0]==53:
      lastTimestamp = r[2][6]
      lastTimestampRow = len(out)
    if last.has_key(1) and last.has_key(6):
      f = GetFields(last[1], last[6])
      fields = ["EPOCH", "TIME"]
      for x in 16,17,18,19:
        fields.extend(f[x])
  return fields, out

def SaveStructTabDelim3(packets,fname=None):
  fields, records = RecordTable(packets)
  if fname != None:
    # Write out
    f=open(fname,"w")
    WriteTabDelim([fields] + records, f)
    f.close()
  else:
    WriteTabDelim([fields] + records)

def RotateListOfLists(ad):
  return [array([x[i] for x in ad[1:]]) for i in range(0,len(ad[0]))]

def ListOfListsToArray(d):
  return array([[y for y in x] for x in d],dtype='uint8')

def TestForMsbLsbPair(x1,x2):
  """A simple test to see if two one-byte columns are actual a
  two-byte integer pair.
  The test checks if x1 is an MSB and x2 is an LSB.  The test
  returns the percentage of time that the MSB value changes
  but the LSB value does NOT change.  In almost all cases, the
  LSB value should always change if the MSB value changes.

  Return value is a tuple (score, score2, nx1, nx2, n2)
  nx1 is the number of times x1 changed value
  nx2 is the number of times x2 changed value
  n2 is the number of times both x1 and x2 changed value
  score is a value between 0 and 1
  score = n2/nx1 - this should be larger than 1, since we
  don't expect more changes in the MSB than the LSB

  EXAMPLE compare an array of arrays:
  [(i,i+1) + bodylib.TestForMsbLsbPair(add[i], add[i+1]) for i in range(0,len(add)-1)]
  """
  x1d=[x for x in x1[:-1] - x1[1:]]
  x1d=array([min(abs(x),1) for x in x1d])
  x2d=[x for x in x2[:-1] - x2[1:]]
  x2d=array([min(abs(x),1) for x in x2d])
  # Number of changes in x1
  n = sum(x1d)
  nx2 = sum(x2d)
  # Number of times both x1 and x2 changed
  n2 = sum(x1d * x2d)
  if n == 0:
    return (0., 0, 0)
  else:
    return (float(n2)/float(n), float(nx2)/float(n), n, nx2, n2)

def TryAndTest(ser, packet):
  res = WriteAndReadSerialPacket(ser, packet)
  PrintPacket2(ParsePacket2(res))
  mem = MemoryDump(ser)
  HexPrintMod(mem, 2*46, skip='\xff', skip2='\x00')
  print "Mem Size: ", len(mem.tostring().rstrip('\x00').rstrip('\xff')), " Checksum: %x" % Checksum(mem.tostring())

### Main function(s) ###


def main(argv=None):
  if argv == None:
    argv=sys.argv
  if len(args) > 0:
    std.syserr.write("Error: extra arguments.  ")
 
class Usage(Exception):
  def __init__(self, msg):
    self.msg = msg

def PrintUsage(argv, fhandle=None):
  if fhandle==None:
    f=sys.stdout
  else:
    f=fhandle
  f.write( "USAGE: " + argv[0] + " [SOURCE] [TARGET] [TARGET] ...\n")
  f.write( "Retrieve and convert data from a BodyMedia armband device\n")
  f.write( "Convert from a packet source to one or more target formats\n")
  f.write( "A packet source can be a live BodyMedia USB device, a cPickle\n")
  f.write( "dump file of packets, or a capture file form a serial port sniffer.\n")
  f.write( "\nSOURCES - specify only one\n")
  f.write( "--fromSerial=<device>\t Extract data by quering a live USB device on the specified serial port\n")
  f.write( "--fromDump=<filename>\t Read packets from a cPickle dump file saved previously\n")
  f.write( "--fromFSPM=<filename>\t Parse packets from a 'Free Serial Port Monitor' by HDD Software.  <filename> is an export of the RequestView window.\n")
  f.write( "\nTARGETS - specify one or more\n")
  f.write( "--toDump=<filename>\t Write cPickle dump of all packet data\n")
  f.write( "--toCsv=<filename>\t Write a Spreadsheet-compatible tab delimited file of most of the data\n")
  f.write( "--toPackets=<filename>\t Write parsed packets in human-readable HEX format\n")
  f.write( "--toMemDump=<filename>\t Write binary dump of device memory to filename\n")
  f.write( "--toMemHex=<filename>\t Write human readable HEX dump of device memory to filename\n")
  f.write( "--toMemHexColor=<filename>\t Write human readable COLOR HEX dump of device memory (ANSI Required)\n")
  f.write(" \nNOTE: Specify '-' as a filename to output commands in order to write to stdout instead of a file\n")
  f.write( "\nACTIONS\n")
  f.write( "--clear\t Clear saved sensor data from the device\n")
  if fhandle != None:
    f.close()

def main(argv=None):
  sys.stderr.write("""THIS CODE IS DECLARED BY THE AUTHOR TO BE IN THE PUBLIC DOMAIN.\nNO WARRANTY EXPRESSED OR IMPLIED OF ANY KIND IS PROVIDED.\n""")
  if argv is None:
    argv = sys.argv
  try:
    try:
      opts, args = getopt.getopt(argv[1:], "h", ["help",
        "fromSerial=", "fromSerialFull=", "fromDump=", "fromFSPM=", "toDump=", 
        "toCsv=", "toPackets=", "toMemDump=", "toMemHex=", "toMemHexColor=", 
        "clear"])
      dopts = dict(opts)
    except getopt.error, msg:
      raise Usage(msg)
    # Check for Help
    if dopts.has_key("-h") or dopts.has_key("--help"):
      PrintUsage(argv)
      return 0
    # Sanity checks
    if dopts.has_key("--fromSerial") and dopts.has_key("--fromDump"):
      raise Usage("ERROR: Cannot have both --fromSerial and --fromDump - only one packet source")
    # Load packet source (serial or file)
    if dopts.has_key("--fromSerial"):
      ser = OpenSerial(dopts["--fromSerial"])
      packets, mem = MemoryDump(ser)
      ser.close()
    elif dopts.has_key("--fromSerialFull"):
      packets=FullSerialDump(dopts['--fromSerialFull'])
    elif dopts.has_key("--fromDump"):
      packets=cPickle.load(open(dopts['--fromDump'],"r"))
    elif dopts.has_key("--fromFSPM"):
      f=open(dopts['--fromFSPM'], "r")
      lns = ParseFile(f)
      f.close()
      packets = ParsePacket2([x[1] for x in lns])
    else:
      raise Usage("ERROR: Must provide either --fromSerial or --fromDump or other --from* packet source")
    # Write out packet data
    if dopts.has_key("--toDump"):
      cPickle.dump(packets, open(dopts['--toDump'],"w"), 2)
      print >>sys.stderr, "Wrote raw packet cPickle Dump to "+dopts['--toDump']
    if dopts.has_key("--toCsv"):
      if dopts['--toCsv'] != '-':
        SaveStructTabDelim3(packets, dopts['--toCsv'])
      else: # stdout
        SaveStructTabDelim3(packets)
      print >>sys.stderr, "Wrote tab-delimited CSV file to "+dopts['--toCsv']
    if dopts.has_key("--toPackets"):
      if dopts['--toPackets'] != '-':
        f=open(dopts['--toPackets'],"w")
        sys.stdout = f  # Kinda scary...
        PrintPacket2(packets, color=False)
        sys.stdout = sys.__stdout__
        f.close()
      else:
        PrintPacket2(packets, color=False)
    if dopts.has_key("--toMemDump"):
      f=open(dopts['--toMemDump'], "w")
      mem=AssembleDataFromPackets(packets)
      f.write(mem)
      f.close()
      print >>sys.stderr, "Wrote binary device memory dump to %s" % dopts['--toMemDump']
    if dopts.has_key("--toMemHex"):
      mem=AssembleDataFromPackets(packets)
      if dopts['--toMemHex'] != '-':
        f=open(dopts['--toMemHex'], "w")
        sys.stdout = f  # Kinda scary...
        HexPrintMod(mem, 46, skip='\xff', skip2='\x00', color=False)
        sys.stdout = sys.__stdout__
        f.close()
      else:
        HexPrintMod(mem, 46, skip='\xff', skip2='\x00', color=False)
      print >>sys.stderr, "Wrote hex device memory dump to %s" % dopts['--toMemHex']
    if dopts.has_key("--toMemHexColor"):
      mem=AssembleDataFromPackets(packets)
      if dopts['--toMemHexColor'] != '-':
        f=open(dopts['--toMemHexColor'], "w")
        sys.stdout = f  # Kinda scary...
        HexPrintMod(mem, 46, skip='\xff', skip2='\x00', color=True)
        sys.stdout = sys.__stdout__
        f.close()
      else:
        HexPrintMod(mem, 46, skip='\xff', skip2='\x00', color=True)
    if dopts.has_key("--clear"):
      # Clear device memory
      if dopts.has_key("--fromSerial"):
        fname = dopts["--fromSerial"]
      elif dopts.has_key("--fromSerialFull"):
        fname = dopts["--fromSerialFull"]
      else:
        raise Usage("ERROR: Must provide --fromSerial or --fromSerialFull to use --clear")
      ser = OpenSerial(dopts["--fromSerial"])
      ClearMemory(ser)
      print >>sys.stderr, "Cleared logged sensor data from device"
      ser.close()
  except Usage, err:
    print >>sys.stderr, err.msg
    print >>sys.stderr, "for help use --help"
    return -2
  return 0

if __name__ == "__main__":
  sys.exit(main())


