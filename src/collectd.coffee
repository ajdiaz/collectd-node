#! /usr/bin/env coffee
###
Node.js Reader for collectd protocol
------------------------------------
(c) 2011 Andres J. Diaz <ajdiaz@connectical.com>
Distributed under terms of MIT license.

Example of usage:
  var reader = require('collectd').Reader
  var server = new reader(port, host, mcast, function (data) {
    // callback
  });

The argument passed to the callback is an object which contains
the fields received in the reader. The callback will be called
once per recevied packet.
###

dgram  = require "dgram"
jspack = require("node-jspack").jspack

# Default variables
DEFAULT_IPv4_PORT  = 25826
DEFAULT_IPv6_PORT  = 25826
DEFAULT_IPv4_GROUP = "239.192.74.66"
DEFAULT_IPv6_GROUP = "ff18::efc0:4a42"

# Message kinds
TYPE_HOST            = 0x0000
TYPE_TIME            = 0x0001
TYPE_PLUGIN          = 0x0002
TYPE_PLUGIN_INSTANCE = 0x0003
TYPE_TYPE            = 0x0004
TYPE_TYPE_INSTANCE   = 0x0005
TYPE_VALUES          = 0x0006
TYPE_INTERVAL        = 0x0007
TYPE_TIME_HIRES      = 0x0008
TYPE_INTERVAL_HIRES  = 0x0009

# For notifications
TYPE_MESSAGE         = 0x0100
TYPE_SEVERITY        = 0x0101

# DS kinds
DS_TYPE_COUNTER      = 0
DS_TYPE_GAUGE        = 1
DS_TYPE_DERIVE       = 2
DS_TYPE_ABSOLUTE     = 3

# Size of fields in bytes
SIZE_HEADER          = 4
SIZE_NVALUES         = 2
SIZE_DATA_TYPE       = 1
SIZE_DATA_VALUE      = 8

# The charCodeAt provide the same functionality that
# the function with the same name in Array object.
Buffer::charCodeAt = (args...) ->
   (@toString()).charCodeAt args

# The getBytes return a slice of the buffer from a
# specific position, counting a number of bytes.
Buffer::getBytes = (from, cnt) ->
  @[from...(from+cnt)]

# Read a big-endian 64bit int from the buffer.
# Note that javascript can only hold up to 53bits, so
# this number will be inaccurate for large values.
Buffer::readInt64 = (signed) ->
  [upper, lower] = jspack.Unpack(signed and "!lL" or "!LL", @)
  (upper << 32) + lower

_decode_network_values = (ptype, plen, buf) ->
  [nval] = jspack.Unpack('H', buf)
  offs = SIZE_NVALUES + nval

  for dtype in (buf.getBytes SIZE_NVALUES, nval)
    do (dtype) ->
      dvals = buf.getBytes offs, 8
      offs += SIZE_DATA_VALUE
      switch dtype
        when DS_TYPE_COUNTER, DS_TYPE_ABSOLUTE then _=
            ds_type: dtype == DS_TYPE_COUNTER and 'counter' or 'absolute'
            ds_value: dvals.readInt64(false)
        when DS_TYPE_GAUGE then _=
            ds_type: 'gauge'
            ds_value: jspack.Unpack("<d", dvals)[0]
        when DS_TYPE_DERIVE then _=
            ds_type: 'derive'
            ds_value: dvals.readInt64(true)
        else
          throw new Error "unknown ds type " + dtype

decode_network_values = (ptype, plen, buf) ->
  type:  ptype
  value: (_decode_network_values ptype, plen, buf)

decode_network_time = (ptype, plen, buf) ->
  [upper, lower] = jspack.Unpack("!LL", buf)
  type:  ptype
  value: (upper << 2) + (lower >> 30)

decode_network_number = (ptype, plen, buf) ->
  type:  ptype
  value: buf.readInt64(true)

decode_network_string = (ptype, plen, buf) ->
  type:  ptype
  value: (buf.getBytes 0, plen-1).toString("ascii")

# Mapping of message types to decoding functions.
_decoders = []
_decoders[TYPE_VALUES]          = decode_network_values
_decoders[TYPE_TIME]            = decode_network_number
_decoders[TYPE_INTERVAL]        = decode_network_number
_decoders[TYPE_HOST]            = decode_network_string
_decoders[TYPE_PLUGIN]          = decode_network_string
_decoders[TYPE_PLUGIN_INSTANCE] = decode_network_string
_decoders[TYPE_TYPE]            = decode_network_string
_decoders[TYPE_TYPE_INSTANCE]   = decode_network_string
_decoders[TYPE_MESSAGE]         = decode_network_string
_decoders[TYPE_SEVERITY]        = decode_network_number
_decoders[TYPE_TIME_HIRES]      = decode_network_time
_decoders[TYPE_INTERVAL_HIRES]  = decode_network_time

decode_network_packet = (buf, info) ->
  ret    = []
  plen   = 0
  offset = 0
  length = buf.length

  if length < SIZE_HEADER
    throw new Error "packet too short, no header."

  while (offset+=plen) < length
    [ptype, plen] = jspack.Unpack 'HH', buf.getBytes(offset, 4)

    if plen > (length - offset)
      throw new Error "Packet longer than amount of data in buffer"

    if not _decoders[ptype]?
      throw new Error "Message type #{ptype} not recognized"

    _decoders[ptype] ptype, plen-SIZE_HEADER, \
                     (buf.slice (offset+SIZE_HEADER))


class @Reader
  constructor: (@port, @host, @mcast, @handler) ->
    if typeof @port is "function"
      @handler = @port
      @port = null

    if typeof @host is "function"
      @handler = @host
      @host = null

    if typeof @mcast is "function"
      @handler = @mcast
      @mcast = null

    if not @host?
      @mcast = true
      @host  = DEFAULT_IPv4_GROUP

    @ipv6 = ":" in @host
    if ":" in @host
      @port ?= DEFAULT_IPv6_PORT
      @type  = 'udp6'
    else
      @port ?= DEFAULT_IPv4_PORT
      @type  = 'udp4'

    @socket = dgram.createSocket @type

    klass = this
    @socket.on('message', (message, rinfo) ->
        klass.recv message, rinfo, klass)

    @socket.bind(@port, @host)

  # The objectize function is used internally to return a readable object,
  # instead of a number of variables in an Array.
  objectize: (d, cb) ->
    vl = {}
    nt = {}
    cb ?= @handler

    for data in d
      do (data) ->
        switch data.type
          when TYPE_TIME then vl.time = nt.time = data.value
          when TYPE_TIME_HIRES then vl.time = nt.time = data.value
          when TYPE_INTERVAL then vl.interval = data.value
          when TYPE_INTERVAL_HIRES then vl.interval = data.value
          when TYPE_HOST then vl.host = nt.host = data.value
          when TYPE_PLUGIN then vl.plugin = nt.plugin = data.value
          when TYPE_TYPE then vl.type = nt.type = data.value
          when TYPE_SEVERITY then nt.severity = data.value
          when TYPE_TYPE_INSTANCE then vl.typeinstance = nt.typeinstance = data.value
          when TYPE_PLUGIN_INSTANCE then vl.plugininstance = nt.plugininstance = data.value
          when TYPE_MESSAGE
            nt.message = data.value
            cb nt
          when TYPE_VALUES
            vl.data = data.value
            cb vl
          else
            console.log("unknown data type #{data.type}")

  recv: (message, rinfo, klass) ->
    if klass.handler? then klass.objectize \
                           (decode_network_packet message, rinfo), \
                           klass.handler

