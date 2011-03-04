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

You need the BinaryParser module, developed by Jonas Raoni,
which you can get from:

	http://jsfromhell.com/classes/binary-parser/download
###

dgram  = require "dgram"
unpack = (require "./binary-parser").BinaryParser

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

# Two number persers, big-endian and litte-endian.
bigparser = new BinaryParser true,  false
litparser = new BinaryParser false, false

# The charCodeAt provide the same functionality that
# the function with the same name in Array object.
Buffer::charCodeAt = (args...) ->
	 (@toString()).charCodeAt args

# The getBytes return a slice of the buffer from a
# specific position, counting a number of bytes.
Buffer::getBytes = (from, cnt) ->
	@[from...(from+cnt)]

_decode_network_values = (ptype, plen, buf) ->
	nval = bigparser.toShort (buf.getBytes 0, SIZE_NVALUES)
	offs = SIZE_NVALUES + nval

	for dtype in (buf.getBytes SIZE_NVALUES, nval)
		do (dtype) ->
			dvals = buf.getBytes offs, 8
			offs += SIZE_DATA_VALUE
			switch dtype
				when DS_TYPE_COUNTER, DS_TYPE_ABSOLUTE then _=
						ds_type: dtype
						ds_value: (bigparser.decodeInt dvals, 64, false)
				when DS_TYPE_GAUGE then _=
						ds_type: dtype
						ds_value: (litparser.toDouble dvals)
				when DS_TYPE_DERIVE then _=
						ds_type: dtype
						ds_value: (bigparser.decodeInt dvals, 64, true)
				else
					throw new Error "unknown ds type " + dtype

decode_network_values = (ptype, plen, buf) -> _=
	type:  ptype
	value: (_decode_network_values ptype, plen, buf)

decode_network_number = (ptype, plen, buf) -> _ =
	type:  ptype
	value: (bigparser.decodeInt buf, 64, true)

decode_network_string = (ptype, plen, buf) -> _=
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

decode_network_packet = (buf, info) ->
	ret    = []
	plen   = 0
	offset = 0
	length = buf.length

	if length < SIZE_HEADER
		throw new Error "packet too short, no header."

	while (offset+=plen) < length
		ptype   = bigparser.toShort (buf.getBytes offset+0, 2)
		plen    = bigparser.toShort (buf.getBytes offset+2, 2)

		if plen > (length - offset)
			throw new Error "Packet longer than amount of data in buffer"

		if not _decoders[ptype]?
			throw new Error "Message type " + ptype + " not recognized"

		_decoders[ptype] ptype, plen-SIZE_HEADER, \
		                 (buf.slice (offset+SIZE_HEADER))


class Reader
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
					when TYPE_INTERVAL then vl.interval = data.value
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

	recv: (message, rinfo, klass) ->
		if klass.handler? then klass.objectize \
		                       (decode_network_packet message, rinfo), \
		                       klass.handler



