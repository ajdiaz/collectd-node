(function() {
  /*
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
  */  var DEFAULT_IPv4_GROUP, DEFAULT_IPv4_PORT, DEFAULT_IPv6_GROUP, DEFAULT_IPv6_PORT, DS_TYPE_ABSOLUTE, DS_TYPE_COUNTER, DS_TYPE_DERIVE, DS_TYPE_GAUGE, Reader, SIZE_DATA_TYPE, SIZE_DATA_VALUE, SIZE_HEADER, SIZE_NVALUES, TYPE_HOST, TYPE_INTERVAL, TYPE_MESSAGE, TYPE_PLUGIN, TYPE_PLUGIN_INSTANCE, TYPE_SEVERITY, TYPE_TIME, TYPE_TYPE, TYPE_TYPE_INSTANCE, TYPE_VALUES, bigparser, decode_network_number, decode_network_packet, decode_network_string, decode_network_values, dgram, litparser, unpack, _decode_network_values, _decoders;
  var __slice = Array.prototype.slice, __indexOf = Array.prototype.indexOf || function(item) {
    for (var i = 0, l = this.length; i < l; i++) {
      if (this[i] === item) return i;
    }
    return -1;
  };
  dgram = require("dgram");
  unpack = (require("./binary-parser")).BinaryParser;
  DEFAULT_IPv4_PORT = 25826;
  DEFAULT_IPv6_PORT = 25826;
  DEFAULT_IPv4_GROUP = "239.192.74.66";
  DEFAULT_IPv6_GROUP = "ff18::efc0:4a42";
  TYPE_HOST = 0x0000;
  TYPE_TIME = 0x0001;
  TYPE_PLUGIN = 0x0002;
  TYPE_PLUGIN_INSTANCE = 0x0003;
  TYPE_TYPE = 0x0004;
  TYPE_TYPE_INSTANCE = 0x0005;
  TYPE_VALUES = 0x0006;
  TYPE_INTERVAL = 0x0007;
  TYPE_MESSAGE = 0x0100;
  TYPE_SEVERITY = 0x0101;
  DS_TYPE_COUNTER = 0;
  DS_TYPE_GAUGE = 1;
  DS_TYPE_DERIVE = 2;
  DS_TYPE_ABSOLUTE = 3;
  SIZE_HEADER = 4;
  SIZE_NVALUES = 2;
  SIZE_DATA_TYPE = 1;
  SIZE_DATA_VALUE = 8;
  bigparser = new BinaryParser(true, false);
  litparser = new BinaryParser(false, false);
  Buffer.prototype.charCodeAt = function() {
    var args;
    args = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
    return (this.toString()).charCodeAt(args);
  };
  Buffer.prototype.getBytes = function(from, cnt) {
    return this.slice(from, from + cnt);
  };
  _decode_network_values = function(ptype, plen, buf) {
    var dtype, nval, offs, _i, _len, _ref, _results;
    nval = bigparser.toShort(buf.getBytes(0, SIZE_NVALUES));
    offs = SIZE_NVALUES + nval;
    _ref = buf.getBytes(SIZE_NVALUES, nval);
    _results = [];
    for (_i = 0, _len = _ref.length; _i < _len; _i++) {
      dtype = _ref[_i];
      _results.push((function(dtype) {
        var dvals, _;
        dvals = buf.getBytes(offs, 8);
        offs += SIZE_DATA_VALUE;
        switch (dtype) {
          case DS_TYPE_COUNTER:
          case DS_TYPE_ABSOLUTE:
            return _ = {
              ds_type: dtype,
              ds_value: bigparser.decodeInt(dvals, 64, false)
            };
          case DS_TYPE_GAUGE:
            return _ = {
              ds_type: dtype,
              ds_value: litparser.toDouble(dvals)
            };
          case DS_TYPE_DERIVE:
            return _ = {
              ds_type: dtype,
              ds_value: bigparser.decodeInt(dvals, 64, true)
            };
          default:
            throw new Error("unknown ds type " + dtype);
        }
      })(dtype));
    }
    return _results;
  };
  decode_network_values = function(ptype, plen, buf) {
    var _;
    return _ = {
      type: ptype,
      value: _decode_network_values(ptype, plen, buf)
    };
  };
  decode_network_number = function(ptype, plen, buf) {
    var _;
    return _ = {
      type: ptype,
      value: bigparser.decodeInt(buf, 64, true)
    };
  };
  decode_network_string = function(ptype, plen, buf) {
    var _;
    return _ = {
      type: ptype,
      value: (buf.getBytes(0, plen - 1)).toString("ascii")
    };
  };
  _decoders = [];
  _decoders[TYPE_VALUES] = decode_network_values;
  _decoders[TYPE_TIME] = decode_network_number;
  _decoders[TYPE_INTERVAL] = decode_network_number;
  _decoders[TYPE_HOST] = decode_network_string;
  _decoders[TYPE_PLUGIN] = decode_network_string;
  _decoders[TYPE_PLUGIN_INSTANCE] = decode_network_string;
  _decoders[TYPE_TYPE] = decode_network_string;
  _decoders[TYPE_TYPE_INSTANCE] = decode_network_string;
  _decoders[TYPE_MESSAGE] = decode_network_string;
  _decoders[TYPE_SEVERITY] = decode_network_number;
  decode_network_packet = function(buf, info) {
    var length, offset, plen, ptype, ret, _results;
    ret = [];
    plen = 0;
    offset = 0;
    length = buf.length;
    if (length < SIZE_HEADER) {
      throw new Error("packet too short, no header.");
    }
    _results = [];
    while ((offset += plen) < length) {
      ptype = bigparser.toShort(buf.getBytes(offset + 0, 2));
      plen = bigparser.toShort(buf.getBytes(offset + 2, 2));
      if (plen > (length - offset)) {
        throw new Error("Packet longer than amount of data in buffer");
      }
      if (!(_decoders[ptype] != null)) {
        throw new Error("Message type " + ptype + " not recognized");
      }
      _results.push(_decoders[ptype](ptype, plen - SIZE_HEADER, buf.slice(offset + SIZE_HEADER)));
    }
    return _results;
  };
  Reader = (function() {
    function Reader(port, host, mcast, handler) {
      var klass, _ref, _ref2;
      this.port = port;
      this.host = host;
      this.mcast = mcast;
      this.handler = handler;
      if (typeof this.port === "function") {
        this.handler = this.port;
        this.port = null;
      }
      if (typeof this.host === "function") {
        this.handler = this.host;
        this.host = null;
      }
      if (typeof this.mcast === "function") {
        this.handler = this.mcast;
        this.mcast = null;
      }
      if (!(this.host != null)) {
        this.mcast = true;
        this.host = DEFAULT_IPv4_GROUP;
      }
      this.ipv6 = __indexOf.call(this.host, ":") >= 0;
      if (__indexOf.call(this.host, ":") >= 0) {
        (_ref = this.port) != null ? _ref : this.port = DEFAULT_IPv6_PORT;
        this.type = 'udp6';
      } else {
        (_ref2 = this.port) != null ? _ref2 : this.port = DEFAULT_IPv4_PORT;
        this.type = 'udp4';
      }
      this.socket = dgram.createSocket(this.type);
      klass = this;
      this.socket.on('message', function(message, rinfo) {
        return klass.recv(message, rinfo, klass);
      });
      this.socket.bind(this.port, this.host);
    }
    Reader.prototype.objectize = function(d, cb) {
      var data, nt, vl, _i, _len, _results;
      vl = {};
      nt = {};
      cb != null ? cb : cb = this.handler;
      _results = [];
      for (_i = 0, _len = d.length; _i < _len; _i++) {
        data = d[_i];
        _results.push((function(data) {
          switch (data.type) {
            case TYPE_TIME:
              return vl.time = nt.time = data.value;
            case TYPE_INTERVAL:
              return vl.interval = data.value;
            case TYPE_HOST:
              return vl.host = nt.host = data.value;
            case TYPE_PLUGIN:
              return vl.plugin = nt.plugin = data.value;
            case TYPE_TYPE:
              return vl.type = nt.type = data.value;
            case TYPE_SEVERITY:
              return nt.severity = data.value;
            case TYPE_TYPE_INSTANCE:
              return vl.typeinstance = nt.typeinstance = data.value;
            case TYPE_PLUGIN_INSTANCE:
              return vl.plugininstance = nt.plugininstance = data.value;
            case TYPE_MESSAGE:
              nt.message = data.value;
              return cb(nt);
            case TYPE_VALUES:
              vl.data = data.value;
              return cb(vl);
          }
        })(data));
      }
      return _results;
    };
    Reader.prototype.recv = function(message, rinfo, klass) {
      if (klass.handler != null) {
        return klass.objectize(decode_network_packet(message, rinfo), klass.handler);
      }
    };
    return Reader;
  })();
}).call(this);
