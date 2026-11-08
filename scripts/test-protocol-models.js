const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const root = path.resolve(__dirname, '..');
function model(name) {
    const context = vm.createContext({console, URL, URLSearchParams, crypto: webcrypto,
        window: {crypto: webcrypto, location: {hostname: 'panel.example'}}, location: {hostname: 'panel.example'},
        Base64: {encode: v => Buffer.from(v, 'utf8').toString('base64'), decode: v => Buffer.from(v, 'base64').toString('utf8')},
        btoa: v => Buffer.from(v, 'binary').toString('base64'), atob: v => Buffer.from(v, 'base64').toString('binary')});
    for (const file of ['util/common.js', 'util/utils.js', 'model/protocol.js', `model/${name}.js`, ...(name === 'xray' ? ['model/dbinbound.js'] : [])]) {
        vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js', file), 'utf8'), context, {filename: file});
    }
    return code => {
        const result = vm.runInContext(code, context);
        return result === undefined ? undefined : JSON.parse(JSON.stringify(result));
    };
}
const incoming = model('xray');
const outgoing = model('outbound');
const uuid = '11111111-1111-4111-8111-111111111111';

test('both editors can construct default streams and protocol objects', () => {
    assert.equal(incoming('new Inbound().toJson().protocol'), 'vless');
    assert.equal(outgoing('new Outbound().toJson().protocol'), 'vmess');
    assert.equal(outgoing('new StreamSettings().toJson().network'), 'tcp');
});

test('HY2 import decodes credentials once and keeps IPv6, SNI, ALPN and standard obfs/hop', () => {
    const link = 'hy2://user%3Apa%40ss%2Fword@[2001:db8::1]:8443/?sni=cert.example&alpn=h3&obfs=salamander&obfs-password=obfs%26secret&mport=8443-8453#name%2520literal';
    const result = outgoing(`Outbound.fromLink(${JSON.stringify(link)}).toJson()`);
    assert.equal(result.tag, 'name%20literal');
    assert.deepEqual(result.settings, {address: '2001:db8::1', port: 8443, version: 2});
    assert.equal(result.streamSettings.security, 'tls');
    assert.equal(result.streamSettings.hysteriaSettings.auth, 'user:pa@ss/word');
    assert.equal(result.streamSettings.tlsSettings.serverName, 'cert.example');
    assert.deepEqual(result.streamSettings.tlsSettings.alpn, ['h3']);
    assert.equal(result.streamSettings.finalmask.udp[0].settings.password, 'obfs&secret');
    assert.equal(result.streamSettings.finalmask.udp[1].settings.remotePorts, '8443-8453');
});

test('HY2 always has its QUIC transport and TLS, including protocol selector changes', () => {
    const result = outgoing('(() => { const o=new Outbound(); o.protocol=Protocols.Hysteria; return o.toJson(); })()');
    assert.equal(result.streamSettings.network, 'hysteria');
    assert.equal(result.streamSettings.security, 'tls');
    assert.deepEqual(result.streamSettings.tlsSettings.alpn, ['h3']);
    assert.equal(result.streamSettings.tlsSettings.fingerprint, '');
    assert.equal(result.streamSettings.hysteriaSettings.udpIdleTimeout, 60);
});

test('HY2 accepts a default port and rejects malformed links without crashing', () => {
    assert.equal(outgoing('Outbound.fromLink("hysteria2://secret@node.example").toJson().settings.port'), 443);
    for (const link of ['hysteria2://@node.example:443', 'hysteria2://%GG@node.example:443', 'vmess://notjson', 'vless://x@h:1?type=xhttp&extra=[]']) {
        assert.equal(outgoing(`Outbound.fromLink(${JSON.stringify(link)})`), null);
    }
});

test('inbound XHTTP advanced fields and legacy session aliases survive an edit', () => {
    const wire = {protocol: 'vless', port: 443, settings: {clients: [{id: uuid}], decryption: 'none', encryption: 'mlkem768x25519plus.native.0rtt.public'},
        streamSettings: {network: 'splithttp', splithttpSettings: {path: '/x', host: 'cdn.example', mode: 'packet-up', sessionPlacement: 'cookie', sessionKey: 'session', xPaddingKey: 'padding', h2Params: {maxReadFrameSize: 16384}, xmux: {maxConcurrency: '16-32', maxConnections: 0}}}};
    const result = incoming(`(() => {const i=Inbound.fromJson(${JSON.stringify(wire)}); i.port=8443; return i.toJson();})()`);
    assert.equal(result.streamSettings.network, 'xhttp');
    assert.equal(result.streamSettings.xhttpSettings.sessionIDPlacement, 'cookie');
    assert.equal(result.streamSettings.xhttpSettings.sessionIDKey, 'session');
    assert.equal(result.streamSettings.xhttpSettings.sessionKey, undefined);
    assert.deepEqual(result.streamSettings.xhttpSettings.h2Params, {maxReadFrameSize: 16384});
    assert.equal(result.settings.encryption, wire.settings.encryption);
});

test('VLESS XHTTP encryption, vision and ML-DSA are included in client links', () => {
    const wire = {protocol: 'vless', port: 443, settings: {clients: [{id: uuid, flow: 'xtls-rprx-vision'}], encryption: 'mlkem768x25519plus.native.0rtt.public', decryption: 'none'},
        streamSettings: {network: 'xhttp', security: 'reality', xhttpSettings: {path: '/x', host: 'cdn.example', mode: 'packet-up', sessionIDKey: 'sid', h2Params: {maxReadFrameSize: 16384}},
            realitySettings: {target: 'target.example:443', serverNames: ['cert.example'], shortIds: ['abcd'], privateKey: 'PRIVATE', settings: {publicKey: 'PUBLIC', mldsa65Verify: 'VERIFY', fingerprint: 'chrome'}}}};
    const link = incoming(`(() => {const i=Inbound.fromJson(${JSON.stringify(wire)});return i.genLink('2001:db8::1',443,'same','test',i.clients[0]);})()`);
    const url = new URL(link);
    assert.equal(url.hostname, '[2001:db8::1]');
    assert.equal(url.searchParams.get('encryption'), wire.settings.encryption);
    assert.equal(url.searchParams.get('flow'), 'xtls-rprx-vision');
    assert.equal(url.searchParams.get('pqv'), 'VERIFY');
    assert.equal(url.searchParams.get('path'), '/x');
    assert.equal(JSON.parse(url.searchParams.get('extra')).sessionIDKey, 'sid');
    assert.equal(JSON.parse(url.searchParams.get('extra')).h2Params, undefined);
    assert.ok(!link.includes('PRIVATE'));
    const outbound = outgoing(`Outbound.fromLink(${JSON.stringify(link)}).toJson()`);
    assert.equal(outbound.settings.vnext[0].users[0].encryption, wire.settings.encryption);
    assert.equal(outbound.streamSettings.realitySettings.mldsa65Verify, 'VERIFY');
    assert.equal(outbound.streamSettings.xhttpSettings.sessionIDKey, 'sid');
});

test('VLESS vision is disabled on XDRIVE and enabled with encryption on XHTTP', () => {
    assert.equal(incoming('(() => {let i=new Inbound(); i.stream.network="xhttp"; i.settings.encryption="mlkem.key"; return i.canEnableTlsFlow();})()'), true);
    assert.equal(incoming('(() => {let i=new Inbound(); i.stream.network="xdrive"; i.settings.encryption="mlkem.key"; return i.canEnableTlsFlow();})()'), false);
});

test('REALITY target, version gates and fallback limits survive form serialization', () => {
    const value = {dest: 'target.example:443', minClientVer: '26.9.9', maxClientVer: '26.10.31', mldsa65Seed: 'SEED', limitFallbackUpload: {afterBytes: 10, bytesPerSec: 50}, settings: {mldsa65Verify: 'VERIFY'}};
    const result = incoming(`RealityStreamSettings.fromJson(${JSON.stringify(value)}).toJson()`);
    assert.equal(result.target, value.dest);
    assert.equal(result.minClientVer, value.minClientVer);
    assert.equal(result.maxClientVer, value.maxClientVer);
    assert.equal(result.mldsa65Seed, value.mldsa65Seed);
    assert.deepEqual(result.limitFallbackUpload, value.limitFallbackUpload);
    assert.equal(result.settings.mldsa65Verify, 'VERIFY');
});

test('TLS CA-only certificates and modern TLS client/server fields survive', () => {
    const value = {certificates: [{usage: 'verify', certificate: ['CA']}], echServerKeys: 'SERVER', curvePreferences: ['X25519MLKEM768'], settings: {echConfigList: 'CLIENT', pinnedPeerCertSha256: ['a'.repeat(64)], verifyPeerCertByName: 'cert.example'}};
    const result = incoming(`TlsStreamSettings.fromJson(${JSON.stringify(value)}).toJson()`);
    assert.equal(result.certificates[0].usage, 'verify');
    assert.deepEqual(result.certificates[0].certificate, ['CA']);
    assert.equal(result.echServerKeys, 'SERVER');
    assert.equal(result.settings.echConfigList, 'CLIENT');
    assert.deepEqual(result.curvePreferences, value.curvePreferences);
    assert.equal(result.settings.verifyPeerCertByName, 'cert.example');
});

test('mKCP seed and header move to ordered masks and remain editable after reload', () => {
    for (const run of [incoming, outgoing]) {
        const result = run('StreamSettings.fromJson({network:"kcp",kcpSettings:{header:{type:"wechat-video"},seed:"my-seed",cwndMultiplier:2}}).toJson()');
        assert.equal(result.kcpSettings.seed, undefined);
        assert.equal(result.kcpSettings.header, undefined);
        assert.equal(result.kcpSettings.cwndMultiplier, 2);
        assert.deepEqual(result.finalmask.udp, [{type: 'mkcp-legacy', settings: {header: '', value: 'my-seed'}}, {type: 'mkcp-legacy', settings: {header: 'wechat', value: ''}}]);
        const edited = run(`(() => {const s=StreamSettings.fromJson(${JSON.stringify(result)}); s.kcp.seed='updated'; return s.toJson();})()`);
        assert.equal(edited.finalmask.udp[0].settings.value, 'updated');
    }
});

test('advanced XDRIVE and unknown transport fields are preserved', () => {
    for (const run of [incoming, outgoing]) {
        const result = run('StreamSettings.fromJson({network:"xdrive",xdriveSettings:{service:"s3",s3:{bucket:"bucket"},xmux:{maxConnections:3}},customTransportField:{value:7}}).toJson()');
        assert.equal(result.xdriveSettings.s3.bucket, 'bucket');
        assert.equal(result.xdriveSettings.xmux.maxConnections, 3);
        assert.deepEqual(result.customTransportField, {value: 7});
    }
});

test('mKCP preserves missing-seed legacy, explicit-empty-seed and modern wire semantics', () => {
    for (const run of [incoming, outgoing]) {
        const legacy = run('StreamSettings.fromJson({network:"kcp",kcpSettings:{header:{type:"srtp"}}}).toJson()');
        assert.deepEqual(legacy.finalmask.udp, [{type:'mkcp-legacy',settings:{header:'',value:''}}, {type:'mkcp-legacy',settings:{header:'srtp',value:''}}]);
        const modern = run('StreamSettings.fromJson({network:"kcp",kcpSettings:{mtu:1350}}).toJson()');
        assert.equal(modern.finalmask, undefined);
        const empty = run('StreamSettings.fromJson({network:"kcp",kcpSettings:{seed:"",header:{type:"srtp"}}}).toJson()');
        assert.equal(empty.kcpSettings.seed, '');
        assert.equal(empty.finalmask, undefined);
        const edited = run('(() => {const s=StreamSettings.fromJson({network:"kcp",kcpSettings:{seed:"",header:{type:"srtp"}}}); s.kcp.seed="chosen"; return s.toJson();})()');
        assert.equal(edited.kcpSettings.seed, undefined);
        assert.equal(edited.finalmask.udp[0].settings.value, 'chosen');
    }
});

test('removed H2/QUIC transports remain readable without dropping saved parameters', () => {
    for (const run of [incoming, outgoing]) {
        const h2 = run('StreamSettings.fromJson({network:"http",httpSettings:{host:["h.example"],path:"/old",read_idle_timeout:7}}).toJson()');
        assert.equal(h2.network, 'http');
        assert.equal(h2.httpSettings.path, '/old');
        assert.equal(h2.httpSettings.read_idle_timeout, 7);
        const quic = run('StreamSettings.fromJson({network:"quic",quicSettings:{security:"aes-128-gcm",key:"secret",header:{type:"srtp"}}}).toJson()');
        assert.equal(quic.network, 'quic');
        assert.equal(quic.quicSettings.key, 'secret');
        assert.equal(quic.quicSettings.header.type, 'srtp');
    }
});

test('HY2 pins normalize base64 and base64url SHA256 values to hex', () => {
    const bytes = Buffer.alloc(32, 255);
    for (const pin of [bytes.toString('base64'), bytes.toString('base64url'), bytes.toString('hex').toUpperCase()]) {
        const link = incoming(`ProtocolUtil.protocolLink('hysteria','node.example',443,'test',{auth:'password'},{},{tlsSettings:{settings:{pinnedPeerCertSha256:[${JSON.stringify(pin)}]}}})`);
        assert.equal(new URL(link).searchParams.get('pinSHA256'), bytes.toString('hex'));
    }
});

test('TLS certificate name and pin lists use native string fields for outbounds', () => {
    const result = outgoing('TlsStreamSettings.fromJson({verifyPeerCertByName:["a.example","b.example"],pinnedPeerCertSha256:["a","b"]}).toJson()');
    assert.equal(result.verifyPeerCertByName, 'a.example,b.example');
    assert.equal(result.pinnedPeerCertSha256, 'a,b');
});

test('native protocol JSON cannot be silently saved as an array or null', () => {
    for (const text of ['null', '[]', '42', '"text"']) {
        assert.throws(() => incoming(`(() => {const i=new Inbound();i.protocol=Protocols.HYSTERIA;i.rawSettingsText=${JSON.stringify(text)};return i.toJson();})()`), /must be a JSON object/);
    }
});

test('new HY2 defaults and panel share links preserve raw settings and TLS properties', () => {
    const result = incoming('(() => {const i=new Inbound();i.protocol=Protocols.HYSTERIA;return i.toJson();})()');
    assert.equal(result.settings.version, 2);
    assert.ok(result.settings.clients[0].auth.length > 10);
    assert.equal(result.streamSettings.security, 'tls');
    const wire = {protocol: 'hysteria', port: 8443, settings: {version: 2, clients: [{auth: 'p@ss:word', email: 'e', enable: true}]}, streamSettings: {network: 'hysteria', security: 'tls', tlsSettings: {serverName: 'cert.example', alpn: ['h3'], settings: {pinnedPeerCertSha256: ['a'.repeat(64)]}}, finalmask: {udp: [{type: 'salamander', settings: {password: 'obfs&secret'}}]}}};
    const link = incoming(`(() => {const i=Inbound.fromJson(${JSON.stringify(wire)});return i.genLink('2001:db8::1',8443,'same','test name',i.clients[0]);})()`);
    const parsed = new URL(link);
    assert.equal(decodeURIComponent(parsed.username), 'p@ss:word');
    assert.equal(parsed.searchParams.get('sni'), 'cert.example');
    assert.equal(parsed.searchParams.get('pinSHA256'), 'a'.repeat(64));
    assert.equal(parsed.searchParams.get('obfs-password'), 'obfs&secret');
});

test('TUIC link uses configured SNI, ALPN, congestion and relay mode', () => {
    const result = incoming(`ProtocolUtil.protocolLink('tuic','2001:db8::2',443,'remark',{id:${JSON.stringify(uuid)},password:'p:@s'},{serverName:'cert.example',alpn:['h3','custom'],congestion_control:'cubic',udp_relay_mode:'quic'},{})`);
    const url = new URL(result);
    assert.equal(decodeURIComponent(url.password), 'p:@s');
    assert.equal(url.searchParams.get('sni'), 'cert.example');
    assert.equal(url.searchParams.get('alpn'), 'h3,custom');
    assert.equal(url.searchParams.get('congestion_control'), 'cubic');
    assert.equal(url.searchParams.get('udp_relay_mode'), 'quic');
});

test('TUIC links read nested server options and respect explicit top-level overrides', () => {
    const settings = {server:{sni:'nested.example',alpn:['custom-h3'],congestion_control:'cubic',udp_relay_mode:'quic'}};
    const nested = incoming(`ProtocolUtil.protocolLink('tuic','node.example',443,'test',{id:'id',password:'password'},${JSON.stringify(settings)},{})`);
    const query = new URL(nested).searchParams;
    assert.equal(query.get('sni'), 'nested.example');
    assert.equal(query.get('alpn'), 'custom-h3');
    assert.equal(query.get('congestion_control'), 'cubic');
    assert.equal(query.get('udp_relay_mode'), 'quic');
    const override = incoming(`ProtocolUtil.protocolLink('tuic','node.example',443,'test',{id:'id',password:'password'},${JSON.stringify({...settings,sni:'top.example',alpn:['top-h3'],congestion_control:''})},{})`);
    assert.equal(new URL(override).searchParams.get('sni'), 'top.example');
    assert.equal(new URL(override).searchParams.get('alpn'), 'top-h3');
    assert.equal(new URL(override).searchParams.get('congestion_control'), 'bbr');
});

test('unknown protocols, multiple endpoints and newer VLESS user fields survive outbound JSON edits', () => {
    const wire = {protocol: 'vless', settings: {vnext: [{address: 'first.example', port: 443, users: [{id: uuid, encryption: 'mlkem.public', reverse: {tag: 'rev'}, testseed: [1,2,3]}]}, {address: 'second.example', port: 8443, users: [{id: uuid, encryption: 'none'}]}]}, streamSettings: {network: 'tcp'}};
    const result = outgoing(`(() => {const o=Outbound.fromJson(${JSON.stringify(wire)});o.settings.port=1443;return o.toJson();})()`);
    assert.equal(result.settings.vnext[0].port, 1443);
    assert.deepEqual(result.settings.vnext[0].users[0].reverse, {tag: 'rev'});
    assert.deepEqual(result.settings.vnext[0].users[0].testseed, [1,2,3]);
    assert.equal(result.settings.vnext[1].address, 'second.example');
    assert.deepEqual(outgoing('Outbound.fromJson({protocol:"loopback",settings:{inboundTag:"other",sniffing:{enabled:true}}}).toJson().settings'), {inboundTag: 'other', sniffing: {enabled: true}});
});

test('new protocol clients expose lifecycle fields and protocol-specific API keys', () => {
    for (const [protocol, key] of [['hysteria','auth'], ['masque','password'], ['mtproto','email'], ['tuic','email']]) {
        const result = incoming(`(() => { const client=new Inbound.ProtocolClient(${JSON.stringify(protocol)}); client._totalGB=2; client._expiryTime=12345; return {client:client.toJson(), key:ProtocolUtil.clientKey(${JSON.stringify(protocol)},client), text:client.toString()};})()`);
        assert.equal(result.key, result.client[key]);
        assert.equal(result.client.totalGB, 2 * 1024 ** 3);
        assert.equal(result.client.expiryTime, 12345);
        assert.equal(JSON.parse(result.text).email, result.client.email);
        if (protocol === 'mtproto') assert.match(result.client.secret, /^ee[0-9a-f]{32}7777772e636c6f7564666c6172652e636f6d$/);
        if (protocol === 'tuic') assert.match(result.client.id, /^[0-9a-f-]{36}$/);
    }
});

test('raw client records keep custom credentials and remain editable client models', () => {
    const wire = {protocol: 'tuic', port: 443, settings: {clients: [{uuid, email: 'client@example', password: 'p:@s', enable: true, customOption: 7}], certificate: '/cert', private_key: '/key'}};
    const result = incoming(`(() => {const i=Inbound.fromJson(${JSON.stringify(wire)});const c=i.clients[0];c.password='new';return {key:ProtocolUtil.clientKey(i.protocol,c),json:JSON.parse(c.toString())};})()`);
    assert.equal(result.key, 'client@example');
    assert.equal(result.json.password, 'new');
    assert.equal(result.json.customOption, 7);
});

test('editing imported client aliases emits only current canonical credentials', () => {
    const tuic = incoming('(() => {const c=Inbound.ProtocolClient.fromJson(Protocols.TUIC,{uuid:"old-id",secret:"old-secret",email:"client"});c.id="edited-id";c.password="edited-secret";return c.toJson();})()');
    assert.equal(tuic.id, 'edited-id');
    assert.equal(tuic.password, 'edited-secret');
    assert.equal(tuic.uuid, undefined);
    assert.equal(tuic.secret, undefined);
    assert.equal(tuic._protocol, undefined);
    const masque = incoming('(() => {const c=Inbound.ProtocolClient.fromJson(Protocols.MASQUE,{pass:"old-pass",email:"client"});c.password="edited-pass";return c.toJson();})()');
    assert.equal(masque.password, 'edited-pass');
    assert.equal(masque.pass, undefined);
    const hy2 = incoming('(() => {const c=Inbound.ProtocolClient.fromJson(Protocols.HYSTERIA,{password:"old-password",secret:"old-secret",email:"client"});c.auth="edited-auth";return c.toJson();})()');
    assert.equal(hy2.auth, 'edited-auth');
    assert.equal(hy2.password, undefined);
    assert.equal(hy2.secret, undefined);
});

test('native raw users maps stay JSON-editable without exposing incompatible client dialogs', () => {
    const native = incoming('(() => {const db=new DBInbound({protocol:"tuic",settings:JSON.stringify({users:{"legacy-uuid":"password"},certificate:"cert.pem",private_key:"key.pem"})});return {multi:db.isMultiUser(),link:db.hasLink(),settings:db.toInbound().toJson().settings};})()');
    assert.equal(native.multi, false);
    assert.equal(native.link, false);
    assert.deepEqual(native.settings.users, {'legacy-uuid':'password'});
    assert.equal(incoming('new DBInbound({protocol:"tuic",settings:JSON.stringify({clients:[]})}).isMultiUser()'), true);
});

test('legacy HY2 tuning moves to supported finalmask keys and UDP hop is last', () => {
    const result = outgoing('StreamSettings.fromJson({network:"hysteria",security:"tls",hysteriaSettings:{auth:"secret",up:"100 Mbps",down:"200 Mbps",keepAlivePeriod:0,udphop:{port:"9000-9010",interval:30}},finalmask:{udp:[{type:"salamander",settings:{password:"p"}}]}}).toJson()');
    assert.equal(result.hysteriaSettings.up, undefined);
    assert.equal(result.finalmask.quicParams.brutalUp, '100 Mbps');
    assert.equal(result.finalmask.quicParams.brutalDown, '200 Mbps');
    assert.equal(result.finalmask.quicParams.congestion, 'brutal');
    assert.equal(result.finalmask.quicParams.keepAlivePeriod, undefined);
    assert.equal(result.finalmask.udp.at(-1).type, 'udphop');
});

test('XDRIVE never produces a misleading generic share URI', () => {
    assert.equal(incoming(`(() => {const i=new Inbound();i.stream.network='xdrive';return i.genLink('node.example',443,'same','test',i.clients[0]);})()`), '');
});

test('frontend-generated configurations are accepted by the selected Xray runtime', {skip: !process.env.XRAY_BINARY}, () => {
    const {execFileSync} = require('node:child_process');
    const os = require('node:os');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), '3x-ui-protocol-'));
    const fixtures = [
        outgoing(`Outbound.fromLink('hysteria2://pass@example.com:443/?sni=cert.example&obfs=salamander&obfs-password=secret&mport=443-453').toJson()`),
        outgoing(`Outbound.fromLink('vless://${uuid}@example.com:443?type=xhttp&security=tls&path=%2Fx&mode=packet-up&sni=cert.example').toJson()`),
        outgoing(`Outbound.fromLink('vless://${uuid}@127.0.0.1:443?type=kcp&headerType=wechat-video&seed=seed').toJson()`),
        outgoing(`Outbound.fromJson({protocol:'masque',settings:{address:'example.com',port:443},streamSettings:{network:'masque',security:'tls',tlsSettings:{serverName:'example.com',alpn:['h3']},masqueSettings:{user:'client',pass:'password'}}}).toJson()`),
        outgoing(`Outbound.fromJson({protocol:'vmess',settings:{vnext:[{address:'example.com',port:443,users:[{id:'${uuid}',security:'auto'}]}]},streamSettings:{network:'ws',security:'tls',tlsSettings:{serverName:'example.com'},wsSettings:{path:'/test'}}}).toJson()`),
    ];
    try {
        for (let i=0;i<fixtures.length;i++) {
            const filename = path.join(dir, `${i}.json`);
            fs.writeFileSync(filename, JSON.stringify({log:{loglevel:'none'}, outbounds:[fixtures[i]]}));
            execFileSync(process.env.XRAY_BINARY, ['run', '-test', '-c', filename], {encoding: 'utf8', stdio: 'pipe'});
        }
    } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test('Tunnel reads both field generations and gives modern values precedence', () => {
    for (const protocol of ['tunnel', 'dokodemo-door']) {
        const wire = incoming(`Inbound.fromJson({protocol:'${protocol}',settings:{address:'old.example',port:80,network:'udp',rewriteAddress:'new.example',rewritePort:8080,allowedNetwork:'tcp',followRedirect:true,customOption:7}}).toJson()`);
        assert.equal(wire.settings.rewriteAddress, 'new.example');
        assert.equal(wire.settings.rewritePort, 8080);
        assert.equal(wire.settings.allowedNetwork, 'tcp');
        assert.equal(wire.settings.customOption, 7);
        assert.equal(wire.settings.address, undefined);
        const legacy = incoming(`Inbound.fromJson({protocol:'${protocol}',settings:{address:'old.example',port:80,network:'udp'}}).toJson()`);
        assert.equal(legacy.settings.rewriteAddress, 'old.example');
        assert.equal(legacy.settings.rewritePort, 80);
        assert.equal(legacy.settings.allowedNetwork, 'udp');
    }
});

test('HTTP, Mixed and WireGuard accept empty imported account and peer lists', () => {
    for (const protocol of ['http', 'mixed', 'socks']) {
        assert.doesNotThrow(() => incoming(`Inbound.fromJson({protocol:'${protocol}',settings:{auth:'password'}}).toJson()`));
    }
    assert.deepEqual(incoming('Inbound.WireguardSettings.fromJson({}).toJson().peers'), []);
    assert.deepEqual(outgoing('Outbound.WireguardSettings.fromJson({}).toJson().peers'), []);
});

test('all TLS outbounds and URI pin fields use the core SHA256 hex representation', () => {
    const raw = Buffer.alloc(32, 255);
    for (const pin of [raw.toString('base64'), raw.toString('base64url'), raw.toString('hex').toUpperCase()]) {
        const wire = outgoing(`TlsStreamSettings.fromJson({pinnedPeerCertSha256:[${JSON.stringify(pin)}]}).toJson()`);
        assert.equal(wire.pinnedPeerCertSha256, raw.toString('hex'));
        const encoded = incoming(`(() => { const p=new URLSearchParams(); ProtocolUtil.applyLinkSecurity(p,{security:'tls',tlsSettings:{settings:{pinnedPeerCertSha256:[${JSON.stringify(pin)}]}}});return p.get('pcs'); })()`);
        assert.equal(encoded, raw.toString('hex'));
    }
});

test('WireGuard preserves stored client private keys and derives RFC7748 public keys', () => {
    const privateHex = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
    const publicHex = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
    const privateBase64 = Buffer.from(privateHex, 'hex').toString('base64');
    const publicBase64 = Buffer.from(publicHex, 'hex').toString('base64');
    for (const key of [privateHex, privateBase64, Buffer.from(privateHex,'hex').toString('base64url')]) {
        const record = incoming(`Inbound.WireguardSettings.Peer.fromJson({privateKey:${JSON.stringify(key)},allowedIPs:['10.0.0.2','fd00::2']}).toJson()`);
        assert.equal(record.privateKey, privateBase64);
        assert.equal(record.publicKey, publicBase64);
        assert.deepEqual(record.allowedIPs, ['10.0.0.2/32', 'fd00::2/128']);
    }
    const conf = incoming(`(() => {const i=Inbound.fromJson({protocol:'wireguard',settings:{secretKey:'${privateHex}',peers:[{privateKey:'${privateHex}',preSharedKey:'${privateHex}',allowedIPs:['10.0.0.2/32','fd00::2/128']}]}});return i.getWireguardLink('2001:db8::1',51820,'wireguard',0);})()`);
    assert.match(conf, /Endpoint = \[2001:db8::1\]:51820/);
    assert.ok(conf.includes('PublicKey = '+publicBase64));
    assert.ok(conf.includes('PrivateKey = '+privateBase64));
    assert.ok(conf.includes('PresharedKey = '+privateBase64));
    assert.match(conf, /Address = 10\.0\.0\.2\/32, fd00::2\/128/);
});

test('unlimited inbound expiry is not incorrectly displayed as expired', () => {
    assert.equal(incoming('new DBInbound({expiryTime:0}).isExpiry'), false);
    assert.equal(incoming('new DBInbound({expiryTime:-86400000}).isExpiry'), false);
    assert.equal(incoming('new DBInbound({expiryTime:1}).isExpiry'), true);
});

test('database inbound reopening preserves non-default allocation settings', () => {
    const allocate = {strategy: 'random', refresh: 13, concurrency: 2};
    for (const protocol of ['vless', 'hysteria']) {
        const wire = incoming(`new DBInbound({protocol:${JSON.stringify(protocol)},settings:'{"clients":[]}',allocate:${JSON.stringify(JSON.stringify(allocate))}}).toInbound().toJson()`);
        assert.deepEqual(wire.allocate, allocate);
    }
    assert.deepEqual(incoming('new DBInbound({protocol:"vless",settings:"{}"}).toInbound().toJson().allocate'), {strategy: 'always', refresh: 5, concurrency: 3});
});
