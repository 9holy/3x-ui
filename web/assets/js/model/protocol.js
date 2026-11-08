// Wire-format helpers shared by the legacy inbound and outbound editors.
// Keep protocol extensions when a form edits only the fields it understands.
const ProtocolUtil = {
    copy(value) {
        return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
    },

    object(value, label = 'JSON') {
        if (value === null || typeof value !== 'object' || Array.isArray(value)) {
            throw new Error(`${label} must be a JSON object`);
        }
        return value;
    },

    parse(text, label = 'JSON') {
        try {
            return this.object(JSON.parse(text || '{}'), label);
        } catch (error) {
            throw new Error(`${label}: ${error.message}`);
        }
    },

    list(value) {
        if (Array.isArray(value)) return value;
        return typeof value === 'string' && value ? value.split(',').map(v => v.trim()).filter(Boolean) : [];
    },

    host(address) {
        const host = String(address || '').replace(/^\[|\]$/g, '');
        return host.includes(':') ? `[${host}]` : host;
    },

    pinHex(value) {
        const pin = String(value || '').trim();
        if (/^[a-fA-F0-9]{64}$/.test(pin)) return pin.toLowerCase();
        try {
            const bytes = atob(pin.replace(/-/g, '+').replace(/_/g, '/'));
            if (bytes.length === 32) return Array.from(bytes, byte => byte.charCodeAt(0).toString(16).padStart(2, '0')).join('');
        } catch (_) {}
        return pin;
    },

    wireguardKeyBase64(value) {
        const key = String(value || '').trim();
        if (!key) return '';
        let bytes;
        if (/^[a-fA-F0-9]{64}$/.test(key)) {
            bytes = key.match(/../g).map(v => String.fromCharCode(parseInt(v, 16))).join('');
        } else {
            if (!/^[A-Za-z0-9+/_-]{43}=?$/.test(key)) throw new Error('WireGuard keys must contain 32 bytes');
            bytes = atob(key.replace(/-/g, '+').replace(/_/g, '/') + (key.endsWith('=') ? '' : '='));
        }
        if (bytes.length !== 32) throw new Error('WireGuard keys must contain 32 bytes');
        return btoa(bytes);
    },

    wireguardPublicKey(privateKey) {
        const key = this.wireguardKeyBase64(privateKey);
        return key ? Wireguard.generateKeypair(key).publicKey : '';
    },

    network(value) {
        return value === 'raw' ? 'tcp' : value === 'splithttp' ? 'xhttp' : value;
    },

    encrypted(settings = {}) {
        return [settings.encryption, settings.decryption].some(v => typeof v === 'string' && v !== '' && v !== 'none');
    },

    clientKey(protocol, client) {
        if (['trojan', 'masque'].includes(protocol)) return client.password;
        if (protocol === 'hysteria') return client.auth;
        if (['shadowsocks', 'tuic', 'mtproto'].includes(protocol)) return client.email;
        return client.id;
    },

    mtprotoSecret(domain = 'www.cloudflare.com') {
        const key = crypto.getRandomValues(new Uint8Array(16));
        const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
        return 'ee' + hex(key) + hex(Array.from(domain, c => c.charCodeAt(0)));
    },

    finalmask(value = {}) {
        const result = this.copy(this.object(value, 'FinalMask'));
        const qp = result.quicParams;
        if (qp) {
            for (const [old, modern] of [['up', 'brutalUp'], ['down', 'brutalDown']]) {
                if (qp[old] !== undefined && String(qp[old]) !== '0' && qp[old] !== '') {
                    if (qp[modern] === undefined) qp[modern] = String(qp[old]);
                    if (qp.congestion === undefined) qp.congestion = 'brutal';
                }
                delete qp[old];
            }
            if (qp.keepAlivePeriod === 0) delete qp.keepAlivePeriod;
            if (qp.udpHop) {
                if (qp.udpHop.ports && !(result.udp || []).some(m => m.type === 'udphop')) {
                    result.udp ||= [];
                    result.udp.push({type: 'udphop', settings: {mode: 'intervalremote', remotePorts: qp.udpHop.ports, interval: String(qp.udpHop.interval || '5-10')}});
                }
                delete qp.udpHop;
            }
            if (!Object.keys(qp).length) delete result.quicParams;
        }
        // Xray requires udpHop to be the outermost (last listed) UDP mask.
        if (Array.isArray(result.udp)) {
            const hops = result.udp.filter(m => m.type === 'udphop');
            if (hops.length) result.udp = [...result.udp.filter(m => m.type !== 'udphop'), hops[hops.length - 1]];
        }
        return result;
    },

    // `known` also includes intentionally removed/renamed keys. Those must not
    // be resurrected when an editor switches transports or certificate modes.
    retain(Type, known) {
        const read = Type.fromJson;
        const write = Type.prototype.toJson;
        Type.fromJson = function(json = {}) {
            const instance = read.call(this, json);
            if (!instance || typeof instance !== 'object') return instance;
            const extras = {};
            for (const key of Object.keys(json || {})) {
                if (!known.includes(key) && !['__proto__', 'constructor', 'prototype'].includes(key)) extras[key] = ProtocolUtil.copy(json[key]);
            }
            Object.defineProperty(instance, '_protocolExtras', {value: extras, writable: true, configurable: true});
            return instance;
        };
        Type.prototype.toJson = function() {
            return {...this._protocolExtras, ...write.call(this)};
        };
    },

    xhttp(json = {}) {
        const source = this.object(json, 'XHTTP settings');
        const extra = source.extra === undefined ? {} : this.object(source.extra, 'XHTTP extra');
        const result = {...this.copy(extra), ...this.copy(source)};
        delete result.extra;
        if (result.sessionIDPlacement === undefined && result.sessionPlacement !== undefined) result.sessionIDPlacement = result.sessionPlacement;
        if (result.sessionIDKey === undefined && result.sessionKey !== undefined) result.sessionIDKey = result.sessionKey;
        delete result.sessionPlacement;
        delete result.sessionKey;
        return result;
    },

    xhttpForClient(json) {
        const result = this.xhttp(json);
        // These settings are read by the listener, not the client dialer.
        for (const key of ['h2Params', 'serverMaxHeaderBytes', 'scMaxBufferedPosts', 'scStreamUpServerSecs']) delete result[key];
        return result;
    },

    kcpMask(finalmask, kcp) {
        const result = this.copy(finalmask || {});
        // An explicitly empty legacy seed selected AES(SHA256('')). The new
        // mask's empty value selects the original authenticator instead. Keep
        // that legacy input intact until the operator chooses a nonempty seed.
        if (kcp.legacyEmptySeed && kcp.seed === '') return result;
        let udp = Array.isArray(result.udp) ? result.udp : [];
        let rebuilding = false;
        if (udp.some(mask => mask.type === 'mkcp-legacy')) {
            if (!kcp._maskOriginal || (kcp._maskOriginal.seed === kcp.seed && kcp._maskOriginal.type === kcp.type)) return result;
            udp = udp.filter(mask => mask.type !== 'mkcp-legacy');
            rebuilding = true;
        }
        if (!rebuilding && !kcp.legacyFormat && !kcp.seed && kcp.type === 'none') return result;
        const headers = {dns: 'dns', dtls: 'dtls', srtp: 'srtp', utp: 'utp', 'wechat-video': 'wechat', wireguard: 'wireguard'};
        udp.push({type: 'mkcp-legacy', settings: {header: '', value: kcp.seed || ''}});
        if (headers[kcp.type]) udp.push({type: 'mkcp-legacy', settings: {header: headers[kcp.type], value: ''}});
        result.udp = udp;
        return result;
    },

    loadKcpMask(stream, finalmask) {
        const result = this.kcpMask(finalmask, stream.kcp);
        const headers = {dns: 'dns', dtls: 'dtls', srtp: 'srtp', utp: 'utp', wechat: 'wechat-video', wireguard: 'wireguard'};
        for (const mask of result.udp || []) {
            if (mask.type !== 'mkcp-legacy') continue;
            if (mask.settings?.header) stream.kcp.type = headers[mask.settings.header] || 'none';
            else if (mask.settings?.value) stream.kcp.seed = mask.settings.value;
        }
        Object.defineProperty(stream.kcp, '_maskOriginal', {value: {seed: stream.kcp.seed, type: stream.kcp.type}, configurable: true});
        return result;
    },

    applyLinkTransport(params, stream) {
        const wire = stream.toJson ? stream.toJson() : stream;
        const network = this.network(wire.network);
        if (network === 'xhttp') {
            const xhttp = this.xhttpForClient(wire.xhttpSettings || wire.splithttpSettings || {});
            params.set('type', 'xhttp');
            params.set('path', xhttp.path || '/');
            if (xhttp.host) params.set('host', xhttp.host);
            params.set('mode', xhttp.mode || 'auto');
            delete xhttp.path;
            delete xhttp.host;
            if (Object.keys(xhttp).length) params.set('extra', JSON.stringify(xhttp));
        }
        if (network === 'xdrive') {
            params.set('type', 'xdrive');
            params.set('extra', JSON.stringify(wire.xdriveSettings || {}));
        }
        if (wire.finalmask && Object.keys(wire.finalmask).length) params.set('fm', JSON.stringify(wire.finalmask));
    },

    applyLinkSecurity(params, stream, security = stream.security) {
        if (security === 'tls') {
            const tls = stream.tlsSettings || {};
            const client = tls.settings || tls;
            if (client.echConfigList) params.set('ech', client.echConfigList);
            if (client.verifyPeerCertByName) params.set('vcn', client.verifyPeerCertByName);
            const pins = this.list(client.pinnedPeerCertSha256);
            if (pins.length) params.set('pcs', pins.map(pin => this.pinHex(pin)).join(','));
        } else if (security === 'reality') {
            const reality = stream.realitySettings || {};
            const client = reality.settings || reality;
            if (client.mldsa65Verify) params.set('pqv', client.mldsa65Verify);
            if (client.serverName) params.set('sni', client.serverName);
        }
    },

    protocolLink(protocol, address, port, remark, client, settings = {}, stream = {}) {
        if (protocol === 'tuic' && settings.server && typeof settings.server === 'object' && !Array.isArray(settings.server)) {
            settings = {...settings.server, ...settings};
        }
        const endpoint = `${this.host(address)}:${port}`;
        const params = new URLSearchParams();
        const tls = stream.tlsSettings || {};
        const tlsClient = tls.settings || tls;
        const sni = tls.serverName || settings.serverName || settings.sni || '';
        if (protocol === 'hysteria') {
            const auth = client.auth || client.password || client.secret;
            if (!auth) return '';
            if (sni) params.set('sni', sni);
            const alpn = this.list(tls.alpn);
            if (alpn.length) params.set('alpn', alpn.join(','));
            if (tlsClient.allowInsecure) params.set('insecure', '1');
            const pins = this.list(tlsClient.pinnedPeerCertSha256);
            if (pins.length) params.set('pinSHA256', pins.map(pin => this.pinHex(pin)).join(','));
            if (tlsClient.echConfigList) params.set('ech', tlsClient.echConfigList);
            if (tlsClient.verifyPeerCertByName) params.set('vcn', tlsClient.verifyPeerCertByName);
            for (const mask of stream.finalmask?.udp || []) {
                if (mask.type === 'salamander' && mask.settings?.password) {
                    const size = String(mask.settings.packetSize || '').match(/^(\d+)-(\d+)$/);
                    params.set('obfs', size ? 'gecko' : 'salamander');
                    params.set('obfs-password', mask.settings.password);
                    if (size) { params.set('minPacketSize', size[1]); params.set('maxPacketSize', size[2]); }
                }
                if (mask.type === 'udphop' && mask.settings?.remotePorts) params.set('mport', mask.settings.remotePorts);
            }
            return `hysteria2://${encodeURIComponent(auth)}@${endpoint}/?${params}#${encodeURIComponent(remark)}`;
        }
        if (protocol === 'tuic') {
            const id = client.id || client.uuid;
            const password = client.password || client.secret;
            if (!id || !password) return '';
            if (sni) params.set('sni', sni);
            params.set('alpn', this.list(settings.alpn || tls.alpn).join(',') || 'h3');
            params.set('congestion_control', settings.congestion_control || settings.congestionControl || 'bbr');
            const relay = settings.udp_relay_mode || settings.udpRelayMode;
            if (relay) params.set('udp_relay_mode', relay);
            if (tlsClient.allowInsecure || settings.allowInsecure) params.set('allow_insecure', '1');
            return `tuic://${encodeURIComponent(id)}:${encodeURIComponent(password)}@${endpoint}/?${params}#${encodeURIComponent(remark)}`;
        }
        if (protocol === 'mtproto') {
            if (!client.secret) return '';
            params.set('server', String(address).replace(/^\[|\]$/g, ''));
            params.set('port', port);
            params.set('secret', client.secret);
            return `tg://proxy?${params}`;
        }
        return '';
    },
};
