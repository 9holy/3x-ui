const Protocols = {
    Freedom: "freedom",
    Blackhole: "blackhole",
    DNS: "dns",
    VMess: "vmess",
    VLESS: "vless",
    Trojan: "trojan",
    Shadowsocks: "shadowsocks",
    Socks: "socks",
    HTTP: "http",
    Wireguard: "wireguard",
    Hysteria: "hysteria",
    Masque: "masque",
    Loopback: "loopback"
};

const SSMethods = {
    AES_256_GCM: 'aes-256-gcm',
    AES_128_GCM: 'aes-128-gcm',
    CHACHA20_POLY1305: 'chacha20-poly1305',
    CHACHA20_IETF_POLY1305: 'chacha20-ietf-poly1305',
    XCHACHA20_POLY1305: 'xchacha20-poly1305',
    XCHACHA20_IETF_POLY1305: 'xchacha20-ietf-poly1305',
    BLAKE3_AES_128_GCM: '2022-blake3-aes-128-gcm',
    BLAKE3_AES_256_GCM: '2022-blake3-aes-256-gcm',
    BLAKE3_CHACHA20_POLY1305: '2022-blake3-chacha20-poly1305',
};

const TLS_FLOW_CONTROL = {
    VISION: "xtls-rprx-vision",
    VISION_UDP443: "xtls-rprx-vision-udp443",
};

const UTLS_FINGERPRINT = {
    UTLS_CHROME: "chrome",
    UTLS_FIREFOX: "firefox",
    UTLS_SAFARI: "safari",
    UTLS_IOS: "ios",
    UTLS_android: "android",
    UTLS_EDGE: "edge",
    UTLS_360: "360",
    UTLS_QQ: "qq",
    UTLS_RANDOM: "random",
    UTLS_RANDOMIZED: "randomized",
    UTLS_RANDOMIZED_NO_ALPN: "randomizednoalpn",
    UTLS_UNSAFE: "unsafe",
};

const ALPN_OPTION = {
    H3: "h3",
    H2: "h2",
    HTTP1: "http/1.1",
};

const OutboundDomainStrategies = [
    "AsIs",
    "UseIP",
    "UseIPv4",
    "UseIPv6",
    "UseIPv6v4",
    "UseIPv4v6",
    "ForceIP",
    "ForceIPv6v4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv4"
];

const WireguardDomainStrategy = [
    "ForceIP",
    "ForceIPv4",
    "ForceIPv4v6",
    "ForceIPv6",
    "ForceIPv6v4"
];

const USERS_SECURITY = {
    AES_128_GCM: "aes-128-gcm",
    CHACHA20_POLY1305: "chacha20-poly1305",
    AUTO: "auto",
    NONE: "none",
    ZERO: "zero",
};

Object.freeze(Protocols);
Object.freeze(SSMethods);
Object.freeze(TLS_FLOW_CONTROL);
Object.freeze(UTLS_FINGERPRINT);
Object.freeze(ALPN_OPTION);
Object.freeze(OutboundDomainStrategies);
Object.freeze(WireguardDomainStrategy);
Object.freeze(USERS_SECURITY);


class CommonClass {

    static toJsonArray(arr) {
        return arr.map(obj => obj.toJson());
    }

    static fromJson() {
        return new CommonClass();
    }

    toJson() {
        return this;
    }

    toString(format = true) {
        return format ? JSON.stringify(this.toJson(), null, 2) : JSON.stringify(this.toJson());
    }
}

class TcpStreamSettings extends CommonClass {
    constructor(type = 'none', host, path) {
        super();
        this.type = type;
        this.host = host;
        this.path = path;
    }

    static fromJson(json = {}) {
        let header = json.header;
        if (!header) return new TcpStreamSettings();
        if (header.type == 'http' && header.request) {
            return new TcpStreamSettings(
                header.type,
                header.request.headers.Host.join(','),
                header.request.path.join(','),
            );
        }
        return new TcpStreamSettings(header.type, '', '');
    }

    toJson() {
        return {
            header: {
                type: this.type,
                request: this.type === 'http' ? {
                    headers: {
                        Host: ObjectUtil.isEmpty(this.host) ? [] : this.host.split(',')
                    },
                    path: ObjectUtil.isEmpty(this.path) ? ["/"] : this.path.split(',')
                } : undefined,
            }
        };
    }
}

class KcpStreamSettings extends CommonClass {
    constructor(
        mtu = 1350,
        tti = 50,
        uplinkCapacity = 5,
        downlinkCapacity = 20,
        congestion = false,
        readBufferSize = 2,
        writeBufferSize = 2,
        type = 'none',
        seed = RandomUtil.randomSeq(10),
    ) {
        super();
        this.mtu = mtu;
        this.tti = tti;
        this.upCap = uplinkCapacity;
        this.downCap = downlinkCapacity;
        this.congestion = congestion;
        this.readBuffer = readBufferSize;
        this.writeBuffer = writeBufferSize;
        this.type = type;
        this.seed = seed;
        this.legacyFormat = true;
        this.cwndMultiplier = 1;
        this.maxSendingWindow = 2097152;
    }

    static fromJson(json = {}) {
        const result = new KcpStreamSettings(json.mtu, json.tti, json.uplinkCapacity, json.downlinkCapacity,
            json.congestion, json.readBufferSize, json.writeBufferSize, json.header?.type || 'none', json.seed ?? '');
        result.cwndMultiplier = json.cwndMultiplier ?? 1;
        result.maxSendingWindow = json.maxSendingWindow ?? 2097152;
        result.legacyEmptySeed = Object.prototype.hasOwnProperty.call(json, 'seed') && json.seed === '';
        result.legacyFormat = ['seed', 'header', 'congestion', 'readBufferSize', 'writeBufferSize'].some(key => Object.prototype.hasOwnProperty.call(json, key));
        return result;
    }
    toJson() {
        return {mtu: this.mtu, tti: this.tti, uplinkCapacity: this.upCap, downlinkCapacity: this.downCap,
            ...(this.legacyEmptySeed && this.seed === '' ? {seed: '', header: {type: this.type}} : {}),
            cwndMultiplier: this.cwndMultiplier, maxSendingWindow: this.maxSendingWindow};
    }
}

class WsStreamSettings extends CommonClass {
    constructor(path = '/', host = '') {
        super();
        this.path = path;
        this.host = host;
    }

    static fromJson(json = {}) {
        return new WsStreamSettings(
            json.path,
            json.host,
        );
    }

    toJson() {
        return {
            path: this.path,
            host: this.host,
        };
    }
}

class HttpStreamSettings extends CommonClass {
    constructor(path = '/', host = '') {
        super();
        this.path = path;
        this.host = host;
    }

    static fromJson(json = {}) {
        return new HttpStreamSettings(
            json.path,
            ProtocolUtil.list(json.host).join(','),
        );
    }

    toJson() {
        return {
            path: this.path,
            host: ObjectUtil.isEmpty(this.host) ? [''] : this.host.split(','),
        }
    }
}

class QuicStreamSettings extends CommonClass {
    constructor(
        security = 'none',
        key = '',
        type = 'none'
    ) {
        super();
        this.security = security;
        this.key = key;
        this.type = type;
    }

    static fromJson(json = {}) {
        return new QuicStreamSettings(
            json.security,
            json.key,
            json.header ? json.header.type : 'none',
        );
    }

    toJson() {
        return {
            security: this.security,
            key: this.key,
            header: {
                type: this.type,
            }
        }
    }
}

class GrpcStreamSettings extends CommonClass {
    constructor(
        serviceName = "",
        authority = "",
        multiMode = false
    ) {
        super();
        this.serviceName = serviceName;
        this.authority = authority;
        this.multiMode = multiMode;
    }

    static fromJson(json = {}) {
        return new GrpcStreamSettings(json.serviceName, json.authority, json.multiMode);
    }

    toJson() {
        return {
            serviceName: this.serviceName,
            authority: this.authority,
            multiMode: this.multiMode
        }
    }
}

class HttpUpgradeStreamSettings extends CommonClass {
    constructor(path = '/', host = '') {
        super();
        this.path = path;
        this.host = host;
    }

    static fromJson(json = {}) {
        return new HttpUpgradeStreamSettings(
            json.path,
            json.host,
        );
    }

    toJson() {
        return {
            path: this.path,
            host: this.host,
        };
    }
}

class SplitHTTPStreamSettings extends CommonClass {
    constructor(path = '/', host = '') {
        super();
        this.path = path;
        this.host = host;
    }

    static fromJson(json = {}) {
        return new SplitHTTPStreamSettings(
            json.path,
            json.host,
        );
    }

    toJson() {
        return {
            path: this.path,
            host: this.host,
        };
    }
}

class XHTTPStreamSettings extends CommonClass {
    constructor(path = '/', host = '', mode = 'auto', extra = {}) {
        super();
        this.path = path;
        this.host = host;
        this.mode = mode;
        this.extraText = JSON.stringify(extra, null, 2);
    }
    static fromJson(json = {}) {
        const extra = ProtocolUtil.xhttp(json);
        const {path, host, mode} = extra;
        delete extra.path; delete extra.host; delete extra.mode;
        return new XHTTPStreamSettings(path, host, mode, extra);
    }
    toJson() {
        const extra = ProtocolUtil.xhttp(ProtocolUtil.parse(this.extraText, 'XHTTP advanced settings'));
        if (!['auto', 'packet-up', 'stream-up', 'stream-one'].includes(this.mode)) throw new Error('Invalid XHTTP mode');
        if (extra.xmux && Number(extra.xmux.maxConnections) > 0 && extra.xmux.maxConcurrency && extra.xmux.maxConcurrency !== '0') {
            throw new Error('XMUX maxConcurrency and maxConnections cannot both be set');
        }
        return {...extra, path: this.path, host: this.host, mode: this.mode};
    }
}

class TlsStreamSettings extends CommonClass {
    constructor(serverName = '', alpn = [], fingerprint = '', allowInsecure = false) {
        super();
        this.serverName = serverName; this.alpn = alpn; this.fingerprint = fingerprint;
        this.allowInsecure = allowInsecure;
        this.echConfigList = ''; this.pinnedPeerCertSha256 = []; this.verifyPeerCertByName = '';
    }
    static fromJson(json = {}) {
        const result = new TlsStreamSettings(json.serverName, json.alpn, json.fingerprint, json.allowInsecure);
        result.echConfigList = json.echConfigList || '';
        result.pinnedPeerCertSha256 = ProtocolUtil.list(json.pinnedPeerCertSha256);
        result.verifyPeerCertByName = ProtocolUtil.list(json.verifyPeerCertByName).join(',');
        return result;
    }
    toJson() {
        return {serverName: this.serverName, alpn: this.alpn, fingerprint: this.fingerprint,
            echConfigList: this.echConfigList || undefined,
            pinnedPeerCertSha256: ProtocolUtil.list(this.pinnedPeerCertSha256).join(',') || undefined,
            verifyPeerCertByName: ProtocolUtil.list(this.verifyPeerCertByName).join(',') || undefined};
    }
}

class RealityStreamSettings extends CommonClass {
    constructor(publicKey = '', fingerprint = 'chrome', serverName = '', shortId = '', spiderX = '/', mldsa65Verify = '') {
        super();
        this.publicKey = publicKey; this.fingerprint = fingerprint; this.serverName = serverName;
        this.shortId = shortId; this.spiderX = spiderX; this.mldsa65Verify = mldsa65Verify;
    }
    static fromJson(json = {}) {
        return new RealityStreamSettings(json.publicKey || json.password, json.fingerprint, json.serverName, json.shortId, json.spiderX, json.mldsa65Verify);
    }
    toJson() {
        return {publicKey: this.publicKey, fingerprint: this.fingerprint, serverName: this.serverName,
            shortId: this.shortId, spiderX: this.spiderX, mldsa65Verify: this.mldsa65Verify || undefined};
    }
}

class HysteriaStreamSettings extends CommonClass {
    constructor(version = 2, auth = '', udpIdleTimeout = 60, masquerade) {
        super();
        this.version = 2; this.auth = auth; this.udpIdleTimeout = udpIdleTimeout; this.masquerade = masquerade;
    }
    static fromJson(json = {}) {
        return new HysteriaStreamSettings(2, json.auth, json.udpIdleTimeout, json.masquerade);
    }
    toJson() {
        if (!Number.isInteger(this.udpIdleTimeout) || this.udpIdleTimeout < 2 || this.udpIdleTimeout > 600) throw new Error('Hysteria UDP idle timeout must be 2–600 seconds');
        return {version: 2, auth: this.auth, udpIdleTimeout: this.udpIdleTimeout, masquerade: this.masquerade};
    }
}

class SockoptStreamSettings extends CommonClass {
    constructor(
        dialerProxy = "",
        tcpFastOpen = false,
        tcpKeepAliveInterval = 0,
        tcpMptcp = false,
        tcpNoDelay = false
    ) {
        super();
        this.dialerProxy = dialerProxy;
        this.tcpFastOpen = tcpFastOpen;
        this.tcpKeepAliveInterval = tcpKeepAliveInterval;
        this.tcpMptcp = tcpMptcp;
        this.tcpNoDelay = tcpNoDelay;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return undefined;
        return new SockoptStreamSettings(
            json.dialerProxy,
            json.tcpFastOpen,
            json.tcpKeepAliveInterval,
            json.tcpMptcp,
            json.tcpNoDelay,
        );
    }

    toJson() {
        return {
            dialerProxy: this.dialerProxy,
            tcpFastOpen: this.tcpFastOpen,
            tcpKeepAliveInterval: this.tcpKeepAliveInterval,
            tcpMptcp: this.tcpMptcp,
            tcpNoDelay: this.tcpNoDelay,
        };
    }
}

class StreamSettings extends CommonClass {
    constructor(
        network = 'tcp',
        security = 'none',
        tlsSettings = new TlsStreamSettings(),
        realitySettings = new RealityStreamSettings(),
        tcpSettings = new TcpStreamSettings(),
        kcpSettings = new KcpStreamSettings(),
        wsSettings = new WsStreamSettings(),
        httpSettings = new HttpStreamSettings(),
        quicSettings = new QuicStreamSettings(),
        grpcSettings = new GrpcStreamSettings(),
        httpupgradeSettings = new HttpUpgradeStreamSettings(),
        splithttpSettings = new SplitHTTPStreamSettings(),
        xhttpSettings = new XHTTPStreamSettings(),
        hysteriaSettings = new HysteriaStreamSettings(),
        sockopt = undefined,
    ) {
        super();
        this.network = ProtocolUtil.network(network);
        this.security = security;
        this.tls = tlsSettings;
        this.reality = realitySettings;
        this.tcp = tcpSettings;
        this.kcp = kcpSettings;
        this.ws = wsSettings;
        this.http = httpSettings;
        this.quic = quicSettings;
        this.grpc = grpcSettings;
        this.httpupgrade = httpupgradeSettings;
        this.splithttp = splithttpSettings;
        this.xhttp = xhttpSettings;
        this.hysteria = hysteriaSettings;
        this.masqueText = '{}';
        this.xdriveText = '{}';
        this.finalMaskText = '{}';
        this.sockopt = sockopt;
    }

    get isTls() {
        return this.security === 'tls';
    }

    get isReality() {
        return this.security === "reality";
    }

    get sockoptSwitch() {
        return this.sockopt != undefined;
    }

    set sockoptSwitch(value) {
        this.sockopt = value ? new SockoptStreamSettings() : undefined;
    }

    static fromJson(json = {}) {
        const result = new StreamSettings(
            json.network, json.security, TlsStreamSettings.fromJson(json.tlsSettings), RealityStreamSettings.fromJson(json.realitySettings),
            TcpStreamSettings.fromJson(json.tcpSettings || json.rawSettings), KcpStreamSettings.fromJson(json.kcpSettings),
            WsStreamSettings.fromJson(json.wsSettings), HttpStreamSettings.fromJson(json.httpSettings), QuicStreamSettings.fromJson(json.quicSettings),
            GrpcStreamSettings.fromJson(json.grpcSettings), HttpUpgradeStreamSettings.fromJson(json.httpupgradeSettings),
            SplitHTTPStreamSettings.fromJson(json.splithttpSettings), XHTTPStreamSettings.fromJson(json.xhttpSettings || json.splithttpSettings),
            HysteriaStreamSettings.fromJson(json.hysteriaSettings), SockoptStreamSettings.fromJson(json.sockopt),
        );
        result.masqueText = JSON.stringify(json.masqueSettings || {}, null, 2);
        result.xdriveText = JSON.stringify(json.xdriveSettings || {}, null, 2);
        const finalmask = ProtocolUtil.copy(json.finalmask || {});
        // Preserve bandwidth/window tuning from pre-finalmask Hysteria configs.
        const legacy = json.hysteriaSettings || {};
        const quicKeys = ['up','down','initStreamReceiveWindow','maxStreamReceiveWindow','initConnectionReceiveWindow','maxConnectionReceiveWindow','maxIdleTimeout','keepAlivePeriod','disablePathMTUDiscovery'];
        for (const key of quicKeys) {
            if (legacy[key] !== undefined) {
                finalmask.quicParams ||= {};
                if (finalmask.quicParams[key] === undefined) finalmask.quicParams[key] = legacy[key];
            }
        }
        if (legacy.udphop?.port && !(finalmask.udp || []).some(m => m.type === 'udphop')) {
            finalmask.udp ||= [];
            finalmask.udp.push({type: 'udphop', settings: {mode: 'intervalremote', remotePorts: legacy.udphop.port,
                interval: String(legacy.udphop.interval || '5-10')}});
        }
        result.finalMaskText = JSON.stringify(result.network === 'kcp' ? ProtocolUtil.loadKcpMask(result, finalmask) : finalmask, null, 2);
        return result;
    }
    toJson() {
        const network = ProtocolUtil.network(this.network);
        let finalmask = ProtocolUtil.finalmask(ProtocolUtil.parse(this.finalMaskText, 'FinalMask'));
        if (network === 'kcp') finalmask = ProtocolUtil.kcpMask(finalmask, this.kcp);
        if (this.isReality && Object.keys(finalmask).length) throw new Error('REALITY cannot be combined with FinalMask');
        return {
            network, security: this.security,
            tlsSettings: this.isTls ? this.tls.toJson() : undefined,
            realitySettings: this.isReality ? this.reality.toJson() : undefined,
            tcpSettings: network === 'tcp' ? this.tcp.toJson() : undefined,
            kcpSettings: network === 'kcp' ? this.kcp.toJson() : undefined,
            wsSettings: network === 'ws' ? this.ws.toJson() : undefined,
            httpSettings: network === 'http' ? this.http.toJson() : undefined,
            quicSettings: network === 'quic' ? this.quic.toJson() : undefined,
            grpcSettings: network === 'grpc' ? this.grpc.toJson() : undefined,
            httpupgradeSettings: network === 'httpupgrade' ? this.httpupgrade.toJson() : undefined,
            xhttpSettings: network === 'xhttp' ? this.xhttp.toJson() : undefined,
            hysteriaSettings: network === 'hysteria' ? this.hysteria.toJson() : undefined,
            masqueSettings: network === 'masque' ? ProtocolUtil.parse(this.masqueText, 'MASQUE settings') : undefined,
            xdriveSettings: network === 'xdrive' ? ProtocolUtil.parse(this.xdriveText, 'XDRIVE settings') : undefined,
            finalmask: Object.keys(finalmask).length ? finalmask : undefined,
            sockopt: this.sockopt?.toJson(),
        };
    }
}

class Mux extends CommonClass {
    constructor(enabled = false, concurrency = 8, xudpConcurrency = 16, xudpProxyUDP443 = "reject") {
        super();
        this.enabled = enabled;
        this.concurrency = concurrency;
        this.xudpConcurrency = xudpConcurrency;
        this.xudpProxyUDP443 = xudpProxyUDP443;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return undefined;
        return new Mux(
            json.enabled,
            json.concurrency,
            json.xudpConcurrency,
            json.xudpProxyUDP443,
        );
    }

    toJson() {
        return {
            enabled: this.enabled,
            concurrency: this.concurrency,
            xudpConcurrency: this.xudpConcurrency,
            xudpProxyUDP443: this.xudpProxyUDP443,
        };
    }
}

class Outbound extends CommonClass {
    constructor(
        tag = '',
        protocol = Protocols.VMess,
        settings = null,
        streamSettings = new StreamSettings(),
        sendThrough,
        mux = new Mux(),
    ) {
        super();
        this.tag = tag;
        this._protocol = protocol;
        this.settings = settings == null ? Outbound.Settings.getSettings(protocol) : settings;
        this.stream = streamSettings;
        this.sendThrough = sendThrough;
        this.mux = mux || new Mux();
        this.normalizeProtocol();
    }

    get protocol() {
        return this._protocol;
    }

    set protocol(protocol) {
        this._protocol = protocol;
        this.settings = Outbound.Settings.getSettings(protocol);
        this.stream = new StreamSettings();
        this.normalizeProtocol();
    }

    normalizeProtocol() {
        if ([Protocols.Hysteria, Protocols.Masque].includes(this.protocol)) {
            this.stream.network = this.protocol;
            this.stream.security = 'tls';
            if (!this.stream.tls.alpn.length) this.stream.tls.alpn = ['h3'];
            if (this.protocol === Protocols.Hysteria) this.stream.tls.fingerprint = '';
        }
    }

    canEnableTls() {
        if ([Protocols.Hysteria, Protocols.Masque].includes(this.protocol)) return true;
        if (![Protocols.VMess, Protocols.VLESS, Protocols.Trojan, Protocols.Shadowsocks].includes(this.protocol)) return false;
        return ["tcp", "ws", "http", "grpc", "httpupgrade", "splithttp", "xhttp", "xdrive"].includes(this.stream.network);
    }

    canEnableTlsFlow() {
        if (this.protocol !== Protocols.VLESS || this.stream.network === 'xdrive') return false;
        return (this.stream.network === 'tcp' && ['tls','reality'].includes(this.stream.security)) || ProtocolUtil.encrypted(this.settings);
    }

    canEnableReality() {
        if (![Protocols.VLESS, Protocols.Trojan].includes(this.protocol)) return false;
        return ["tcp", "http", "grpc", "xhttp", "splithttp"].includes(this.stream.network);
    }

    canEnableStream() {
        return [Protocols.VMess, Protocols.VLESS, Protocols.Trojan, Protocols.Shadowsocks, Protocols.Hysteria, Protocols.Masque, Protocols.Wireguard].includes(this.protocol);
    }

    canEnableMux() {
        if (this.settings.flow && this.settings.flow != '') {
            this.mux.enabled = false;
            return false;
        }
        return [Protocols.VMess, Protocols.VLESS, Protocols.Trojan, Protocols.Shadowsocks, Protocols.HTTP, Protocols.Socks].includes(this.protocol);
    }

    hasVnext() {
        return [Protocols.VMess, Protocols.VLESS].includes(this.protocol);
    }

    hasServers() {
        return [Protocols.Trojan, Protocols.Shadowsocks, Protocols.Socks, Protocols.HTTP].includes(this.protocol);
    }

    hasAddressPort() {
        return [
            Protocols.DNS,
            Protocols.VMess,
            Protocols.VLESS,
            Protocols.Trojan,
            Protocols.Shadowsocks,
            Protocols.Socks,
            Protocols.HTTP,
            Protocols.Hysteria,
            Protocols.Masque
        ].includes(this.protocol);
    }

    hasUsername() {
        return [Protocols.Socks, Protocols.HTTP].includes(this.protocol);
    }

    static fromJson(json = {}) {
        return new Outbound(
            json.tag,
            json.protocol,
            Outbound.Settings.fromJson(json.protocol, json.settings),
            StreamSettings.fromJson(json.streamSettings),
            json.sendThrough,
            Mux.fromJson(json.mux),
        )
    }

    toJson() {
        this.normalizeProtocol();
        var stream;
        if (this.canEnableStream()) {
            stream = this.stream.toJson();
        } else {
            if (this.stream?.sockopt)
                stream = { sockopt: this.stream.sockopt.toJson() };
        }
        return {
            tag: this.tag == '' ? undefined : this.tag,
            protocol: this.protocol,
            settings: this.settings instanceof CommonClass ? this.settings.toJson() : this.settings,
            streamSettings: stream,
            sendThrough: this.sendThrough != "" ? this.sendThrough : undefined,
            mux: this.mux?.enabled ? this.mux : undefined,
        };
    }

    static fromLink(link) {
        try {
            const scheme = String(link).split('://')[0].toLowerCase();
            if (scheme === 'vmess') return this.fromVmessLink(JSON.parse(Base64.decode(link.substring(link.indexOf('://') + 3))));
            if (['vless','trojan','ss'].includes(scheme)) return this.fromParamLink(link);
            if (['hysteria2','hy2'].includes(scheme)) return this.fromHysteriaLink(link);
        } catch (_) {
            // Malformed imported data must not take down the outbound editor.
        }
        return null;
    }

    static fromVmessLink(json = {}) {
        let stream = new StreamSettings(ProtocolUtil.network(json.net), json.tls);

        let network = json.net;
        if (network === 'tcp') {
            stream.tcp = new TcpStreamSettings(
                json.type,
                json.host ?? '',
                json.path ?? '');
        } else if (network === 'kcp') {
            stream.kcp = new KcpStreamSettings();
            stream.kcp.type = json.type;
            stream.kcp.seed = json.path;
        } else if (network === 'ws') {
            stream.ws = new WsStreamSettings(json.path, json.host);
        } else if (network === 'http' || network == 'h2') {
            stream.network = 'http'
            stream.http = new HttpStreamSettings(
                json.path,
                json.host);
        } else if (network === 'grpc') {
            stream.grpc = new GrpcStreamSettings(json.path, json.authority, json.type == 'multi');
        } else if (network === 'httpupgrade') {
            stream.httpupgrade = new HttpUpgradeStreamSettings(json.path, json.host);
        } else if (network === 'splithttp' || network === 'xhttp') {
            stream.xhttp = XHTTPStreamSettings.fromJson({...json.extra, path: json.path, host: json.host, mode: json.mode});
        }

        if (json.tls && json.tls == 'tls') {
            stream.tls = new TlsStreamSettings(
                json.sni,
                json.alpn ? json.alpn.split(',') : [],
                json.fp,
                json.allowInsecure);
        }

        if (json.fm) stream.finalMaskText = JSON.stringify(typeof json.fm === 'string' ? ProtocolUtil.parse(json.fm, 'FinalMask') : json.fm, null, 2);
        stream.tls.echConfigList = json.ech || '';
        stream.tls.pinnedPeerCertSha256 = ProtocolUtil.list(json.pcs);
        stream.tls.verifyPeerCertByName = json.vcn || '';
        const port = json.port * 1;

        return new Outbound(json.ps, Protocols.VMess, new Outbound.VmessSettings(json.add, port, json.id, json.scy), stream);
    }

    static fromParamLink(link) {
        const url = new URL(link);
        const p = url.searchParams;
        const protocol = url.protocol.slice(0, -1) === 'ss' ? Protocols.Shadowsocks : url.protocol.slice(0, -1);
        const network = ProtocolUtil.network(p.get('type') || 'tcp');
        const security = p.get('security') || 'none';
        const stream = new StreamSettings(network, security);
        const host = p.get('host') || '';
        const path = p.get('path') || '';
        if (network === 'tcp' || network === 'none') stream.tcp = new TcpStreamSettings(p.get('headerType') || 'none', host, path);
        if (network === 'kcp') { stream.kcp.type = p.get('headerType') || 'none'; stream.kcp.seed = p.get('seed') || path; }
        if (network === 'ws') stream.ws = new WsStreamSettings(path, host);
        if (network === 'http' || network === 'h2') { stream.network = 'http'; stream.http = new HttpStreamSettings(path, host); }
        if (network === 'grpc') stream.grpc = new GrpcStreamSettings(p.get('serviceName') || '', p.get('authority') || '', p.get('mode') === 'multi');
        if (network === 'httpupgrade') stream.httpupgrade = new HttpUpgradeStreamSettings(path, host);
        if (network === 'xhttp') {
            const extra = p.has('extra') ? ProtocolUtil.parse(p.get('extra'), 'XHTTP extra') : {};
            const stringKeys = ['xPaddingBytes','xPaddingKey','xPaddingHeader','xPaddingPlacement','xPaddingMethod','sessionIDPlacement','sessionIDKey','sessionIDTable','sessionIDLength','sessionPlacement','sessionKey','seqPlacement','seqKey','uplinkDataPlacement','uplinkDataKey','scMaxEachPostBytes','scMinPostsIntervalMs','scStreamUpServerSecs','uplinkHTTPMethod'];
            for (const key of stringKeys) if (p.has(key)) extra[key] = p.get(key);
            for (const key of ['noSSEHeader','noGRPCHeader','xPaddingObfsMode']) if (p.has(key)) extra[key] = ['1','true'].includes(p.get(key));
            for (const key of ['scMaxBufferedPosts','serverMaxHeaderBytes','uplinkChunkSize']) if (p.has(key)) extra[key] = Number(p.get(key));
            stream.xhttp = XHTTPStreamSettings.fromJson({...extra, path: path || '/', host, mode: p.get('mode') || extra.mode || 'auto'});
        }
        if (network === 'xdrive' && p.has('extra')) stream.xdriveText = JSON.stringify(ProtocolUtil.parse(p.get('extra'), 'XDRIVE settings'), null, 2);
        if (p.has('fm')) stream.finalMaskText = JSON.stringify(ProtocolUtil.parse(p.get('fm'), 'FinalMask'), null, 2);
        if (security === 'tls') {
            stream.tls = TlsStreamSettings.fromJson({serverName: p.get('sni') || '', alpn: ProtocolUtil.list(p.get('alpn')),
                fingerprint: p.get('fp') || '', echConfigList: p.get('ech') || '', pinnedPeerCertSha256: ProtocolUtil.list(p.get('pcs')),
                verifyPeerCertByName: p.get('vcn') || ''});
        }
        if (security === 'reality') stream.reality = new RealityStreamSettings(p.get('pbk') || '', p.get('fp') || 'chrome', p.get('sni') || '', p.get('sid') || '', p.get('spx') || '/', p.get('pqv') || '');
        const address = url.hostname.replace(/^\[|\]$/g, '');
        const port = Number(url.port || 443);
        if (!address || !port) return null;
        let settings;
        if (protocol === Protocols.VLESS) settings = new Outbound.VLESSSettings(address, port, decodeURIComponent(url.username), p.get('flow') || '', p.get('encryption') || 'none');
        else if (protocol === Protocols.Trojan) settings = new Outbound.TrojanSettings(address, port, decodeURIComponent(url.username) + (url.password ? ':' + decodeURIComponent(url.password) : ''));
        else if (protocol === Protocols.Shadowsocks) {
            let userinfo = decodeURIComponent(url.username);
            if (url.password) userinfo += ':' + decodeURIComponent(url.password);
            else userinfo = Base64.decode(userinfo);
            const split = userinfo.indexOf(':');
            if (split < 1) return null;
            settings = new Outbound.ShadowsocksSettings(address, port, userinfo.slice(split + 1), userinfo.slice(0, split), true);
        } else return null;
        const remark = decodeURIComponent(url.hash.slice(1)) || `out-${protocol}-${port}`;
        return new Outbound(remark, protocol, settings, stream);
    }

    static fromHysteriaLink(link) {
        const url = new URL(link);
        if (!['hysteria2:', 'hy2:'].includes(url.protocol)) return null;
        const address = url.hostname.replace(/^\[|\]$/g, '');
        const port = Number(url.port || 443);
        const auth = decodeURIComponent(url.username) + (url.password ? ':' + decodeURIComponent(url.password) : '');
        if (!address || !auth || !port) return null;
        const p = url.searchParams;
        const stream = new StreamSettings('hysteria', 'tls');
        stream.hysteria.auth = auth;
        stream.tls = TlsStreamSettings.fromJson({serverName: p.get('sni') || '', alpn: ProtocolUtil.list(p.get('alpn') || 'h3'),
            fingerprint: '', echConfigList: p.get('ech') || '', pinnedPeerCertSha256: ProtocolUtil.list(p.get('pinSHA256')),
            verifyPeerCertByName: p.get('vcn') || ''});
        const finalmask = p.has('fm') ? ProtocolUtil.parse(p.get('fm'), 'FinalMask') : {};
        const obfs = (p.get('obfs') || '').toLowerCase();
        const password = p.get('obfs-password') || p.get('obfs_password') || p.get('obfsPassword');
        if (['salamander','gecko'].includes(obfs) && password && !(finalmask.udp || []).some(m => m.type === 'salamander')) {
            const settings = {password};
            if (obfs === 'gecko') {
                const min = Number(p.get('minPacketSize')), max = Number(p.get('maxPacketSize'));
                if (Number.isInteger(min) && min >= 1 && Number.isInteger(max) && max >= min && max <= 2048) settings.packetSize = `${min}-${max}`;
            }
            finalmask.udp ||= [];
            finalmask.udp.push({type: 'salamander', settings});
        }
        const ports = p.get('mport') || p.get('udphopPort');
        if (ports && !(finalmask.udp || []).some(m => m.type === 'udphop')) {
            finalmask.udp ||= [];
            finalmask.udp.push({type: 'udphop', settings: {mode: 'intervalremote', remotePorts: ports, interval: p.get('udphopInterval') || '5-10'}});
        }
        for (const key of ['up','down']) if (p.has(key)) { finalmask.quicParams ||= {}; finalmask.quicParams[key] = p.get(key); }
        stream.finalMaskText = JSON.stringify(finalmask, null, 2);
        return new Outbound(decodeURIComponent(url.hash.slice(1)) || `out-hysteria-${port}`, Protocols.Hysteria, new Outbound.HysteriaSettings(address, port, 2), stream);
    }

}

Outbound.Settings = class extends CommonClass {
    constructor(protocol) {
        super();
        this.protocol = protocol;
    }

    static getSettings(protocol) {
        switch (protocol) {
            case Protocols.Freedom: return new Outbound.FreedomSettings();
            case Protocols.Blackhole: return new Outbound.BlackholeSettings();
            case Protocols.DNS: return new Outbound.DNSSettings();
            case Protocols.VMess: return new Outbound.VmessSettings();
            case Protocols.VLESS: return new Outbound.VLESSSettings();
            case Protocols.Trojan: return new Outbound.TrojanSettings();
            case Protocols.Shadowsocks: return new Outbound.ShadowsocksSettings();
            case Protocols.Socks: return new Outbound.SocksSettings();
            case Protocols.HTTP: return new Outbound.HttpSettings();
            case Protocols.Wireguard: return new Outbound.WireguardSettings();
            case Protocols.Hysteria: return new Outbound.HysteriaSettings();
            case Protocols.Masque: return new Outbound.MasqueSettings();
            default: return {};
        }
    }

    static fromJson(protocol, json) {
        switch (protocol) {
            case Protocols.Freedom: return Outbound.FreedomSettings.fromJson(json);
            case Protocols.Blackhole: return Outbound.BlackholeSettings.fromJson(json);
            case Protocols.DNS: return Outbound.DNSSettings.fromJson(json);
            case Protocols.VMess: return Outbound.VmessSettings.fromJson(json);
            case Protocols.VLESS: return Outbound.VLESSSettings.fromJson(json);
            case Protocols.Trojan: return Outbound.TrojanSettings.fromJson(json);
            case Protocols.Shadowsocks: return Outbound.ShadowsocksSettings.fromJson(json);
            case Protocols.Socks: return Outbound.SocksSettings.fromJson(json);
            case Protocols.HTTP: return Outbound.HttpSettings.fromJson(json);
            case Protocols.Wireguard: return Outbound.WireguardSettings.fromJson(json);
            case Protocols.Hysteria: return Outbound.HysteriaSettings.fromJson(json);
            case Protocols.Masque: return Outbound.MasqueSettings.fromJson(json);
            default: return ProtocolUtil.copy(json || {});
        }
    }

    toJson() {
        return {};
    }
};
Outbound.FreedomSettings = class extends CommonClass {
    constructor(
        domainStrategy = '',
        redirect = '',
        fragment = {},
        noises = []
    ) {
        super();
        this.domainStrategy = domainStrategy;
        this.redirect = redirect;
        this.fragment = fragment;
        this.noises = noises;
    }

    addNoise() {
        this.noises.push(new Outbound.FreedomSettings.Noise());
    }

    delNoise(index) {
        this.noises.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Outbound.FreedomSettings(
            json.domainStrategy,
            json.redirect,
            json.fragment ? Outbound.FreedomSettings.Fragment.fromJson(json.fragment) : undefined,
            json.noises ? json.noises.map(noise => Outbound.FreedomSettings.Noise.fromJson(noise)) : [new Outbound.FreedomSettings.Noise()],
        );
    }

    toJson() {
        return {
            domainStrategy: ObjectUtil.isEmpty(this.domainStrategy) ? undefined : this.domainStrategy,
            redirect: this.redirect,
            fragment: Object.keys(this.fragment).length === 0 ? undefined : this.fragment,
            noises: Outbound.FreedomSettings.Noise.toJsonArray(this.noises),
        };
    }
};

Outbound.FreedomSettings.Fragment = class extends CommonClass {
    constructor(packets = '1-3', length = '', interval = '') {
        super();
        this.packets = packets;
        this.length = length;
        this.interval = interval;
    }

    static fromJson(json = {}) {
        return new Outbound.FreedomSettings.Fragment(
            json.packets,
            json.length,
            json.interval,
        );
    }
};

Outbound.FreedomSettings.Noise = class extends CommonClass {
    constructor(
        type = 'rand',
        packet = '10-20',
        delay = '10-16'
    ) {
        super();
        this.type = type;
        this.packet = packet;
        this.delay = delay;
    }

    static fromJson(json = {}) {
        return new Outbound.FreedomSettings.Noise(
            json.type,
            json.packet,
            json.delay,
        );
    }

    toJson() {
        return {
            type: this.type,
            packet: this.packet,
            delay: this.delay,
        };
    }

    static toJsonArray(noises) {
        return noises.map(noise => noise.toJson());
    }
};

Outbound.BlackholeSettings = class extends CommonClass {
    constructor(type) {
        super();
        this.type = type;
    }

    static fromJson(json = {}) {
        return new Outbound.BlackholeSettings(
            json.response ? json.response.type : undefined,
        );
    }

    toJson() {
        return {
            response: ObjectUtil.isEmpty(this.type) ? undefined : { type: this.type },
        };
    }
};
Outbound.DNSSettings = class extends CommonClass {
    constructor(
        network = 'udp',
        address = '1.1.1.1',
        port = 53,
        nonIPQuery = 'drop',
        blockTypes = []
    ) {
        super();
        this.network = network;
        this.address = address;
        this.port = port;
        this.nonIPQuery = nonIPQuery;
        this.blockTypes = blockTypes;
    }

    static fromJson(json = {}) {
        return new Outbound.DNSSettings(
            json.network,
            json.address,
            json.port,
            json.nonIPQuery,
            json.blockTypes,
        );
    }
};
Outbound.VmessSettings = class extends CommonClass {
    constructor(address, port, id, security) {
        super();
        this.address = address;
        this.port = port;
        this.id = id;
        this.security = security;
    }

    static fromJson(json = {}) {
        if (ObjectUtil.isArrEmpty(json.vnext)) return new Outbound.VmessSettings();
        return new Outbound.VmessSettings(
            json.vnext[0].address,
            json.vnext[0].port,
            json.vnext[0].users[0].id,
            json.vnext[0].users[0].security,
        );
    }

    toJson() {
        return {
            vnext: [{
                address: this.address,
                port: this.port,
                users: [{ id: this.id, security: this.security }],
            }],
        };
    }
};
Outbound.VLESSSettings = class extends CommonClass {
    constructor(address, port, id, flow, encryption = 'none') {
        super();
        this.address = address;
        this.port = port;
        this.id = id;
        this.flow = flow;
        this.encryption = encryption
    }

    static fromJson(json = {}) {
        const server = json.vnext?.[0] || json;
        const user = server.users?.[0] || server;
        return new Outbound.VLESSSettings(server.address, server.port, user.id, user.flow, user.encryption);
    }

    toJson() {
        return {
            vnext: [{
                address: this.address,
                port: this.port,
                users: [{ id: this.id, flow: this.flow, encryption: this.encryption || 'none' }],
            }],
        };
    }
};
Outbound.TrojanSettings = class extends CommonClass {
    constructor(address, port, password) {
        super();
        this.address = address;
        this.port = port;
        this.password = password;
    }

    static fromJson(json = {}) {
        if (ObjectUtil.isArrEmpty(json.servers)) return new Outbound.TrojanSettings();
        return new Outbound.TrojanSettings(
            json.servers[0].address,
            json.servers[0].port,
            json.servers[0].password,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                password: this.password,
            }],
        };
    }
};
Outbound.ShadowsocksSettings = class extends CommonClass {
    constructor(address, port, password, method, uot, UoTVersion) {
        super();
        this.address = address;
        this.port = port;
        this.password = password;
        this.method = method;
        this.uot = uot;
        this.UoTVersion = UoTVersion;
    }

    static fromJson(json = {}) {
        let servers = json.servers;
        if (ObjectUtil.isArrEmpty(servers)) servers = [{}];
        return new Outbound.ShadowsocksSettings(
            servers[0].address,
            servers[0].port,
            servers[0].password,
            servers[0].method,
            servers[0].uot,
            servers[0].UoTVersion,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                password: this.password,
                method: this.method,
                uot: this.uot,
                UoTVersion: this.UoTVersion,
            }],
        };
    }
};

Outbound.SocksSettings = class extends CommonClass {
    constructor(address, port, user, pass) {
        super();
        this.address = address;
        this.port = port;
        this.user = user;
        this.pass = pass;
    }

    static fromJson(json = {}) {
        let servers = json.servers;
        if (ObjectUtil.isArrEmpty(servers)) servers = [{ users: [{}] }];
        return new Outbound.SocksSettings(
            servers[0].address,
            servers[0].port,
            ObjectUtil.isArrEmpty(servers[0].users) ? '' : servers[0].users[0].user,
            ObjectUtil.isArrEmpty(servers[0].users) ? '' : servers[0].users[0].pass,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                users: ObjectUtil.isEmpty(this.user) ? [] : [{ user: this.user, pass: this.pass }],
            }],
        };
    }
};
Outbound.HttpSettings = class extends CommonClass {
    constructor(address, port, user, pass) {
        super();
        this.address = address;
        this.port = port;
        this.user = user;
        this.pass = pass;
    }

    static fromJson(json = {}) {
        let servers = json.servers;
        if (ObjectUtil.isArrEmpty(servers)) servers = [{ users: [{}] }];
        return new Outbound.HttpSettings(
            servers[0].address,
            servers[0].port,
            ObjectUtil.isArrEmpty(servers[0].users) ? '' : servers[0].users[0].user,
            ObjectUtil.isArrEmpty(servers[0].users) ? '' : servers[0].users[0].pass,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                users: ObjectUtil.isEmpty(this.user) ? [] : [{ user: this.user, pass: this.pass }],
            }],
        };
    }
};

Outbound.WireguardSettings = class extends CommonClass {
    constructor(
        mtu = 1420,
        secretKey = '',
        address = [''],
        workers = 2,
        domainStrategy = '',
        reserved = '',
        peers = [new Outbound.WireguardSettings.Peer()],
        kernelMode = false
    ) {
        super();
        this.mtu = mtu;
        this.secretKey = secretKey;
        this.pubKey = secretKey.length > 0 ? Wireguard.generateKeypair(secretKey).publicKey : '';
        this.address = Array.isArray(address) ? address.join(',') : address;
        this.workers = workers;
        this.domainStrategy = domainStrategy;
        this.reserved = Array.isArray(reserved) ? reserved.join(',') : reserved;
        this.peers = peers;
        this.kernelMode = kernelMode;
    }

    addPeer() {
        this.peers.push(new Outbound.WireguardSettings.Peer());
    }

    delPeer(index) {
        this.peers.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Outbound.WireguardSettings(
            json.mtu,
            json.secretKey,
            json.address,
            json.workers,
            json.domainStrategy,
            json.reserved,
            json.peers.map(peer => Outbound.WireguardSettings.Peer.fromJson(peer)),
            json.kernelMode,
        );
    }

    toJson() {
        return {
            mtu: this.mtu ?? undefined,
            secretKey: this.secretKey,
            address: this.address ? this.address.split(",") : [],
            workers: this.workers ?? undefined,
            domainStrategy: WireguardDomainStrategy.includes(this.domainStrategy) ? this.domainStrategy : undefined,
            reserved: this.reserved ? this.reserved.split(",").map(Number) : undefined,
            peers: Outbound.WireguardSettings.Peer.toJsonArray(this.peers),
            kernelMode: this.kernelMode,
        };
    }
};

Outbound.WireguardSettings.Peer = class extends CommonClass {
    constructor(
        publicKey = '',
        psk = '',
        allowedIPs = ['0.0.0.0/0', '::/0'],
        endpoint = '',
        keepAlive = 0
    ) {
        super();
        this.publicKey = publicKey;
        this.psk = psk;
        this.allowedIPs = allowedIPs;
        this.endpoint = endpoint;
        this.keepAlive = keepAlive;
    }

    static fromJson(json = {}) {
        return new Outbound.WireguardSettings.Peer(
            json.publicKey,
            json.preSharedKey,
            json.allowedIPs,
            json.endpoint,
            json.keepAlive
        );
    }

    toJson() {
        return {
            publicKey: this.publicKey,
            preSharedKey: this.psk.length > 0 ? this.psk : undefined,
            allowedIPs: this.allowedIPs ? this.allowedIPs : undefined,
            endpoint: this.endpoint,
            keepAlive: this.keepAlive ?? undefined,
        };
    }
};

Outbound.HysteriaSettings = class extends CommonClass {
    constructor(address = '', port = 443, version = 2) {
        super();
        this.address = address;
        this.port = port;
        this.version = version;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return new Outbound.HysteriaSettings();
        return new Outbound.HysteriaSettings(
            json.address,
            json.port,
            json.version
        );
    }

    toJson() {
        return {
            address: this.address,
            port: this.port,
            version: this.version
        };
    }
};

Outbound.MasqueSettings = class extends CommonClass {
    constructor(address = '', port = 443) { super(); this.address = address; this.port = port; }
    static fromJson(json = {}) { return new Outbound.MasqueSettings(json.address, json.port); }
    toJson() { return {address: this.address, port: this.port}; }
};

ProtocolUtil.retain(StreamSettings, ['network','security','tcpSettings','rawSettings','kcpSettings','wsSettings','httpSettings','quicSettings','grpcSettings','httpupgradeSettings','splithttpSettings','xhttpSettings','xdriveSettings','hysteriaSettings','masqueSettings','tlsSettings','realitySettings','sockopt','finalmask']);
ProtocolUtil.retain(TlsStreamSettings, ['serverName','alpn','fingerprint','allowInsecure','echConfigList','pinnedPeerCertSha256','verifyPeerCertByName']);
ProtocolUtil.retain(RealityStreamSettings, ['publicKey','password','fingerprint','serverName','shortId','spiderX','mldsa65Verify']);
ProtocolUtil.retain(KcpStreamSettings, ['mtu','tti','uplinkCapacity','downlinkCapacity','congestion','readBufferSize','writeBufferSize','header','seed','cwndMultiplier','maxSendingWindow']);
ProtocolUtil.retain(WsStreamSettings, ['path','host']);
ProtocolUtil.retain(HttpStreamSettings, ['path','host']);
ProtocolUtil.retain(QuicStreamSettings, ['security','key','header']);
ProtocolUtil.retain(GrpcStreamSettings, ['serviceName','authority','multiMode']);
ProtocolUtil.retain(HttpUpgradeStreamSettings, ['path','host']);
ProtocolUtil.retain(SockoptStreamSettings, ['dialerProxy','tcpFastOpen','tcpKeepAliveInterval','tcpMptcp','tcpNoDelay']);
ProtocolUtil.retain(HysteriaStreamSettings, ['version','auth','udpIdleTimeout','masquerade','up','down','udphop','initStreamReceiveWindow','maxStreamReceiveWindow','initConnectionReceiveWindow','maxConnectionReceiveWindow','maxIdleTimeout','keepAlivePeriod','disablePathMTUDiscovery']);
ProtocolUtil.retain(Outbound.HysteriaSettings, ['address','port','version']);
ProtocolUtil.retain(Outbound.MasqueSettings, ['address','port']);
ProtocolUtil.retain(Outbound.VLESSSettings, ['address','port','id','flow','encryption','vnext']);
ProtocolUtil.retain(Outbound.VmessSettings, ['vnext']);
ProtocolUtil.retain(Outbound, ['tag','protocol','settings','streamSettings','sendThrough','mux']);

// The simple form edits the first endpoint/user, while JSON may legitimately
// contain additional endpoints or protocol fields (e.g. VLESS reverse/testseed).
for (const Type of [Outbound.VLESSSettings, Outbound.VmessSettings, Outbound.TrojanSettings, Outbound.ShadowsocksSettings, Outbound.SocksSettings, Outbound.HttpSettings]) {
    const read = Type.fromJson, write = Type.prototype.toJson;
    Type.fromJson = function(json = {}) {
        const result = read.call(this, json);
        Object.defineProperty(result, '_serverWire', {value: ProtocolUtil.copy(json), configurable: true});
        return result;
    };
    Type.prototype.toJson = function() {
        const result = write.call(this);
        const key = result.vnext ? 'vnext' : 'servers';
        const original = this._serverWire?.[key];
        if (original?.length && result[key]?.length) {
            const first = {...original[0], ...result[key][0]};
            if (original[0].users?.length && first.users?.length) first.users = [{...original[0].users[0], ...first.users[0]}, ...original[0].users.slice(1)];
            result[key] = [first, ...original.slice(1)];
        }
        return result;
    };
}
