class DBInbound {

    constructor(data) {
        this.id = 0;
        this.userId = 0;
        this.up = 0;
        this.down = 0;
        this.total = 0;
        this.remark = "";
        this.enable = true;
        this.expiryTime = 0;

        this.listen = "";
        this.port = 0;
        this.protocol = "";
        this.settings = "";
        this.streamSettings = "";
        this.tag = "";
        this.sniffing = "";
        this.clientStats = ""
        if (data == null) {
            return;
        }
        ObjectUtil.cloneProps(this, data);
    }

    get totalGB() {
        return toFixed(this.total / ONE_GB, 2);
    }

    set totalGB(gb) {
        this.total = toFixed(gb * ONE_GB, 0);
    }

    get isVMess() {
        return this.protocol === Protocols.VMESS;
    }

    get isVLess() {
        return this.protocol === Protocols.VLESS;
    }

    get isTrojan() {
        return this.protocol === Protocols.TROJAN;
    }

    get isSS() {
        return this.protocol === Protocols.SHADOWSOCKS;
    }

    get isSocks() {
        return [Protocols.SOCKS, Protocols.MIXED].includes(this.protocol);
    }

    get isHTTP() {
        return this.protocol === Protocols.HTTP;
    }

    get isWireguard() {
        return this.protocol === Protocols.WIREGUARD;
    }

    get address() {
        let address = location.hostname;
        if (!ObjectUtil.isEmpty(this.listen) && this.listen !== "0.0.0.0") {
            address = this.listen;
        }
        return address;
    }

    get _expiryTime() {
        if (this.expiryTime === 0) {
            return null;
        }
        return moment(this.expiryTime);
    }

    set _expiryTime(t) {
        if (t == null) {
            this.expiryTime = 0;
        } else {
            this.expiryTime = t.valueOf();
        }
    }

    get isExpiry() {
        return this.expiryTime < new Date().getTime();
    }

    toInbound() {
        let settings = {};
        if (!ObjectUtil.isEmpty(this.settings)) {
            settings = typeof this.settings === "string" ? JSON.parse(this.settings) : (this.settings.toJson ? this.settings.toJson() : this.settings);
        }

        let streamSettings = {};
        if (!ObjectUtil.isEmpty(this.streamSettings)) {
            streamSettings = JSON.parse(this.streamSettings);
        }

        let sniffing = {};
        if (!ObjectUtil.isEmpty(this.sniffing)) {
            sniffing = JSON.parse(this.sniffing);
        }

        const config = {
            port: this.port,
            listen: this.listen,
            protocol: this.protocol,
            settings: settings,
            streamSettings: streamSettings,
            tag: this.tag,
            sniffing: sniffing,
            clientStats: this.clientStats,
        };
        return Inbound.fromJson(config);
    }

    isMultiUser() {
        switch (this.protocol) {
            case Protocols.VMESS:
            case Protocols.VLESS:
            case Protocols.TROJAN:
                return true;
            case Protocols.HYSTERIA:
            case Protocols.MASQUE:
            case Protocols.MTPROTO:
            case Protocols.TUIC:
                // Native users-map/secret formats remain editable as JSON;
                // panel client dialogs require the panel's clients array.
                return Array.isArray(this.toInbound().clients);
            case Protocols.SHADOWSOCKS:
                return this.toInbound().isSSMultiUser;
            default:
                return false;
        }
    }

    hasLink() {
        if (this.toInbound().network === 'xdrive') return false;
        if ([Protocols.HYSTERIA, Protocols.TUIC, Protocols.MTPROTO].includes(this.protocol) && !this.isMultiUser()) return false;
        switch (this.protocol) {
            case Protocols.VMESS:
            case Protocols.VLESS:
            case Protocols.TROJAN:
            case Protocols.SHADOWSOCKS:
            case Protocols.HYSTERIA:
            case Protocols.TUIC:
            case Protocols.MTPROTO:
                return true;
            default:
                return false;
        }
    }
    
	genInboundLinks(remarkModel) {
        const inbound = this.toInbound();
        return inbound.genInboundLinks(this.remark,remarkModel);
    }
}
