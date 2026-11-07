// Component-level checks against HTML served by a locally built panel.
// Set PROTOCOL_UI_HTML_DIR to a directory containing authenticated
// /panel/inbounds and /panel/xray responses as inbounds.html and xray.html.
// Uses the panel's actual Vue compiler, models, templates and modal methods;
// this does not claim browser layout or third-party component E2E coverage.
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const root = path.resolve(__dirname, '..');
const htmlDir = process.env.PROTOCOL_UI_HTML_DIR;

function runtime(page, model) {
    const html = fs.readFileSync(path.join(htmlDir, `${page}.html`), 'utf8');
    const templates = {}, scripts = {};
    for (const match of html.matchAll(/(<a-modal\b[^>]*\bid="([^"]+)"[^>]*>[\s\S]*?<\/a-modal>)\s*<script>([\s\S]*?)<\/script>/g)) {
        templates[`#${match[2]}`] = match[1]; scripts[match[2]] = match[3];
    }
    const messages = [], errors = [], instances = {};
    const context = vm.createContext({console, URL, URLSearchParams, crypto: webcrypto,
        setTimeout, clearTimeout, templates, instances, messages, errors,
        Base64: {encode: v => Buffer.from(v, 'utf8').toString('base64'), decode: v => Buffer.from(v, 'base64').toString('utf8')},
        btoa: v => Buffer.from(v, 'binary').toString('base64'), atob: v => Buffer.from(v, 'base64').toString('binary'),
        document: {createElement: () => ({
            set innerHTML(html) { this.textContent = html.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&'); },
            get innerHTML() { return this.textContent; },
        }), getElementById: () => ({value: ''})},
    });
    const run = code => vm.runInContext(code, context);
    // Load Vue before window exists so its DOM patcher stays disabled. Render
    // functions still use the exact production compiler shipped by the panel.
    run(fs.readFileSync(path.join(root, 'web/assets/vue/vue.min.js'), 'utf8'));
    run(`
        Vue.config.errorHandler = (error) => errors.push(error.message);
        Vue.prototype.$message = {error: text => messages.push(text), success: () => {}};
        const RealVue = Vue;
        Vue = function(options) {
            const id = options.el; const compiled = RealVue.compile(templates[id], {delimiters: options.delimiters});
            const instance = new RealVue({...options, ...compiled, el: undefined});
            instances[id] = instance; return instance;
        };
        Vue.prototype = RealVue.prototype;
        const themeSwitcher = {currentTheme: 'light', isDarkTheme: false};
        const app = {datepicker: 'gregorian', subSettings: {enable: true}, tgBotEnable: false,
            ipLimitEnable: false, trafficDiff: 0, cmOptions: {}, defaultCert: '', defaultKey: ''};
        const window = {crypto, location: {hostname: '127.0.0.1'}};
        const location = window.location;
        const CodeMirror = {fromTextArea: area => ({value: area.value, change: null,
            on(event, callback) {this.change=callback;}, getValue() {return this.value;},
            setValue(value) {this.value=value;this.change(this);}, toTextArea() {}})};
    `);
    for (const file of ['util/common.js', 'util/utils.js', 'util/date-util.js', 'model/protocol.js', `model/${model}.js`, ...(model === 'xray' ? ['model/dbinbound.js'] : [])]) {
        run(fs.readFileSync(path.join(root, 'web/assets/js', file), 'utf8'));
    }
    run(fs.readFileSync(path.join(root, 'web/assets/moment/moment.min.js'), 'utf8'));
    const names = model === 'xray' ? ['inbound-modal','client-modal','client-bulk-modal'] : ['out-modal'];
    for (const name of names) {
        assert.ok(scripts[name], `served ${name} template and script`);
        run(scripts[name]);
    }
    const render = id => {
        errors.length = 0;
        const result = run(`instances[${JSON.stringify('#' + id)}]._render()`);
        assert.deepEqual(errors, [], `${id} render errors`);
        return result;
    };
    return {run, render, messages, templates, html};
}

function nodes(node) {
    if (!node) return [];
    if (Array.isArray(node)) return node.flatMap(nodes);
    return [node, ...(node.children || []).flatMap(nodes)];
}
function input(tree, value) { return nodes(tree).find(node => node.tag === 'a-input' && node.data?.model?.value === value); }

test('served inbound/client forms compile and execute their protocol workflows', {skip: !htmlDir}, () => {
    const ui = runtime('inbounds', 'xray');
    assert.match(ui.html, /assets\/js\/model\/protocol\.js/);
    ui.run('inModal.show({}); inModal.inbound.protocol=Protocols.VLESS; inModal.inbound.stream.network="xhttp"; inModal.inbound.settings.encryption="mlkem.test";');
    let tree = ui.render('inbound-modal');
    assert.ok(nodes(tree).some(n => n.data?.attrs?.label === 'Advanced XHTTP JSON'));
    const pathInput = input(tree, '/');
    assert.ok(pathInput, 'XHTTP path form input');
    pathInput.data.model.callback('/ui-edited');
    ui.run('inModal.changeTab("json");');
    assert.equal(ui.run('JSON.parse(inModal.jsonText).streamSettings.xhttpSettings.path'), '/ui-edited');
    ui.run('inModal.changeTab("form");');
    ui.render('inbound-modal');
    ui.run('inModal.show({isEdit:true,inbound:inModal.inbound});');
    assert.equal(ui.run('inModal.inbound.stream.xhttp.path'), '/ui-edited');

    for (const protocol of ['hysteria','masque','mtproto','tuic']) {
        ui.run(`
            inModal.show({}); inModal.inbound.protocol=${JSON.stringify(protocol)};
            var wire = inModal.inbound.toJson();
            var db = new DBInbound({id: 42, protocol: wire.protocol, port: 443,
                settings: JSON.stringify(wire.settings), streamSettings: JSON.stringify(wire.streamSettings), clientStats: []});
            var saved = null;
            clientModal.show({dbInbound: db, confirm: client => {saved=client.toJson();}});
        `);
        ui.render('inbound-modal');
        tree = ui.render('client-modal');
        const credential = ui.run('clientModalApp.client.auth || clientModalApp.client.password || clientModalApp.client.secret');
        assert.ok(credential, `${protocol} generated credentials`);
        assert.ok(input(tree, credential), `${protocol} editable credential input`);
        if (protocol === 'tuic') assert.ok(nodes(tree).some(n => n.tag === 'a-switch' && n.data?.model?.value === false && n.data?.attrs?.disabled === true), 'TUIC cannot newly enable delayed start');
        ui.run('clientModalApp.client.email="ui-client";clientModalApp.client._expiryTime=Date.now()+86400000;clientModal.ok();');
        assert.equal(ui.run('saved.email'), 'ui-client');
        assert.ok(ui.run('saved.expiryTime > Date.now()'));
        ui.run('clientModal.close();clientModal.show({dbInbound:db,index:0,isEdit:true,confirm:client=>{saved=client.toJson();}});');
        ui.render('client-modal');
        assert.ok(ui.run('clientModal.oldClientId'));
        ui.run('clientModalApp.client.enable=false;clientModal.ok();');
        assert.equal(ui.run('saved.enable'), false);

        if (protocol === 'tuic' || protocol === 'masque') {
            const legacy = protocol === 'tuic' ? {uuid:'legacy-uuid',secret:'legacy-secret',email:'legacy'} : {pass:'legacy-pass',email:'legacy'};
            ui.run(`var legacySettings=JSON.parse(db.settings);legacySettings.clients=[${JSON.stringify(legacy)}];db.settings=JSON.stringify(legacySettings);clientModal.show({dbInbound:db,index:0,isEdit:true,confirm:client=>{saved=client.toJson();}});`);
            tree = ui.render('client-modal');
            const oldCredential = protocol === 'tuic' ? 'legacy-secret' : 'legacy-pass';
            assert.ok(input(tree, oldCredential));
            input(tree, oldCredential).data.model.callback('edited-credential');
            if (protocol === 'tuic') input(tree, 'legacy-uuid').data.model.callback('edited-uuid');
            ui.run('clientModal.ok();');
            assert.equal(ui.run('saved.password'), 'edited-credential');
            assert.equal(ui.run('saved.pass || saved.secret || saved.uuid'), undefined);
            if (protocol === 'tuic') assert.equal(ui.run('saved.id'), 'edited-uuid');
        }

        ui.run('clientsBulkModal.show({dbInbound:db,confirm:clients=>{saved=clients.map(c=>c.toJson());}}); clientsBulkModal.quantity=2;');
        tree = ui.render('client-bulk-modal');
        ui.run('clientsBulkModal.ok();');
        assert.equal(ui.run('saved.length'), 2);
        if (protocol === 'tuic') {
            assert.ok(nodes(tree).some(n => n.tag === 'a-input-number' && n.data?.attrs?.disabled === true), 'TUIC quota input is disabled');
            assert.ok(nodes(tree).some(n => n.tag === 'a-switch' && n.data?.model?.value === false && n.data?.attrs?.disabled === true), 'TUIC bulk delayed start is disabled');
            ui.run('var oldSettings=JSON.parse(db.settings);oldSettings.clients[0].expiryTime=-86400000;db.settings=JSON.stringify(oldSettings);clientModal.show({dbInbound:db,index:0,isEdit:true});');
            tree = ui.render('client-modal');
            const clearSwitch = nodes(tree).find(n => n.tag === 'a-switch' && n.data?.model?.value === true && n.data?.attrs?.disabled === false);
            assert.ok(clearSwitch, 'legacy negative expiry can be cleared');
            clearSwitch.data.model.callback(false); clearSwitch.data.on.click();
            assert.equal(ui.run('clientModalApp.client.expiryTime'), 0);
        }
    }
    ui.messages.length = 0;
    ui.run('inModal.activeKey="json";inModal.jsonText="[]";var confirmed=false;inModal.confirm=()=>{confirmed=true;};inModal.ok();');
    assert.equal(ui.run('confirmed'), false);
    assert.match(ui.messages.at(-1), /must be a JSON object/);
});

test('served outbound modal supports new/import/edit and invalid JSON workflows', {skip: !htmlDir}, () => {
    const ui = runtime('xray', 'outbound');
    ui.run('outModal.show({});');
    ui.render('out-modal');
    ui.run('outModal.link="hy2://secret%3Aencoded@[::1]:443?sni=example.com&obfs=salamander&obfs-password=mask#ui-hy2";instances["#out-modal"].convertLink();');
    assert.equal(ui.run('outModal.outbound.stream.hysteria.auth'), 'secret:encoded');
    assert.equal(ui.run('outModal.activeKey'), '2');
    ui.run('outModal.toggleJson(false);');
    let tree = ui.render('out-modal');
    assert.ok(input(tree, 'secret:encoded'), 'HY2 auth form input');
    input(tree, 'secret:encoded').data.model.callback('edited:auth');
    ui.run('var saved=null;outModal.confirm=wire=>{saved=wire;};outModal.ok();outModal.show({isEdit:true,outbound:saved});');
    tree = ui.render('out-modal');
    assert.ok(input(tree, 'edited:auth'));
    ui.run('outModal.toggleJson(true);outModal.cm.setValue("[]");');
    assert.equal(ui.run('outModal.isValid'), false);
    ui.messages.length = 0;
    ui.run('var confirmed=false;outModal.confirm=()=>{confirmed=true;};outModal.ok();');
    assert.equal(ui.run('confirmed'), false);
    assert.match(ui.messages.at(-1), /must be a JSON object/);
});

test('served modal warnings prevent removed transports and explicit empty legacy KCP seed', {skip: !htmlDir}, () => {
    for (const model of ['xray', 'outbound']) {
        const ui = runtime(model === 'xray' ? 'inbounds' : 'xray', model);
        const modal = model === 'xray' ? 'inModal' : 'outModal';
        const object = model === 'xray' ? 'inbound' : 'outbound';
        const name = model === 'xray' ? 'inbound-modal' : 'out-modal';
        for (const network of ['http','quic','kcp']) {
            ui.run(`${modal}.show({});${modal}.${object}.stream = StreamSettings.fromJson({network:${JSON.stringify(network)},kcpSettings:{seed:""}});var confirmed=false;${modal}.confirm=()=>{confirmed=true;};`);
            const tree = ui.render(name);
            assert.ok(nodes(tree).some(n => n.tag === 'a-alert' && n.data?.attrs?.type === 'error'), `${network} visible migration message`);
            ui.messages.length = 0;
            ui.run(`${modal}.ok();`);
            assert.equal(ui.run('confirmed'), false);
            assert.match(ui.messages.at(-1), /H2|seed/);
        }
    }
});
