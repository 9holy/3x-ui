// Real Chromium checks against a disposable panel database. No live listeners
// are created by these form tests; native protocol data planes have separate tests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const {spawn, execFileSync} = require('node:child_process');
const {randomBytes} = require('node:crypto');
const {chromium} = require('./browser-test/node_modules/playwright');
const root = path.resolve(__dirname, '..');
const artifacts = path.resolve(process.env.PROTOCOL_BROWSER_ARTIFACTS || 'test-results/browser');
const panelBinary = process.env.PANEL_BINARY;
const xrayBinary = process.env.XRAY_BINARY;
if (!panelBinary || !xrayBinary) throw new Error('PANEL_BINARY and XRAY_BINARY must point to the release binaries');
fs.mkdirSync(artifacts, {recursive: true});
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), '3x-ui-browser-'));
const bin = path.join(temporary, 'bin'), db = path.join(temporary, 'db');
fs.mkdirSync(bin); fs.mkdirSync(db);
fs.symlinkSync(path.resolve(xrayBinary), path.join(bin, 'xray-linux-amd64'));
const env = {...process.env, XUI_BIN_FOLDER: bin, XUI_DB_FOLDER: db, XUI_LOG_FOLDER: temporary};
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const freePort = () => new Promise((resolve, reject) => {
    const server = net.createServer(); server.on('error', reject);
    server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); });
});
const report = {checks: [], errors: []};
let panel, browser, page, log, base;

async function postResult(suffix, action) {
    const response = page.waitForResponse(r => new URL(r.url()).pathname.endsWith(suffix) && r.request().method() === 'POST');
    await action();
    const result = await response;
    assert.equal(result.status(), 200, suffix);
    const body = await result.json();
    assert.equal(body.success, true, `${suffix}: ${body.msg}`);
    return body;
}
const modal = () => page.locator('.ant-modal:visible').last();
const field = label => modal().locator('.ant-form-item:visible').filter({
    has: page.locator('.ant-form-item-label').filter({hasText: label}),
}).first();
async function saveModal(endpoint) {
    const result = await postResult(endpoint, () => modal().locator('.ant-modal-footer .ant-btn-primary').click());
    await page.waitForFunction(() => !inModal.visible && !clientModal.visible);
    await modal().waitFor({state: 'hidden'});
    return result;
}
async function loadedInbound(id) {
    await page.waitForFunction(id => app.dbInbounds.some(item => item.id === id), id);
    return page.evaluate(id => JSON.parse(JSON.stringify(app.dbInbounds.find(item => item.id === id))), id);
}

(async () => {
    const port = await freePort(), corePort = await freePort();
    base = `http://127.0.0.1:${port}/browser-audit/`;
    const password = randomBytes(20).toString('hex');
    execFileSync(path.resolve(panelBinary), ['setting', '-port', String(port), '-username', 'browser-audit', '-password', password, '-webBasePath', '/browser-audit/'], {cwd: temporary, env, stdio: 'pipe'});
    const template = JSON.parse(fs.readFileSync(path.join(root, 'web/service/config.json'), 'utf8'));
    template.inbounds[0].port = corePort;
    template.inbounds[0].protocol = 'tunnel';
    template.inbounds[0].settings = {rewriteAddress: '127.0.0.1'};
    template.routing.rules = template.routing.rules.filter(rule => rule.inboundTag?.includes('api'));
    execFileSync('python3', ['-c',
        'import sqlite3,json,sys\ndb=sqlite3.connect(sys.argv[1])\nfor key,value in json.loads(sys.argv[2]).items():\n db.execute("DELETE FROM settings WHERE key=?",(key,))\n db.execute("INSERT INTO settings(key,value) VALUES(?,?)",(key,value))\ndb.commit()\ndb.close()',
        path.join(db, 'x-ui.db'), JSON.stringify({webListen: '127.0.0.1', xrayTemplateConfig: JSON.stringify(template)})]);
    const cert = path.join(temporary, 'cert.pem'), key = path.join(temporary, 'key.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', key, '-out', cert], {stdio: 'pipe'});
    log = fs.openSync(path.join(artifacts, 'panel.log'), 'w');
    panel = spawn(path.resolve(panelBinary), [], {cwd: temporary, env, stdio: ['ignore', log, log]});
    for (let attempt = 0; ; attempt++) {
        try { if ((await fetch(base, {signal: AbortSignal.timeout(1000)})).ok) break; } catch (_) {}
        if (attempt === 100 || panel.exitCode !== null) throw new Error('Panel did not start; see panel.log');
        await sleep(100);
    }
    browser = await chromium.launch({headless: true, executablePath: process.env.BROWSER_EXECUTABLE || undefined});
    const context = await browser.newContext({viewport: {width: 1440, height: 1080}, locale: 'en-US'});
    await context.addCookies([{name: 'lang', value: 'en-US', url: base}]);
    page = await context.newPage();
    page.setDefaultTimeout(15000);
    page.on('pageerror', error => report.errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') report.errors.push(message.text()); });
    await page.goto(base);
    await page.locator('input[name="username"]').fill('browser-audit');
    await page.locator('input[name="password"]').fill(password);
    await Promise.all([page.waitForURL('**/panel/'), page.getByRole('button', {name: 'Log In', exact: true}).click()]);
    await page.goto(base + 'panel/inbounds');
    await page.waitForFunction(() => typeof app !== 'undefined' && Array.isArray(app.dbInbounds) && !app.refreshing);
    fs.writeFileSync(path.join(artifacts, 'inbounds.html'), await (await context.request.get(base + 'panel/inbounds')).text());
    await page.evaluate(() => { Vue.config.errorHandler = error => console.error('Vue: ' + error.stack); });
    const protocols = await page.evaluate(() => Object.values(Protocols).filter(protocol => protocol !== Protocols.TUN));
    const ids = {};
    for (let index = 0; index < protocols.length; index++) {
        const protocol = protocols[index], remark = `browser-${protocol}`;
        // Ant Design includes the plus icon's aria-label in the button name.
        await page.getByRole('button', {name: /\bAdd Inbound$/}).click();
        await field('Protocol').locator('.ant-select').click();
        await page.locator('.ant-select-dropdown-menu-item:visible').filter({hasText: new RegExp(`^\\s*${protocol}\\s*$`)}).click();
        const fixture = await page.evaluate(({protocol, index, cert, key}) => {
            const inbound = new Inbound(); inbound.protocol = protocol;
            inbound.port = 32000 + index; inbound.listen = '127.0.0.1';
            if ([Protocols.TUNNEL, Protocols.DOKODEMO].includes(protocol)) {
                inbound.settings.address = '127.0.0.1'; inbound.settings.port = 8080; inbound.settings.network = 'tcp';
            }
            if ([Protocols.HYSTERIA, Protocols.MASQUE].includes(protocol)) {
                const stream = JSON.parse(inbound.rawStreamSettingsText);
                stream.tlsSettings.certificates = [{certificateFile: cert, keyFile: key}];
                inbound.rawStreamSettingsText = JSON.stringify(stream);
            }
            if (protocol === Protocols.TUIC) {
                const settings = JSON.parse(inbound.rawSettingsText);
                settings.certificate = cert; settings.private_key = key;
                inbound.rawSettingsText = JSON.stringify(settings);
            }
            if (protocol === Protocols.AMNEZIAWG) {
                const privateKey = Wireguard.generateKeypair().privateKey;
                inbound.rawSettingsText = JSON.stringify({config: `[Interface]\nPrivateKey = ${privateKey}\nAddress = 10.75.0.1/24\n`});
            }
            return inbound.toJson();
        }, {protocol, index, cert, key});
        await modal().getByRole('tab', {name: 'Protocol JSON', exact: true}).click();
        await page.waitForFunction(() => inModal.activeKey === 'json');
        await modal().locator('.ant-tabs-tabpane-active[role="tabpanel"]').locator('textarea').fill(JSON.stringify(fixture));
        await modal().getByRole('tab', {name: 'Form', exact: true}).click();
        await page.waitForFunction(() => inModal.activeKey === 'form');
        assert.equal(await page.evaluate(() => inModal.inbound.port), fixture.port, protocol + ' JSON tab applies fixture');
        await field('Remark').locator('input').fill(remark);
        await field('Enabled').getByRole('switch').click();
        const created = await saveModal('/panel/inbound/add');
        ids[protocol] = created.obj.id;
        const saved = await loadedInbound(created.obj.id);
        assert.equal(saved.enable, false, protocol + ' disabled state');
        assert.deepEqual(JSON.parse(saved.settings), fixture.settings, protocol + ' actual database settings');
        await page.evaluate(id => app.openEditInbound(id), saved.id);
        await field('Port').locator('input').first().fill(String(33000 + index));
        await saveModal(`/panel/inbound/update/${saved.id}`);
        await page.waitForFunction(({id, port}) => app.dbInbounds.find(item => item.id === id)?.port === port, {id: saved.id, port: 33000 + index});
        const edited = await loadedInbound(saved.id);
        assert.deepEqual(JSON.parse(edited.settings), fixture.settings, protocol + ' edit preserves settings');
        report.checks.push(`${protocol}: select, form/JSON round trip, create, edit, persisted settings and disabled state`);
        console.log('PASS: ' + report.checks.at(-1));
    }
    for (const protocol of ['vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria', 'masque', 'mtproto', 'tuic']) {
        const id = ids[protocol], email = 'browser-client-' + protocol;
        await page.evaluate(id => app.openAddClient(id), id);
        await field('Email').locator('input').fill(email);
        if (protocol === 'tuic') {
            assert.equal(await field('Total Flow').locator('input').isDisabled(), true);
            assert.equal(await field('Start After First Use').getByRole('switch').isDisabled(), true);
        } else {
            await field('Total Flow').locator('input').fill('2');
            await field('Start After First Use').getByRole('switch').click();
            await field('Duration').locator('input').fill('3');
        }
        await saveModal('/panel/inbound/addClient');
        await page.waitForFunction(({id, email}) => JSON.parse(app.dbInbounds.find(item => item.id === id).settings).clients.some(client => client.email === email), {id, email});
        const client = await page.evaluate(({id, email}) => JSON.parse(app.dbInbounds.find(item => item.id === id).settings).clients.find(client => client.email === email), {id, email});
        if (protocol !== 'tuic') { assert.equal(client.totalGB, 2 * 1024 ** 3); assert.equal(client.expiryTime, -3 * 86400000); }
        await page.evaluate(({id, client}) => app.openEditClient(id, client), {id, client});
        await field('Enabled').getByRole('switch').click();
        const clientKey = await page.evaluate(() => clientModal.oldClientId);
        await saveModal('/panel/inbound/updateClient/' + encodeURIComponent(clientKey));
        await page.waitForFunction(({id, email}) => JSON.parse(app.dbInbounds.find(item => item.id === id).settings).clients.find(client => client.email === email)?.enable === false, {id, email});
        await page.evaluate(({id, email}) => {
            const record = app.dbInbounds.find(item => item.id === id);
            infoModal.show(record, record.toInbound().clients.findIndex(client => client.email === email));
        }, {id, email});
        await modal().waitFor({state: 'visible'});
        await modal().locator('.ant-modal-close').click();
        await modal().waitFor({state: 'hidden'});
        await postResult(`/panel/inbound/${id}/delClient/${encodeURIComponent(clientKey)}`, () => page.evaluate(({id, client}) => app.delClient(id, client, false), {id, client}));
        await page.waitForFunction(({id, email}) => !JSON.parse(app.dbInbounds.find(item => item.id === id).settings).clients.some(client => client.email === email), {id, email});
        report.checks.push(`${protocol}: customer create, quota/delay availability, edit, disable, details, delete`);
        console.log('PASS: ' + report.checks.at(-1));
    }
    await page.screenshot({path: path.join(artifacts, 'inbounds-desktop.png'), fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    await page.screenshot({path: path.join(artifacts, 'inbounds-mobile.png'), fullPage: true});
    await page.setViewportSize({width: 1440, height: 1080});
    await page.goto(base + 'panel/xray');
    await page.waitForFunction(() => typeof app !== 'undefined' && app.templateSettings?.outbounds);
    fs.writeFileSync(path.join(artifacts, 'xray.html'), await (await context.request.get(base + 'panel/xray')).text());
    await page.evaluate(() => { Vue.config.errorHandler = error => console.error('Vue: ' + error.stack); app.addOutbound(); });
    await modal().getByRole('tab', {name: 'JSON', exact: true}).click();
    await modal().locator('input[placeholder^="vmess://"]').fill('hy2://browser%3Asecret@[::1]:443?sni=localhost&obfs=salamander&obfs-password=test#browser-hy2');
    await modal().locator('.ant-form-item').filter({has: page.locator('input[placeholder^="vmess://"]')}).getByRole('button').click();
    await modal().getByRole('tab', {name: 'Form', exact: true}).click();
    const imported = await page.evaluate(() => outModal.outbound.toJson());
    assert.equal(imported.streamSettings.hysteriaSettings.auth, 'browser:secret');
    assert.equal(imported.settings.address, '::1');
    await modal().locator('.ant-modal-footer .ant-btn-primary').click();
    await page.waitForFunction(() => !outModal.visible);
    await postResult('/panel/xray/update', () => page.evaluate(() => app.updateXraySetting()));
    await page.reload();
    await page.waitForFunction(() => app.templateSettings?.outbounds.some(item => item.tag === 'browser-hy2'));
    const outbound = await page.evaluate(() => app.templateSettings.outbounds.find(item => item.tag === 'browser-hy2'));
    assert.equal(outbound.streamSettings.hysteriaSettings.auth, 'browser:secret');
    report.checks.push('Hysteria2 outbound: actual link import, form, persisted template and reload');
    await page.screenshot({path: path.join(artifacts, 'outbound-desktop.png'), fullPage: true});
    assert.deepEqual(report.errors, [], 'browser console and unhandled errors');
    console.log(`PASS: ${report.checks.length} browser workflows; artifacts: ${artifacts}`);
})().catch(async error => {
    report.failure = error.stack; process.exitCode = 1;
    console.error(error.stack);
    if (page) { try { await page.screenshot({path: path.join(artifacts, 'failure.png'), fullPage: true}); fs.writeFileSync(path.join(artifacts, 'failure.html'), await page.content()); } catch (_) {} }
}).finally(async () => {
    fs.writeFileSync(path.join(artifacts, 'results.json'), JSON.stringify(report, null, 2));
    if (browser) await browser.close();
    if (panel && panel.exitCode === null) {
        panel.kill('SIGTERM');
        for (let count = 0; panel.exitCode === null && count < 50; count++) await sleep(100);
        if (panel.exitCode === null) panel.kill('SIGKILL');
    }
    if (log !== undefined) fs.closeSync(log);
    fs.rmSync(temporary, {recursive: true, force: true});
});
