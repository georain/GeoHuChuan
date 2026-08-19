#!/usr/bin/env node
/* ============================================================
   GeoRainCONNECT - 局域网信令服务器（零依赖）
   ------------------------------------------------------------
   用法:
     node server.js            # 监听 0.0.0.0:8787
     PORT=9000 node server.js  # 自定义端口
   ------------------------------------------------------------
   协议（JSON 文本帧）:
     C->S  {type:'hello', name}                注册设备名
     S->*  {type:'peers', list:[{id,name}]}    在线设备列表广播
     C->S  {type:'signal', to, payload}        转发信令给指定设备
     S->T  {type:'signal', from, fromName, payload}
     C->S  {type:'bye'}                        主动注销（关闭前可发）
   ============================================================ */
'use strict';

const http = require('http');
const crypto = require('crypto');
const os = require('os');

const PORT = parseInt(process.env.PORT, 10) || 8787;
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const HEARTBEAT_MS = 30000;   // 服务端 ping 间隔
const MAX_PAYLOAD = 512 * 1024; // 单帧最大 512KB，防滥用

/* ---------------- 工具 ---------------- */
function now() {
  return new Date().toTimeString().slice(0, 8);
}
function log(msg) {
  console.log('[' + now() + '] ' + msg);
}
function getLanAddresses() {
  const addrs = [];
  const ifs = os.networkInterfaces();
  for (const name of Object.keys(ifs)) {
    for (const info of (ifs[name] || [])) {
      if (info.family === 'IPv4' && !info.internal) addrs.push(info.address);
    }
  }
  return addrs;
}

/* ---------------- WebSocket 帧编解码 ---------------- */
// 解析客户端帧（客户端->服务端必须带掩码）
function decodeFrame(buf) {
  if (buf.length < 2) throw new Error('帧头不完整');
  const b0 = buf[0], b1 = buf[1];
  const fin = (b0 & 0x80) !== 0;
  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) !== 0;
  let len = b1 & 0x7f;
  let offset = 2;
  if (len === 126) {
    if (buf.length < 4) throw new Error('帧头不完整');
    len = buf.readUInt16BE(2); offset = 4;
  } else if (len === 127) {
    if (buf.length < 10) throw new Error('帧头不完整');
    const hi = buf.readUInt32BE(2), lo = buf.readUInt32BE(6);
    if (hi !== 0) throw new Error('帧长度超限');
    len = lo; offset = 10;
  }
  if (len > MAX_PAYLOAD) throw new Error('帧过大');
  if (buf.length < offset + (masked ? 4 : 0) + len) throw new Error('帧数据不完整');
  let mask = null, payload = null;
  if (masked) {
    mask = buf.slice(offset, offset + 4);
    payload = Buffer.from(buf.slice(offset + 4, offset + 4 + len));
    for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
  } else {
    payload = buf.slice(offset, offset + 4 + len);
  }
  return { fin, opcode, payload };
}

// 构造服务端帧（服务端->客户端不带掩码）
function encodeFrame(opcode, payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const len = data.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x80 | opcode;
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(len, 6);
  }
  return Buffer.concat([header, data]);
}

/* ---------------- 连接与房间管理 ---------------- */
const clients = new Map(); // id -> {id, name, socket, buffer, alive}

function broadcastPeers() {
  const list = [];
  for (const c of clients.values()) list.push({ id: c.id, name: c.name || '未命名设备' });
  const msg = JSON.stringify({ type: 'peers', list });
  for (const c of clients.values()) sendText(c, msg);
}

function sendText(client, text) {
  try {
    client.socket.write(encodeFrame(0x1, text));
  } catch (e) {
    removeClient(client.id, '发送失败');
  }
}

function removeClient(id, reason) {
  const c = clients.get(id);
  if (!c) return;
  clients.delete(id);
  clearInterval(c.heartbeat);
  log('设备断开: ' + (c.name || id) + (reason ? ' (' + reason + ')' : '') + ' | 在线 ' + clients.size);
  broadcastPeers();
}

/* ---------------- HTTP 服务与握手 ---------------- */
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('GeoRainCONNECT 信令服务器运行中。请在应用内连接 ws://<本机IP>:' + PORT);
});

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n'
  );

  const id = crypto.randomUUID();
  const client = { id, name: '', socket, buffer: Buffer.alloc(0), heartbeat: null };
  clients.set(id, client);
  log('新设备接入: ' + id + ' | 在线 ' + clients.size);

  socket.on('data', (chunk) => {
    client.buffer = Buffer.concat([client.buffer, chunk]);
    // 循环解析完整帧（可能一次收到多帧）
    for (;;) {
      try {
        if (client.buffer.length < 2) break;
        // 估算帧总长以判断是否收齐
        const b1 = client.buffer[1];
        let frameLen = 2;
        let len = b1 & 0x7f;
        if (len === 126) { if (client.buffer.length < 4) break; frameLen = 4; len = client.buffer.readUInt16BE(2); }
        else if (len === 127) { if (client.buffer.length < 10) break; frameLen = 10; len = client.buffer.readUInt32BE(6); }
        const masked = (b1 & 0x80) !== 0;
        const total = frameLen + (masked ? 4 : 0) + len;
        if (client.buffer.length < total) break;

        const frameBuf = client.buffer.slice(0, total);
        client.buffer = client.buffer.slice(total);
        const frame = decodeFrame(frameBuf);

        if (frame.opcode === 0x8) { // close
          try { socket.write(encodeFrame(0x8, Buffer.from([0x03, 0xe8]))); } catch (e) {}
          socket.end();
          removeClient(id, '主动关闭');
          break;
        } else if (frame.opcode === 0x9) { // ping -> pong
          try { socket.write(encodeFrame(0xa, frame.payload)); } catch (e) {}
        } else if (frame.opcode === 0x1) { // text
          handleMessage(client, frame.payload.toString('utf8'));
        }
        // 0x2 二进制忽略，0xa pong 忽略
      } catch (e) {
        removeClient(id, '协议错误: ' + e.message);
        socket.destroy();
        break;
      }
    }
  });

  socket.on('error', () => { removeClient(id, '网络错误'); });
  socket.on('close', () => { removeClient(id, '连接关闭'); });

  // 心跳：30s ping 一次；浏览器端 WebSocket 会自动回 pong
  client.heartbeat = setInterval(() => {
    try {
      socket.write(encodeFrame(0x9, Buffer.from('ping')));
    } catch (e) {
      removeClient(id, '心跳失败');
      socket.destroy();
    }
  }, HEARTBEAT_MS);
});

function handleMessage(client, text) {
  let msg;
  try { msg = JSON.parse(text); } catch (e) { return; }
  if (!msg || typeof msg.type !== 'string') return;

  if (msg.type === 'hello') {
    const name = typeof msg.name === 'string' ? msg.name.trim().slice(0, 64) : '';
    client.name = name || '未命名设备';
    log('设备注册: ' + client.name + ' (' + client.id + ')');
    // 回执自己的 id，客户端用于在设备列表中排除自己
    sendText(client, JSON.stringify({ type: 'hello-ack', id: client.id }));
    broadcastPeers();
  } else if (msg.type === 'signal') {
    const target = clients.get(msg.to);
    if (!target) {
      // 目标不存在，回执错误给发送方
      sendText(client, JSON.stringify({ type: 'error', code: 'PEER_GONE', message: '对方设备已离线' }));
      return;
    }
    sendText(target, JSON.stringify({
      type: 'signal',
      from: client.id,
      fromName: client.name || '未命名设备',
      payload: msg.payload
    }));
  } else if (msg.type === 'bye') {
    removeClient(client.id, '主动注销');
    try { client.socket.end(); } catch (e) {}
  }
}

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error('[' + now() + '] 端口 ' + PORT + ' 已被占用，请换端口重试（PORT=xxxx node server.js）');
  } else {
    console.error('[' + now() + '] 服务器错误: ' + e.message);
  }
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  const addrs = getLanAddresses();
  log('GeoRainCONNECT 信令服务器已启动，端口 ' + PORT);
  log('本机局域网地址:');
  addrs.forEach((a) => log('  ws://' + a + ':' + PORT));
  if (addrs.length === 0) log('  （未检测到局域网地址，请检查网络连接）');
  log('请在应用的「自动发现」中输入上面的 ws:// 地址并连接');
});
