document.addEventListener('contextmenu', e => e.preventDefault(), true);
document.addEventListener('mousedown', e => {
  if (e.button !== 0 && e.target !== document.getElementById('usernameInput')) e.preventDefault();
});

const uInput = document.getElementById('usernameInput');
const nameErrorEl = document.getElementById('nameError');
const avatarL = document.getElementById('avatarLetter');
const settingLabelEl = document.getElementById('settingLabel');

const loadBarEl = document.getElementById('load-bar');
const loadStageEl = document.getElementById('loadStage');
const loadPathEl = document.getElementById('loadPathText');
const loadSizesEl = document.getElementById('loadSizes');
const loadPctEl = document.getElementById('load-pct');
const pbtn = document.getElementById('playBtn');
const cbtn = document.getElementById('cancelBtn');
const onlineTextEl = document.getElementById('onlineText');
const onlineBadgeEl = document.getElementById('onlineBadge');

const BOOT_R = 40;
const BOOT_CIRC = 2 * Math.PI * BOOT_R;
const rProgEl = document.getElementById('r-prog');
const bootStEl = document.getElementById('boot-status');
const bootEl = document.getElementById('boot');
const lncEl = document.getElementById('launcher');

let bootCurrent = 0;
let bootAnimId = null;
let currentSlide = 0;
let totalSlides = 3;
let slideTimer = null;
let isHovered = false;
let isUpdating = false;
let currentSetting = 1;
let lastAnimatedFilePath = '';
let serverQueryOk = false;
let serverOnline = true;
let socialLinks = {
  trangchu: '',
  youtubeChannel: '',
  vk: '',
  ig: '',
  telegram: '',
  discord: ''
};
let newsLinks = ['', '', '', '', '', ''];

function isLinkEnabled(url) {
  return !!url && String(url).trim() !== '' && String(url).trim().toLowerCase() !== 'none';
}

function sendNative(msg) {
  window.chrome?.webview?.postMessage(msg);
}

uInput.addEventListener('input', () => {
  const v = uInput.value.trim();
  avatarL.textContent = v.length ? v[0].toUpperCase() : '?';
  if (v.length > 0) nameErrorEl.textContent = '';
});
uInput.addEventListener('contextmenu', e => e.preventDefault());

document.getElementById('btnMin').addEventListener('click', () => sendNative('minimize'));
document.getElementById('btnClose').addEventListener('click', () => {
  sendNative('close');
  window.close();
});

document.querySelectorAll('.tb-tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tb-tab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
  });
});

function showSlide(idx) {
  currentSlide = (idx + totalSlides) % totalSlides;
  document.querySelectorAll('.nc').forEach(c => {
    c.style.display = parseInt(c.dataset.slide, 10) === currentSlide ? '' : 'none';
  });
  document.querySelectorAll('.dot-btn').forEach((d, i) => d.classList.toggle('active', i === currentSlide));
}

function startAutoSlide() {
  clearInterval(slideTimer);
  slideTimer = setInterval(() => {
    if (!isHovered) showSlide(currentSlide + 1);
  }, 3500);
}

document.querySelectorAll('.dot-btn').forEach(d => {
  d.addEventListener('click', () => {
    showSlide(parseInt(d.dataset.slide, 10));
    startAutoSlide();
  });
});

const newsSection = document.querySelector('.news-section');
newsSection.addEventListener('mouseenter', () => { isHovered = true; });
newsSection.addEventListener('mouseleave', () => { isHovered = false; });

const wrenchBtn = document.getElementById('wrenchBtn');
const wrenchPopup = document.getElementById('wrenchPopup');
const settingsBtn = document.getElementById('btnSettings');
const settingsPopup = document.getElementById('settingsPopup');

wrenchBtn.addEventListener('click', e => {
  e.stopPropagation();
  wrenchPopup.classList.toggle('open');
  settingsPopup.classList.remove('open');
});

settingsBtn.addEventListener('click', e => {
  e.stopPropagation();
  settingsPopup.classList.toggle('open');
  wrenchPopup.classList.remove('open');
});

document.addEventListener('click', () => {
  wrenchPopup.classList.remove('open');
  settingsPopup.classList.remove('open');
});

document.querySelectorAll('#settingsPopup .popup-item[data-theme]').forEach(item => {
  item.addEventListener('click', e => {
    e.stopPropagation();
    const theme = e.currentTarget.dataset.theme;
    if (theme === 'light') document.body.classList.add('light-theme');
    else document.body.classList.remove('light-theme');
    settingsPopup.classList.remove('open');
  });
});

document.querySelectorAll('#settingsPopup .popup-item[data-res]').forEach(item => {
  item.addEventListener('click', e => {
    e.stopPropagation();
    const res = e.currentTarget.dataset.res;
    document.querySelectorAll('#settingsPopup .popup-item[data-res]').forEach(r => r.classList.remove('active-res'));
    e.currentTarget.classList.add('active-res');
    sendNative('resize:' + res);
    settingsPopup.classList.remove('open');
  });
});

function setSettingMode(mode) {
  currentSetting = mode;
  const pReset = document.getElementById('pItemReset');
  const pCustom = document.getElementById('pItemCustom');
  const pServer = document.getElementById('pItemServer');

  [pReset, pCustom, pServer].forEach(p => p.classList.remove('active-setting'));

  if (mode === 2) {
    pCustom.classList.add('active-setting');
    settingLabelEl.textContent = 'Custom Mod';
  } else if (mode === 3) {
    pServer.classList.add('active-setting');
    settingLabelEl.textContent = 'Server Mod';
  } else {
    pReset.classList.add('active-setting');
    settingLabelEl.textContent = 'Game mặc định';
  }

  sendNative('setting:' + mode);
  wrenchPopup.classList.remove('open');
}

document.getElementById('pItemReset').addEventListener('click', () => setSettingMode(1));
document.getElementById('pItemCustom').addEventListener('click', () => setSettingMode(2));
document.getElementById('pItemServer').addEventListener('click', () => setSettingMode(3));

function updateSocialButtons() {
  const map = [
    ['btnTrangChu', socialLinks.trangchu],
    ['btnYoutubeChannel', socialLinks.youtubeChannel],
    ['btnVK', socialLinks.vk],
    ['btnIG', socialLinks.ig],
    ['btnTelegram', socialLinks.telegram],
    ['btnDiscord', socialLinks.discord]
  ];

  map.forEach(([id, url]) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (isLinkEnabled(url)) el.classList.remove('disabled');
    else el.classList.add('disabled');
  });
}

function bindSocialClicks() {
  const handlers = {
    btnTrangChu: () => socialLinks.trangchu,
    btnYoutubeChannel: () => socialLinks.youtubeChannel,
    btnVK: () => socialLinks.vk,
    btnIG: () => socialLinks.ig,
    btnTelegram: () => socialLinks.telegram,
    btnDiscord: () => socialLinks.discord
  };

  Object.keys(handlers).forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('click', () => {
      const url = handlers[id]();
      if (isLinkEnabled(url)) sendNative('openurl:' + url);
    });
  });
}

function setNews(news) {
  const src = Array.isArray(news) ? news : [];

  const toEmbedUrl = (url) => {
    if (!isLinkEnabled(url)) return '';
    try {
      const u = new URL(url);
      let vid = '';
      if (u.hostname.includes('youtu.be')) {
        vid = u.pathname.replace('/', '').trim();
      } else if (u.pathname.startsWith('/shorts/')) {
        vid = u.pathname.split('/')[2] || '';
      } else {
        vid = u.searchParams.get('v') || '';
      }
      if (!vid) return '';
      return 'https://www.youtube.com/embed/' + encodeURIComponent(vid) + '?rel=0&modestbranding=1&playsinline=1';
    } catch {
      return '';
    }
  };

  for (let idx = 0; idx < 6; idx++) {
    const n = src[idx] || null;
    const title = n && n.title ? n.title : ('Tin tức ' + (idx + 1));
    const youtube = n && n.youtube ? n.youtube : '';
    newsLinks[idx] = youtube;
    const embed = toEmbedUrl(youtube);

    const label = document.getElementById('newsLabel' + idx);
    if (label) label.textContent = title;

    const frame = document.getElementById('newsFrame' + idx);
    const holder = frame ? frame.parentElement : null;
    if (frame && holder) {
      frame.src = embed;
      frame.style.display = embed ? '' : 'none';
      const svg = holder.querySelector('svg');
      if (svg) svg.style.display = embed ? 'none' : '';
    }

    const card = document.getElementById('newsCard' + idx);
    if (card) {
      if (isLinkEnabled(youtube)) card.classList.remove('disabled');
      else card.classList.add('disabled');
      card.onclick = () => {
        if (isLinkEnabled(newsLinks[idx])) sendNative('openurl:' + newsLinks[idx]);
      };
    }
  }
}

function setAnimatedPathText(text) {
  const value = String(text || '');
  loadPathEl.innerHTML = '';
  if (!value) {
    loadPathEl.textContent = '';
    return;
  }

  for (let i = 0; i < value.length; i++) {
    const span = document.createElement('span');
    span.className = 'char';
    span.textContent = value[i] === ' ' ? '\u00A0' : value[i];
    span.style.animationDelay = (i * 0.026) + 's';
    loadPathEl.appendChild(span);
  }
}

function animateBootTo(target, onDone) {
  if (bootAnimId) cancelAnimationFrame(bootAnimId);
  function step() {
    if (bootCurrent < target) {
      bootCurrent = Math.min(bootCurrent + 0.5, target);
      rProgEl.style.strokeDashoffset = BOOT_CIRC * (1 - bootCurrent / 100);
      bootAnimId = requestAnimationFrame(step);
    } else {
      bootCurrent = target;
      rProgEl.style.strokeDashoffset = BOOT_CIRC * (1 - bootCurrent / 100);
      if (onDone) onDone();
    }
  }
  requestAnimationFrame(step);
}

function finishBoot(gameFolderExists) {
  bootEl.classList.add('fade-out');
  setTimeout(() => {
    bootEl.style.display = 'none';
    lncEl.style.opacity = '1';
    lncEl.style.pointerEvents = 'all';
    const heroBgImg = document.getElementById('heroBgImg');
    if (heroBgImg) heroBgImg.classList.add('visible');
    startAutoSlide();
    if (!gameFolderExists) setSettingMode(1);
    loadStageEl.textContent = 'Chọn cấu hình và bấm Chơi ngay';
    loadPathEl.textContent = '';
    loadBarEl.style.width = '0%';
    loadPctEl.textContent = '0%';
    loadSizesEl.textContent = '';
  }, 620);
}

bootStEl.textContent = 'Đang khởi tạo...';

pbtn.addEventListener('click', () => {
  if (isUpdating) return;
  if (!serverOnline) return;
  const name = uInput.value.trim();
  if (!name) {
    nameErrorEl.textContent = 'Vui lòng nhập tên nhân vật trước khi vào game.';
    uInput.focus();
    return;
  }

  nameErrorEl.textContent = '';
  isUpdating = true;
  lastAnimatedFilePath = '';
  pbtn.style.display = 'none';
  cbtn.classList.add('show');
  loadStageEl.textContent = 'Đang chuẩn bị...';
  setAnimatedPathText('');
  loadBarEl.style.width = '0%';
  loadPctEl.textContent = '0%';
  loadSizesEl.textContent = '';
  sendNative('play:' + name);
});

cbtn.addEventListener('click', () => {
  sendNative('cancel');
  isUpdating = false;
  lastAnimatedFilePath = '';
  cbtn.classList.remove('show');
  pbtn.style.display = '';
  loadBarEl.style.width = '0%';
  loadPctEl.textContent = '0%';
  loadStageEl.textContent = 'Đã hủy';
  setAnimatedPathText('');
  loadSizesEl.textContent = '';
});

bindSocialClicks();

if (window.chrome && window.chrome.webview) {
  window.chrome.webview.addEventListener('message', event => {
    const d = event.data;
    if (!d || !d.type) return;

    switch (d.type) {
      case 'boot':
        animateBootTo(d.percent || 0);
        bootStEl.textContent = d.msg || '';
        break;

      case 'bootComplete':
        if (typeof d.resolution === 'number') {
          const target = d.resolution === 1 ? '800x600' : '1280x720';
          document.querySelectorAll('#settingsPopup .popup-item[data-res]').forEach(r => r.classList.remove('active-res'));
          const el = document.querySelector('#settingsPopup .popup-item[data-res="' + target + '"]');
          if (el) el.classList.add('active-res');
        }

        if (typeof d.setting === 'number') {
          setSettingMode(d.setting);
        } else {
          setSettingMode(1);
        }

        socialLinks = {
          trangchu: d.trangchu || '',
          youtubeChannel: d.youtubeChannel || '',
          vk: d.vk || '',
          ig: d.ig || '',
          telegram: d.telegram || '',
          discord: d.discord || ''
        };
        uInput.value = d.nickname || '';
        avatarL.textContent = uInput.value.trim().length ? uInput.value.trim()[0].toUpperCase() : '?';
        nameErrorEl.textContent = '';

        serverQueryOk = !!d.serverQueryOk;
        const currentPlayers = Number(d.currentPlayers || 0);
        const maxPlayers = Number(d.maxPlayers || 0);
        serverOnline = !!d.serverOnline && maxPlayers > 0;
        if (serverQueryOk && serverOnline) {
          onlineTextEl.textContent = 'Trực tuyến: ' + currentPlayers + '/' + maxPlayers;
          onlineBadgeEl.style.color = '';
          pbtn.disabled = false;
          pbtn.textContent = 'Chơi ngay ›';
        } else if (serverQueryOk && !serverOnline) {
          onlineTextEl.textContent = 'Server Offline';
          onlineBadgeEl.style.color = 'var(--red)';
          pbtn.disabled = true;
          pbtn.textContent = 'Server Offline';
        } else {
          onlineTextEl.textContent = 'Trực tuyến: --/--';
          onlineBadgeEl.style.color = '';
          pbtn.disabled = false;
          pbtn.textContent = 'Chơi ngay ›';
        }

        updateSocialButtons();
        setNews(d.news || []);

        animateBootTo(100, () => finishBoot(!!d.gameFolderExists));
        break;

      case 'downloadProgress':
        loadBarEl.style.width = (d.percent || 0) + '%';
        loadPctEl.textContent = (d.percent || 0) + '%';
        loadStageEl.textContent = d.stage || '';
        if ((d.file || '') !== lastAnimatedFilePath) {
          setAnimatedPathText(d.file || '');
          lastAnimatedFilePath = d.file || '';
        }
        loadSizesEl.textContent = d.sizes || '';
        break;

      case 'downloadComplete':
        isUpdating = false;
        cbtn.classList.remove('show');
        pbtn.style.display = '';
        pbtn.textContent = (serverQueryOk && !serverOnline) ? 'Server Offline' : 'Chơi ngay ›';
        pbtn.style.opacity = '1';
        pbtn.disabled = (serverQueryOk && !serverOnline);
        loadBarEl.style.width = '100%';
        loadPctEl.textContent = '100%';
        loadStageEl.textContent = 'Sẵn sàng chơi';
        setAnimatedPathText('Tất cả file đã cập nhật');
        loadSizesEl.textContent = d.failed > 0 ? (d.downloaded + ' OK, ' + d.failed + ' lỗi') : (d.downloaded + ' file đã tải');
        break;

      case 'launching':
        pbtn.textContent = 'Đang mở game...';
        pbtn.style.opacity = '0.7';
        pbtn.disabled = true;
        loadStageEl.textContent = 'Đang khởi động game...';
        break;

      case 'error':
        isUpdating = false;
        lastAnimatedFilePath = '';
        cbtn.classList.remove('show');
        pbtn.style.display = '';
        pbtn.textContent = (serverQueryOk && !serverOnline) ? 'Server Offline' : 'Chơi ngay ›';
        pbtn.style.opacity = '1';
        pbtn.disabled = (serverQueryOk && !serverOnline);
        loadStageEl.textContent = d.msg || 'Đã xảy ra lỗi';
        loadBarEl.style.width = '0%';
        loadPctEl.textContent = '0%';
        break;
    }
  });
}