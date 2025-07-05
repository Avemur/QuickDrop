document.querySelectorAll('[data-panel]').forEach(btn => {
    btn.onclick = () => showPanel(btn.dataset.panel);
  });
  document.querySelectorAll('.back').forEach(b => {
    b.onclick = () => showPanel('home');
  });
  
  function showPanel(id) {
    document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
    document.getElementById(id).classList.add('active');
  }
  
  // — LISTEN —
  document.getElementById('start-listen').onclick = async () => {
    const alias = document.getElementById('listen-alias').value || 'QuickDropPeer';
    document.getElementById('listen-log').textContent = 'Starting…';
    await fetch(`/listen?alias=${encodeURIComponent(alias)}`);
    document.getElementById('listen-log').textContent = 'Broadcasting and ready to receive.';
  };
  
  // — DISCOVER —
  async function refreshDiscover() {
    const res = await fetch('/discover');
    const list = await res.json();
    const ul   = document.getElementById('peers-list');
    ul.innerHTML = list.map(p=>
      `<li>${p.alias} (${p.ip}:${p.port})</li>`
    ).join('');
  }
  document.getElementById('refresh-discover').onclick = refreshDiscover;
  refreshDiscover();
  
  // — SEND & DRAG+DROP —
  const drop = document.getElementById('drop-zone');
  const fileInput = document.getElementById('send-file');
  let pickedFile = null;
  
  drop.onclick = ()=> fileInput.click();
  drop.addEventListener('dragover', e=>{ e.preventDefault(); drop.classList.add('dragover'); });
  drop.addEventListener('dragleave', ()=> drop.classList.remove('dragover'));
  drop.addEventListener('drop', e=>{
    e.preventDefault(); drop.classList.remove('dragover');
    const f = e.dataTransfer.files[0];
    if (f) selectFile(f);
  });
  
  fileInput.onchange = ()=> {
    if (fileInput.files[0]) selectFile(fileInput.files[0]);
  };
  
  function selectFile(f) {
    pickedFile = f;
    drop.textContent = f.name;
    document.getElementById('do-send').disabled = false;
  }
  
  // populate peer dropdown
  async function populatePeers() {
    const res = await fetch('/discover');
    const list = await res.json();
    const sel = document.getElementById('send-peer');
    sel.innerHTML = list.map(p=>
      `<option value="${p.ip}:${p.port}">${p.alias}</option>`
    ).join('');
  }
  populatePeers();
  
  document.getElementById('do-send').onclick = async () => {
    if (!pickedFile) return;
    const sel = document.getElementById('send-peer');
    const [ip,port] = sel.value.split(':');
    const log = document.getElementById('send-log');
    log.textContent = 'Uploading…';
  
    const fd = new FormData();
    fd.append('file', pickedFile);
    fd.append('ip', ip);
    fd.append('port', port);
  
    const res = await fetch('/send', { method:'POST', body: fd });
    if (res.status === 202) log.textContent = 'Send queued!';
    else log.textContent = `Error ${res.status}`;
  };
  