async function refreshPeers() {
    const res  = await fetch('/discover');
    const data = await res.json();
    const peers = document.getElementById('peers');
    peers.innerHTML = '';
    data.forEach(p => {
      const opt = document.createElement('option');
      opt.value = `${p.ip}:${p.port}`;
      opt.text  = `${p.alias} (${p.ip}:${p.port})`;
      peers.appendChild(opt);
    });
    // mirror to send-form select
    const sendSel = document.getElementById('peerSelect');
    sendSel.innerHTML = peers.innerHTML;
  }
  
  document.getElementById('refresh').onclick = refreshPeers;
  refreshPeers();
  
  document.getElementById('sendForm').onsubmit = async e => {
    e.preventDefault();
    const form = e.target;
    const data = new FormData(form);
    const log  = document.getElementById('log');
    log.textContent = 'Sending…';
  
    const [ip,port] = data.get('peer').split(':');
    data.set('ip', ip);
    data.set('port', port);
  
    const res = await fetch('/send', {
      method: 'POST',
      body: data
    });
  
    if (res.status === 202) {
      log.textContent = 'File send queued!';
    } else {
      log.textContent = 'Error: ' + res.status;
    }
  };
  