// NEXUS INTEL — Voice Assistant
(function(){
  const WAKE_WORDS = ['nexus', 'system', 'assistant', 'hey nexus'];
  let recognition = null;
  let synth = window.speechSynthesis;
  let listening = false;
  let wakeActive = false;
  let silenceTimer = null;
  let voiceEnabled = localStorage.getItem('voiceEnabled') === 'true';

  // ── Build UI ──────────────────────────────────────────────────────────────
  const panel = document.createElement('div');
  panel.id = 'voicePanel';
  panel.innerHTML = `
    <div id="voiceBtn" title="Voice Assistant (V)" onclick="CFS_VOICE.toggle()">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3z"/>
        <path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/>
        <line x1="8" y1="23" x2="16" y2="23"/>
      </svg>
    </div>
    <div id="voiceDrawer" class="va-hidden">
      <div id="vaHeader">
        <span id="vaTitle">NEXUS VOICE ASSISTANT</span>
        <button id="vaClose" onclick="CFS_VOICE.close()">✕</button>
      </div>
      <div id="vaStatus"><span id="vaStatusDot"></span><span id="vaStatusTxt">Ready</span></div>
      <div id="vaWaveform"><div class="va-wave" id="w1"></div><div class="va-wave" id="w2"></div><div class="va-wave" id="w3"></div><div class="va-wave" id="w4"></div><div class="va-wave" id="w5"></div></div>
      <div id="vaTranscript"></div>
      <div id="vaReply"></div>
      <div id="vaQuickBtns">
        <button class="va-qbtn" onclick="CFS_VOICE.ask('How many criminals are in the database')">Criminals</button>
        <button class="va-qbtn" onclick="CFS_VOICE.ask('How many detections total')">Detections</button>
        <button class="va-qbtn" onclick="CFS_VOICE.ask('What is the accuracy')">Accuracy</button>
        <button class="va-qbtn" onclick="CFS_VOICE.ask('Show me the most wanted list')">Wanted</button>
        <button class="va-qbtn" onclick="CFS_VOICE.ask('What was the last detection')">Last detection</button>
        <button class="va-qbtn" onclick="CFS_VOICE.ask('Who has the highest threat score')">Top threat</button>
        <button class="va-qbtn" onclick="CFS_VOICE.ask('How many detections today')">Today</button>
        <button class="va-qbtn" onclick="CFS_VOICE.ask('Help')">Help</button>
      </div>
      <div id="vaInputRow">
        <input id="vaTextInput" type="text" placeholder="Type or speak a question…" onkeydown="if(event.key==='Enter')CFS_VOICE.submitText()">
        <button id="vaMicBtn" onclick="CFS_VOICE.startListening()" title="Click to speak">🎤</button>
        <button id="vaSubmit" onclick="CFS_VOICE.submitText()">→</button>
      </div>
    </div>`;
  document.body.appendChild(panel);

  // ── CSS injected ──────────────────────────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
  #voicePanel{position:fixed;bottom:24px;right:24px;z-index:8000;font-family:'Exo 2',sans-serif}
  #voiceBtn{width:52px;height:52px;border-radius:50%;background:linear-gradient(135deg,#005f73,#00b4d8);
    color:#001219;display:flex;align-items:center;justify-content:center;cursor:pointer;
    box-shadow:0 0 20px rgba(0,180,216,.5),0 4px 12px rgba(0,0,0,.4);transition:all .2s;border:none}
  #voiceBtn:hover{transform:scale(1.08);box-shadow:0 0 30px rgba(0,229,255,.7)}
  #voiceBtn.active{background:linear-gradient(135deg,#ff1744,#ff5252);
    box-shadow:0 0 24px rgba(255,23,68,.7);animation:vbPulse 1s infinite}
  @keyframes vbPulse{0%,100%{transform:scale(1)}50%{transform:scale(1.12)}}
  #voiceDrawer{position:absolute;bottom:64px;right:0;width:340px;
    background:linear-gradient(145deg,#08101e,#0d1a2e);border:1px solid #1a3050;
    border-radius:18px;padding:0;overflow:hidden;
    box-shadow:0 8px 40px rgba(0,0,0,.7),0 0 0 1px rgba(0,229,255,.1);
    transition:all .25s cubic-bezier(.4,0,.2,1)}
  .va-hidden{opacity:0;transform:translateY(12px) scale(.97);pointer-events:none}
  #vaHeader{display:flex;align-items:center;justify-content:space-between;
    padding:14px 16px 10px;border-bottom:1px solid #1a3050}
  #vaTitle{font-family:'Orbitron',monospace;font-size:.65rem;letter-spacing:3px;color:#00e5ff}
  #vaClose{background:none;border:none;color:#64748b;cursor:pointer;font-size:14px;padding:2px 4px}
  #vaClose:hover{color:#ff5252}
  #vaStatus{display:flex;align-items:center;gap:8px;padding:10px 16px 6px;font-size:.8rem;color:#94a3b8}
  #vaStatusDot{width:8px;height:8px;border-radius:50%;background:#64748b;flex-shrink:0;transition:all .3s}
  #vaStatusDot.ready{background:#00e676;box-shadow:0 0 6px rgba(0,230,118,.6)}
  #vaStatusDot.listening{background:#00e5ff;box-shadow:0 0 8px rgba(0,229,255,.8);animation:vbPulse 1s infinite}
  #vaStatusDot.speaking{background:#ffd740;box-shadow:0 0 8px rgba(255,215,64,.7)}
  #vaStatusDot.thinking{background:#a855f7;box-shadow:0 0 8px rgba(168,85,247,.7)}
  #vaWaveform{display:flex;align-items:center;justify-content:center;gap:4px;height:32px;padding:0 16px}
  .va-wave{width:4px;border-radius:2px;background:#00e5ff;opacity:.4;transition:height .1s}
  .va-wave.active{opacity:1;animation:vaWave .6s ease-in-out infinite}
  .va-wave:nth-child(2){animation-delay:.1s}.va-wave:nth-child(3){animation-delay:.2s}
  .va-wave:nth-child(4){animation-delay:.1s}.va-wave:nth-child(5){animation-delay:.25s}
  @keyframes vaWave{0%,100%{height:4px}50%{height:22px}}
  #vaTranscript{margin:6px 16px 0;padding:8px 10px;background:rgba(0,0,0,.25);
    border-radius:8px;font-size:.8rem;color:#94a3b8;min-height:24px;
    border:1px solid #1a2540;font-style:italic;display:none}
  #vaReply{margin:8px 16px;padding:10px 12px;background:rgba(0,229,255,.06);
    border:1px solid rgba(0,229,255,.2);border-radius:10px;font-size:.85rem;
    color:#e2e8f0;line-height:1.5;min-height:36px;display:none}
  #vaQuickBtns{display:flex;flex-wrap:wrap;gap:5px;padding:8px 16px}
  .va-qbtn{background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.2);
    border-radius:20px;color:#94a3b8;font-size:.72rem;padding:4px 10px;cursor:pointer;
    font-family:'Exo 2',sans-serif;transition:all .15s}
  .va-qbtn:hover{background:rgba(0,229,255,.15);color:#00e5ff;border-color:rgba(0,229,255,.4)}
  #vaInputRow{display:flex;gap:6px;padding:10px 16px 14px;border-top:1px solid #1a3050}
  #vaTextInput{flex:1;background:rgba(0,0,0,.3);border:1px solid #1a3050;border-radius:8px;
    color:#e2e8f0;padding:7px 10px;font-size:.82rem;font-family:'Exo 2',sans-serif;outline:none}
  #vaTextInput:focus{border-color:rgba(0,229,255,.4)}
  #vaMicBtn{background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.25);
    border-radius:8px;padding:6px 10px;cursor:pointer;font-size:14px}
  #vaMicBtn.active{background:rgba(255,23,68,.15);border-color:rgba(255,23,68,.4);animation:vbPulse .8s infinite}
  #vaSubmit{background:linear-gradient(135deg,#005f73,#00b4d8);border:none;border-radius:8px;
    color:#001219;padding:6px 12px;font-weight:700;cursor:pointer;font-size:.85rem}
  /* Light theme */
  [data-theme="light"] #voiceDrawer{background:#fff;border-color:#d1dce8;box-shadow:0 8px 40px rgba(0,0,0,.12)}
  [data-theme="light"] #vaHeader,[data-theme="light"] #vaInputRow{border-color:#e2e8f0}
  [data-theme="light"] #vaTitle{color:#0056b3}
  [data-theme="light"] #vaTranscript{background:#f8fafc;border-color:#e2e8f0;color:#64748b}
  [data-theme="light"] #vaReply{background:rgba(0,100,200,.05);border-color:rgba(0,100,200,.2);color:#1a2636}
  [data-theme="light"] #vaTextInput{background:#f8fafc;border-color:#d1dce8;color:#1a2636}
  [data-theme="light"] .va-wave{background:#0056b3}
  [data-theme="light"] .va-qbtn{background:rgba(0,100,200,.06);border-color:rgba(0,100,200,.15);color:#475569}
  [data-theme="light"] .va-qbtn:hover{color:#0056b3;background:rgba(0,100,200,.12)}
  `;
  document.head.appendChild(style);

  // ── Speech recognition setup ───────────────────────────────────────────────
  const SpeechRecog = window.SpeechRecognition || window.webkitSpeechRecognition;

  function setStatus(state, text){
    const dot = document.getElementById('vaStatusDot');
    const txt = document.getElementById('vaStatusTxt');
    const btn = document.getElementById('vaMicBtn');
    const vbtn= document.getElementById('voiceBtn');
    dot.className = state;
    txt.textContent = text;
    btn.classList.toggle('active', state === 'listening');
    vbtn.classList.toggle('active', state === 'listening');
    // Animate waveform
    document.querySelectorAll('.va-wave').forEach(w => {
      w.classList.toggle('active', state === 'listening' || state === 'speaking');
      w.style.height = (state === 'listening' || state === 'speaking') ? '' : '4px';
    });
  }

  function showTranscript(text){
    const el = document.getElementById('vaTranscript');
    el.style.display = text ? 'block' : 'none';
    el.textContent = text ? '"' + text + '"' : '';
  }

  function showReply(text){
    const el = document.getElementById('vaReply');
    el.style.display = text ? 'block' : 'none';
    el.textContent = text || '';
  }

  function speak(text){
    if(!synth) return;
    synth.cancel();
    setStatus('speaking', 'Speaking…');
    const utt = new SpeechSynthesisUtterance(text);
    utt.rate = 1.0; utt.pitch = 1.0; utt.volume = 1.0;
    // Pick a good voice if available
    const voices = synth.getVoices();
    const pref = voices.find(v => v.lang.startsWith('en') && v.name.includes('Google'))
              || voices.find(v => v.lang.startsWith('en'))
              || voices[0];
    if(pref) utt.voice = pref;
    utt.onend = () => setStatus('ready', 'Ready');
    utt.onerror = () => setStatus('ready', 'Ready');
    synth.speak(utt);
  }

  async function sendQuery(query){
    showTranscript(query);
    showReply('');
    setStatus('thinking', 'Processing…');
    try {
      const res = await fetch('/api/voice_query', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({query})
      });
      const json = await res.json();
      showReply(json.reply);
      speak(json.reply);
      // Navigate if the response suggests it
      if(json.data && json.data.type === 'navigate' && json.data.url){
        setTimeout(() => window.location.href = json.data.url, 2500);
      }
    } catch(e){
      const msg = 'Sorry, I could not connect to the system.';
      showReply(msg); speak(msg);
      setStatus('ready', 'Ready');
    }
  }

  function startListening(){
    if(!SpeechRecog){
      speak('Speech recognition is not supported in this browser. Please use Chrome.');
      showReply('Speech recognition requires Google Chrome browser.');
      return;
    }
    if(listening) { stopListening(); return; }
    recognition = new SpeechRecog();
    recognition.continuous = false;
    recognition.interimResults = true;
    recognition.lang = 'en-US';
    recognition.maxAlternatives = 1;

    recognition.onstart = () => { listening = true; setStatus('listening', 'Listening…'); };
    recognition.onresult = (e) => {
      const interim = Array.from(e.results).map(r=>r[0].transcript).join(' ');
      showTranscript(interim);
      if(e.results[e.results.length-1].isFinal){
        const final = e.results[e.results.length-1][0].transcript;
        stopListening();
        sendQuery(final);
      }
    };
    recognition.onerror = (e) => {
      setStatus('ready', 'Mic error: ' + e.error);
      listening = false;
    };
    recognition.onend = () => { listening = false; };
    recognition.start();

    // Auto-stop after 8 seconds
    clearTimeout(silenceTimer);
    silenceTimer = setTimeout(stopListening, 8000);
  }

  function stopListening(){
    if(recognition){ try{recognition.stop()}catch(e){} }
    listening = false;
    clearTimeout(silenceTimer);
  }

  // ── Public API ──────────────────────────────────────────────────────────────
  window.CFS_VOICE = {
    toggle(){
      const drawer = document.getElementById('voiceDrawer');
      const isHidden = drawer.classList.contains('va-hidden');
      if(isHidden){
        drawer.classList.remove('va-hidden');
        setStatus('ready','Ready');
      } else {
        this.close();
      }
    },
    close(){
      stopListening();
      if(synth) synth.cancel();
      document.getElementById('voiceDrawer').classList.add('va-hidden');
    },
    startListening,
    ask(q){
      document.getElementById('vaTextInput').value = q;
      sendQuery(q);
    },
    submitText(){
      const inp = document.getElementById('vaTextInput');
      const val = inp.value.trim();
      if(!val) return;
      inp.value = '';
      sendQuery(val);
    }
  };

  // Keyboard shortcut: V key toggles voice panel
  document.addEventListener('keydown', e => {
    if(e.key === 'v' && !e.ctrlKey && !e.altKey &&
       !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)){
      CFS_VOICE.toggle();
    }
  });

  // Auto-open hint after 1.5s on first visit
  if(!localStorage.getItem('vaShown')){
    localStorage.setItem('vaShown','1');
    setTimeout(()=>{
      const drawer = document.getElementById('voiceDrawer');
      drawer.classList.remove('va-hidden');
      showReply('Hello! I am your NEXUS INTEL voice assistant. Ask me anything about the system, or click the microphone to speak. Press V to toggle me anytime.');
      setStatus('ready','Ready');
    }, 1500);
  }
})();
