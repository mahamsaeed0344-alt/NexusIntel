// Global alert popup + voice + beep
window.CFS = {
  speak(text){
    try{
      const u = new SpeechSynthesisUtterance(text);
      u.lang='en-US'; u.rate=1; u.pitch=1; u.volume=1;
      speechSynthesis.cancel(); speechSynthesis.speak(u);
    }catch(e){}
  },

  // Programmatic beep using Web Audio API as fallback / supplement
  beep(freq=880, duration=0.18, vol=0.7){
    try{
      const ctx = new (window.AudioContext||window.webkitAudioContext)();
      // Three sharp beeps
      [0, 0.22, 0.44].forEach(offset=>{
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain); gain.connect(ctx.destination);
        osc.type='square'; osc.frequency.value=freq;
        gain.gain.setValueAtTime(vol, ctx.currentTime+offset);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime+offset+duration);
        osc.start(ctx.currentTime+offset);
        osc.stop(ctx.currentTime+offset+duration);
      });
    }catch(e){}
  },

  alertCriminal(name, confidence, meta, snapshotPath){
    const pop  = document.getElementById('alertPopup');
    const snap = document.getElementById('alertSnap');
    document.getElementById('alertName').textContent = name;

    // Confidence line: handle null/zero gracefully
    if(confidence && confidence > 0){
      document.getElementById('alertConf').textContent = `Confidence: ${(+confidence).toFixed(1)}%`;
    } else {
      document.getElementById('alertConf').textContent = '⚠ IDENTITY MATCH — LOW CONFIDENCE';
    }
    document.getElementById('alertMeta').textContent = meta || '';

    // Show snapshot in alert popup if available
    if(snapshotPath){
      snap.src = `/file/by_rel?p=${encodeURIComponent(snapshotPath)}`;
      snap.style.display='block';
      snap.onerror = ()=>{ snap.style.display='none'; };
    } else {
      snap.style.display='none';
    }

    pop.classList.remove('d-none');

    // 1. Play alert.wav first
    const snd = document.getElementById('alertSound');
    if(snd){
      snd.currentTime = 0;
      const played = snd.play();
      // If wav blocked (autoplay policy), fall back to programmatic beep
      if(played && typeof played.then === 'function'){
        played.catch(()=>this.beep());
      }
    } else {
      this.beep();
    }

    // 2. Also always fire the beep for guaranteed audio feedback
    setTimeout(()=>this.beep(1100, 0.15, 0.5), 50);

    // 3. Voice announcement — always speak real name
    this.speak(`Warning. Criminal detected. ${name}.`);
  }
};

document.addEventListener('click', e=>{
  if(e.target && e.target.id==='alertAck'){
    document.getElementById('alertPopup').classList.add('d-none');
    speechSynthesis.cancel();
  }
});
