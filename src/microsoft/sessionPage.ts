/** No remote assets, template variables from account/page content, or arbitrary browser commands. */
export function sessionPage(nonce: string): string {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Perch · Microsoft sign-in</title>
<style nonce="${nonce}">
:root{font:16px "Source Sans 3",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#0a0a0a;background:#ffffff}body{max-width:1120px;margin:24px auto;padding:0 16px}h1{font-size:24px}button,input{font:inherit;padding:8px 12px;border:1px solid #d4d4d4;border-radius:6px;background:white}button{cursor:pointer}button:focus-visible,#screen:focus-visible{outline:3px solid #0a0a0a}nav{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.note{padding:12px;background:#fdf3e3;border-radius:6px}#screen{display:block;width:100%;max-width:1100px;aspect-ratio:1100/780;background:#f5f5f5;border:1px solid #d4d4d4;object-fit:contain}#message{min-height:24px}small{display:block;margin:12px 0;color:#525252}#site{flex:1;min-width:220px}summary{cursor:pointer}#status{font-variant-numeric:tabular-nums}button:disabled{opacity:.5;cursor:default}
</style>
<h1>Connect Microsoft</h1>
<p class="note">Sign in, select “Finish sign-in”, then confirm access in the terminal.</p>
<p id="status">Connecting …</p>
<nav><button data-action="back">Back</button><button data-action="reload">Reload</button><button data-service="login">Microsoft sign-in</button><button id="extend">Extend time</button><button id="finish">Finish sign-in</button></nav>
<p id="message" role="status"></p>
<img id="screen" tabindex="0" alt="Server browser — click to interact, then type or paste">
<details><summary>Sign-in stuck?</summary><p>For passkey or Touch ID prompts, select “Microsoft sign-in” and choose “Other sign-in options” if available. This viewer cannot use your local Touch ID.</p></details>
<details><summary>Connection details</summary><p>Microsoft host: <strong id="host">–</strong></p><p id="network"></p></details>
<details><summary>Other services</summary><nav><button data-service="teams">Open Teams</button><button data-service="mail">Open mailbox</button><button data-service="calendar">Open calendar</button><button data-service="onedrive">Open OneDrive</button></nav>
<nav><input id="site" type="url" placeholder="https://your-organization.sharepoint.com/sites/…" aria-label="SharePoint site"><button id="sharepoint">Open SharePoint site</button></nav>
</details>
<script nonce="${nonce}">
const screen=document.getElementById('screen'),message=document.getElementById('message'),status=document.getElementById('status');
let active=true,finishing=false,expires=0,chain=Promise.resolve(),pending=0,lastQueued=null,lastAction=0,lastFrame=0,snapshotPromise=null;
async function api(path,data){const r=await fetch(path,{method:data===undefined?'GET':'POST',headers:data===undefined?{}:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});const b=await r.json();if(!r.ok){const e=new Error(b.error||'Connection failed');e.status=r.status;throw e}return b}
function error(e){message.textContent=e.message||'Connection lost. Continue in the terminal.'}
// Serialize screenshots and input; merge only adjacent, not-yet-dispatched text.
// At most four input batches plus four frames per second stays below the server limit.
async function refresh(force=false){
  if(snapshotPromise)return snapshotPromise;
  if(!force&&Date.now()-lastFrame<250)return;
  snapshotPromise=(async()=>{const s=await api('/state');if(!active)return;screen.src='data:image/png;base64,'+s.image;document.getElementById('host').textContent=s.host;expires=s.expires;document.getElementById('network').textContent=s.blockedHosts?.length?'Blocked hosts: '+s.blockedHosts.join(', '):'No blocked hosts.';lastFrame=Date.now()})().finally(()=>{snapshotPromise=null});
  return snapshotPromise;
}
function send(data){
  if(!active||finishing)return;
  if(data.type==='text'&&lastQueued?.type==='text'&&lastQueued.text.length+data.text.length<=4096){lastQueued.text+=data.text;return}
  if(data.type==='wheel'&&lastQueued?.type==='wheel'&&data.x===lastQueued.x&&data.y===lastQueued.y&&Math.sign(data.deltaY)===Math.sign(lastQueued.deltaY)&&Math.abs(data.deltaY+lastQueued.deltaY)<=2000){lastQueued.deltaY+=data.deltaY;return}
  if(pending>=64){message.textContent='Too many inputs. Wait briefly, then repeat the last input.';return}
  pending++;lastQueued=data;
  chain=chain.then(async()=>{
    const wait=Math.max(0,250-(Date.now()-lastAction));if(wait)await new Promise(r=>setTimeout(r,wait));
    // A failed idle frame must not discard independent, unsent input.
    try{await snapshotPromise}catch(e){if(e.status===401||e.status===410)throw e}
    if(lastQueued===data)lastQueued=null;
    if(!active)return;
    let accepted=false;
    for(let n=0;n<8;n++){
      try{await api('/action',data);accepted=true;lastAction=Date.now();message.textContent='';break}
      catch(e){if(e.status!==409)throw e;await new Promise(r=>setTimeout(r,150))}
    }
    if(!accepted)throw new Error('Browser busy. Repeat the input.');
    // A failed frame must never replay an already accepted click or keystroke.
    await refresh(true);
  }).catch(e=>{error(e);if(e.status===401||e.status===410)active=false}).finally(()=>{if(lastQueued===data)lastQueued=null;pending--});
}
function coords(e){const r=screen.getBoundingClientRect();return{x:Math.min(1099,Math.max(0,Math.round((e.clientX-r.left)*1100/r.width))),y:Math.min(779,Math.max(0,Math.round((e.clientY-r.top)*780/r.height)))}}
screen.onclick=e=>{screen.focus();send({type:'click',...coords(e)})};
screen.addEventListener('wheel',e=>{e.preventDefault();send({type:'wheel',...coords(e),deltaY:Math.max(-2000,Math.min(2000,e.deltaY))})},{passive:false});
screen.onkeydown=e=>{if(e.metaKey||(e.ctrlKey&&!e.getModifierState('AltGraph')))return;if(e.key.length===1){e.preventDefault();send({type:'text',text:e.key})}else if(['Enter','Tab','Escape','Backspace','Delete','ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End'].includes(e.key)){e.preventDefault();send({type:'key',key:e.key,shift:e.shiftKey})}};
screen.onpaste=e=>{e.preventDefault();const text=e.clipboardData.getData('text/plain');if(text.length>4096){message.textContent='Paste up to 4096 characters at a time.';return}send({type:'text',text})};
document.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>send({type:b.dataset.action}));
document.querySelectorAll('[data-service]').forEach(b=>b.onclick=()=>send({type:'service',service:b.dataset.service}));
document.getElementById('sharepoint').onclick=()=>send({type:'service',service:'sharepoint',site:document.getElementById('site').value});
document.getElementById('extend').onclick=async()=>{try{expires=(await api('/extend',{})).expires;message.textContent='Sign-in time extended.'}catch(e){error(e)}};
document.getElementById('finish').onclick=async()=>{if(finishing||!active)return;finishing=true;try{await chain;await snapshotPromise;if(!active)return;await api('/finish',{});active=false;screen.removeAttribute('src');status.textContent='Confirm access in the terminal.';document.querySelectorAll('button').forEach(b=>b.disabled=true)}catch(e){error(e)}finally{finishing=false}};
async function poll(){if(!active)return;try{if(!pending&&!finishing)await refresh()}catch(e){if(e.status!==409){error(e);if(e.status===401||e.status===410)active=false}}if(active)setTimeout(poll,250)}
setInterval(()=>{if(!active||!expires)return;const sec=Math.max(0,Math.ceil((expires-Date.now())/1000));status.textContent='Time remaining: '+Math.floor(sec/60)+':'+String(sec%60).padStart(2,'0');if(!sec){active=false;screen.removeAttribute('src');message.textContent='Sign-in expired. Run the new command in the terminal.'}},1000);
(async()=>{try{const token=location.hash.slice(1);history.replaceState(null,'','/');if(token)await api('/unlock',{token});await poll()}catch(e){error(e)}})();
</script></html>`;
}
