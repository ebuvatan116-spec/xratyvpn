(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const form = $('profile-form');
  const fields = ['name','protocol','address','port','identity','alterId','password','method','security','network','flow','sni','fingerprint','publicKey','shortId','realitySni','realityFlow','host','path','serviceName','alpn','allowInsecure'];
  const storeKey = 'node-xray-profiles-v1';
  let current = null;
  let currentOutputs = null;
  let activeTab = 'uri';
  let toastTimer;

  function showToast(message) {
    const node = $('toast'); node.textContent = message; node.classList.add('show');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => node.classList.remove('show'), 2600);
  }
  function b64Encode(text) {
    const bytes = new TextEncoder().encode(text);
    let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }
  function b64Decode(text) {
    const clean = text.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(clean + '='.repeat((4 - clean.length % 4) % 4));
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }
  function b64url(text) { return b64Encode(text).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
  function safeName(s) { return (s || 'xray-profile').normalize('NFKD').replace(/[^\w\u0600-\u06ff-]+/g,'-').replace(/^-+|-+$/g,'').slice(0,64) || 'xray-profile'; }
  function esc(s) { return String(s ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }
  function readForm() {
    return {
      name:$('name').value.trim(), protocol:$('protocol').value, address:$('address').value.trim(), port:Number($('port').value),
      identity:$('identity').value.trim(), alterId:Number($('alterId').value || 0), password:$('password').value,
      method:$('method').value, security:$('security').value, network:$('network').value, flow:$('flow').value,
      sni:$('security').value === 'reality' ? $('realitySni').value.trim() : $('sni').value.trim(),
      fingerprint:$('fingerprint').value, publicKey:$('publicKey').value.trim(), shortId:$('shortId').value.trim(),
      realityFlow:$('realityFlow').value, host:$('host').value.trim(), path:$('path').value.trim(),
      serviceName:$('serviceName').value.trim(), alpn:$('alpn').value.trim(), allowInsecure:$('allowInsecure').checked
    };
  }
  function validate(p) {
    if (!p.name) return 'نام پروفایل را وارد کن.';
    if (!p.address || /[\s/@]/.test(p.address)) return 'آدرس سرور را به‌صورت دامنه یا IP معتبر وارد کن.';
    if (!Number.isInteger(p.port) || p.port < 1 || p.port > 65535) return 'پورت باید عدد صحیح بین ۱ تا ۶۵۵۳۵ باشد.';
    if (p.protocol === 'vless' || p.protocol === 'vmess') {
      if (!p.identity) return 'UUID کاربر لازم است.';
      if (p.protocol === 'vless' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(p.identity)) return 'UUID در قالب استاندارد نیست؛ مقدار را بررسی کن.';
    }
    if (p.protocol === 'trojan' && !p.password) return 'رمز Trojan را وارد کن.';
    if (p.protocol === 'shadowsocks' && !p.password) return 'رمز Shadowsocks را وارد کن.';
    if (p.protocol === 'vless' && p.security === 'reality' && !p.publicKey) return 'کلید عمومی Reality لازم است.';
    if (p.protocol === 'vless' && p.security === 'reality' && !p.sni) return 'SNI برای Reality لازم است.';
    if (p.network === 'grpc' && !p.serviceName && p.protocol !== 'shadowsocks') return 'برای gRPC نام سرویس را وارد کن.';
    return '';
  }
  function encodedQuery(entries) {
    const q = new URLSearchParams();
    for (const [k,v] of entries) if (v !== undefined && v !== null && String(v) !== '') q.set(k, String(v));
    return q.toString();
  }
  function toUri(p) {
    const tag = encodeURIComponent(p.name);
    if (p.protocol === 'vless') {
      const items = [['encryption','none'],['security',p.security],['type',p.network]];
      if (p.security === 'tls') { items.push(['sni',p.sni],['fp',p.fingerprint],['alpn',p.alpn],['allowInsecure',p.allowInsecure?'1':'']); }
      if (p.security === 'reality') { items.push(['sni',p.sni],['fp',p.fingerprint],['pbk',p.publicKey],['sid',p.shortId],['flow',p.flow || p.realityFlow],['spx',p.path || '/']); }
      else if (p.flow) items.push(['flow',p.flow]);
      if (p.network === 'ws') items.push(['host',p.host],['path',p.path || '/']);
      if (p.network === 'grpc') items.push(['serviceName',p.serviceName],['authority',p.host]);
      if (p.network === 'httpupgrade' || p.network === 'xhttp') items.push(['host',p.host],['path',p.path || '/']);
      return `vless://${encodeURIComponent(p.identity)}@${p.address}:${p.port}?${encodedQuery(items)}#${tag}`;
    }
    if (p.protocol === 'vmess') {
      const obj = {v:'2',ps:p.name,add:p.address,port:String(p.port),id:p.identity,aid:String(p.alterId),scy:'auto',net:p.network,type:'none',host:p.host,path:p.network==='grpc'?p.serviceName:(p.path||''),tls:p.security==='tls'?'tls':'',sni:p.sni,fp:p.fingerprint,alpn:p.alpn};
      if (p.allowInsecure) obj.allowInsecure=true;
      return `vmess://${b64Encode(JSON.stringify(obj))}`;
    }
    if (p.protocol === 'trojan') {
      const entries = [['security',p.security],['sni',p.sni],['type',p.network],['fp',p.fingerprint],['alpn',p.alpn],['allowInsecure',p.allowInsecure?'1':'']];
      if (p.network === 'ws') entries.push(['host',p.host],['path',p.path || '/']);
      if (p.network === 'grpc') entries.push(['serviceName',p.serviceName],['authority',p.host]);
      if (p.network === 'httpupgrade' || p.network === 'xhttp') entries.push(['host',p.host],['path',p.path || '/']);
      return `trojan://${encodeURIComponent(p.password)}@${p.address}:${p.port}?${encodedQuery(entries)}#${tag}`;
    }
    const userPass = b64Encode(`${p.method}:${p.password}`).replace(/=+$/,'');
    return `ss://${userPass}@${p.address}:${p.port}#${tag}`;
  }
  function streamSettings(p) {
    const stream = {network:p.protocol === 'shadowsocks' ? 'tcp' : p.network, security:p.protocol === 'shadowsocks' ? 'none' : p.security};
    if (stream.security === 'tls') stream.tlsSettings = {serverName:p.sni || p.address,allowInsecure:!!p.allowInsecure,fingerprint:p.fingerprint || 'chrome',...(p.alpn?{alpn:p.alpn.split(',').map(x=>x.trim()).filter(Boolean)}:{})};
    if (stream.security === 'reality') stream.realitySettings = {serverName:p.sni, fingerprint:p.fingerprint || 'chrome', publicKey:p.publicKey, shortId:p.shortId || '', spiderX:p.path || '/', show:false};
    if (stream.network === 'ws') stream.wsSettings = {path:p.path || '/',headers:p.host?{Host:p.host}:{}};
    if (stream.network === 'grpc') stream.grpcSettings = {serviceName:p.serviceName || '',authority:p.host || '',multiMode:false};
    if (stream.network === 'httpupgrade') stream.httpupgradeSettings = {path:p.path || '/',host:p.host || ''};
    if (stream.network === 'xhttp') stream.xhttpSettings = {path:p.path || '/',host:p.host || '',mode:'auto'};
    return stream;
  }
  function outbound(p) {
    const stream = streamSettings(p);
    if (p.protocol === 'vless') return {tag:'proxy',protocol:'vless',settings:{vnext:[{address:p.address,port:p.port,users:[{id:p.identity,encryption:'none',...(p.flow || (p.security==='reality'?p.realityFlow:''))?{flow:p.flow || p.realityFlow}:{}}]}]},streamSettings:stream};
    if (p.protocol === 'vmess') return {tag:'proxy',protocol:'vmess',settings:{vnext:[{address:p.address,port:p.port,users:[{id:p.identity,alterId:p.alterId,security:'auto'}]}]},streamSettings:stream};
    if (p.protocol === 'trojan') return {tag:'proxy',protocol:'trojan',settings:{servers:[{address:p.address,port:p.port,password:p.password,level:0}]},streamSettings:stream};
    return {tag:'proxy',protocol:'shadowsocks',settings:{servers:[{address:p.address,port:p.port,method:p.method,password:p.password,level:0,uot:true}]},streamSettings:stream};
  }
  function makeJson(p) {
    const inbound = {tag:'socks-in',listen:'127.0.0.1',port:10808,protocol:'socks',settings:{auth:'noauth',udp:true,ip:'127.0.0.1'},sniffing:{enabled:true,destOverride:['http','tls','quic']}};
    return {log:{loglevel:'warning'},inbounds:[inbound],outbounds:[outbound(p),{tag:'direct',protocol:'freedom',settings:{}},{tag:'block',protocol:'blackhole',settings:{}}],routing:{domainStrategy:'IPIfNonMatch',rules:[{type:'field',inboundTag:['socks-in'],outboundTag:'proxy'}]}};
  }
  function makeShareUrl(p) {
    const url = new URL(location.href); url.hash = `profile=${b64url(JSON.stringify(p))}`; return url.toString();
  }
  function renderOutput() {
    if (!current || !currentOutputs) return;
    const output = activeTab === 'uri' ? currentOutputs.uri : activeTab === 'json' ? currentOutputs.json : currentOutputs.share;
    $('output-text').textContent = output;
    $('output-label').textContent = activeTab === 'uri' ? 'Share URI' : activeTab === 'json' ? 'Xray JSON · SOCKS 10808' : 'لینک سازنده با پروفایل';
    $('download-output').classList.toggle('hidden', activeTab === 'share');
    $('copy-share').classList.toggle('hidden', activeTab !== 'share');
    $('copy-output').textContent = activeTab === 'share' ? 'کپی لینک' : 'کپی خروجی';
    $('result-card').classList.add('has-result');
  }
  function showResult(p) {
    current = p;
    const uri = toUri(p), json = JSON.stringify(makeJson(p), null, 2), share = makeShareUrl(p);
    currentOutputs = {uri,json,share};
    $('empty-state').classList.add('hidden'); $('result-content').classList.remove('hidden');
    $('result-indicator').classList.add('is-ready'); $('result-indicator').innerHTML = '<i></i> خروجی آماده';
    $('result-name').textContent = p.name; $('result-protocol').textContent = p.protocol.toUpperCase();
    $('result-endpoint').textContent = `${p.address}:${p.port}`; $('profile-avatar').textContent = p.protocol.slice(0,1).toUpperCase();
    $('save-profile').classList.toggle('saved',getProfiles().some(x=>fingerprint(x)===fingerprint(p)));
    renderOutput();
  }
  function resetResult() {
    current = null; currentOutputs = null; $('empty-state').classList.remove('hidden'); $('result-content').classList.add('hidden');
    $('result-indicator').classList.remove('is-ready'); $('result-indicator').innerHTML = '<i></i> منتظر ورودی';
  }
  function fingerprint(p) { return `${p.protocol}|${p.address}|${p.port}|${p.identity}|${p.password}|${p.name}`; }
  function getProfiles() { try { const x=JSON.parse(localStorage.getItem(storeKey)||'[]'); return Array.isArray(x)?x:[]; } catch { return []; } }
  function putProfiles(list) { localStorage.setItem(storeKey,JSON.stringify(list.slice(0,100))); renderSaved(); }
  function saveCurrent(silent=false) {
    if (!current) return;
    const list=getProfiles();
    if (list.some(x=>fingerprint(x)===fingerprint(current))) { if (!silent) showToast('این پروفایل از قبل ذخیره شده است.'); return; }
    list.unshift({...current,savedAt:new Date().toISOString()}); putProfiles(list);
    $('save-profile').classList.add('saved'); $('save-profile').textContent='★'; if(!silent) showToast('پروفایل فقط روی همین دستگاه ذخیره شد.');
  }
  function renderSaved() {
    const list=getProfiles(); $('saved-count').textContent=String(list.length); $('saved-caption').textContent=`${list.length} پروفایل ذخیره‌شده روی همین دستگاه`;
    $('saved-list').innerHTML=list.map((p,i)=>`<div class="saved-row"><div class="profile-avatar">${esc((p.protocol||'x').slice(0,1).toUpperCase())}</div><div class="saved-info"><strong>${esc(p.name)}</strong><small>${esc((p.protocol||'').toUpperCase())} · ${esc(p.address)}:${esc(p.port)}</small></div><button data-load="${i}">بازکردن</button><button class="delete-saved" data-delete="${i}" title="حذف">حذف</button></div>`).join('');
    $('saved-empty').classList.toggle('hidden',list.length>0); $('saved-list').classList.toggle('hidden',list.length===0);
    $('saved-list').querySelectorAll('[data-load]').forEach(btn=>btn.addEventListener('click',()=>{const p=getProfiles()[Number(btn.dataset.load)];fillForm(p);navigate('builder');showResult(p);showToast('پروفایل باز شد.')}));
    $('saved-list').querySelectorAll('[data-delete]').forEach(btn=>btn.addEventListener('click',()=>{const a=getProfiles();a.splice(Number(btn.dataset.delete),1);putProfiles(a);}));
  }
  function setIf(id,value) { const e=$(id); if(e && value!==undefined && value!==null) e.value=String(value); }
  function fillForm(p) {
    for(const k of fields) if(p[k]!==undefined) setIf(k,p[k]);
    if(p.security==='reality'){setIf('realitySni',p.sni);setIf('realityFlow',p.realityFlow||p.flow);}
    else setIf('sni',p.sni);
    updateFields(); $('form-error').textContent='';
  }
  function updateFields() {
    const proto=$('protocol').value, security=$('security').value, network=$('network').value;
    const ss=proto==='shadowsocks', vmess=proto==='vmess', trojan=proto==='trojan', vless=proto==='vless';
    $('identity-row').classList.toggle('hidden',ss||trojan);
    $('alterid-field').classList.toggle('hidden',!vmess);
    $('method-field').classList.toggle('hidden',!ss);
    $('password-row').classList.toggle('hidden',!(ss||trojan));
    $('password-label').innerHTML = (trojan?'رمز عبور':'رمز عبور')+' <b>*</b>';
    $('security').disabled=ss;
    if(ss){$('security').value='none';$('network').value='tcp';}
    $('transport-security-row').classList.toggle('hidden',ss);
    const realityAllowed=vless;
    for(const opt of $('security').options) if(opt.value==='reality') opt.disabled=!realityAllowed;
    if(!realityAllowed && security==='reality') $('security').value='tls';
    const sec=$('security').value;
    $('flow-field').classList.toggle('hidden',!vless || sec==='reality');
    $('reality-row').classList.toggle('hidden',!(vless&&sec==='reality'));
    $('tls-row').classList.toggle('hidden',!(sec==='tls'&&!ss));
    $('alpn-row').classList.toggle('hidden',!(sec==='tls'&&!ss));
    $('insecure-row').classList.toggle('hidden',!(sec==='tls'&&!ss));
    const transportVisible=!ss && ['ws','grpc','httpupgrade','xhttp'].includes(network);
    $('transport-row').classList.toggle('hidden',!transportVisible);
    $('host-field').classList.toggle('hidden',network==='grpc');
    $('path-field').classList.toggle('hidden',network==='grpc');
    $('service-field').classList.toggle('hidden',network!=='grpc');
    $('protocol-hint').textContent=proto==='vless'?'پروتکل سبک برای Xray؛ TLS یا Reality و چند انتقال':'';
    $('identity-label').innerHTML=(vmess?'UUID': 'UUID')+' <b>*</b>';
    $('identity').required=!ss&&!trojan;
    $('password').required=ss||trojan;
    $('method').required=ss;
    $('publicKey').required=vless&&sec==='reality'; $('realitySni').required=vless&&sec==='reality';
  }
  function navigate(view) {
    document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id===`view-${view}`));
    document.querySelectorAll('.nav-item').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
    const labels={builder:'سازنده کانفیگ',import:'ورود / تبدیل',saved:'ذخیره‌شده‌ها'}; $('crumb-current').textContent=labels[view]||labels.builder;
    window.scrollTo({top:0,behavior:'smooth'});
  }
  function parseUri(line) {
    const text=line.trim();
    if(text.startsWith('vmess://')) {
      const raw=text.slice(8).split('#')[0]; const o=JSON.parse(b64Decode(raw));
      return {name:o.ps||'VMess',protocol:'vmess',address:o.add,port:Number(o.port),identity:o.id,alterId:Number(o.aid||0),security:o.tls==='tls'?'tls':'none',network:o.net||'tcp',host:o.host||'',path:o.net==='grpc'?'':(o.path||''),serviceName:o.net==='grpc'?(o.path||''):'' ,sni:o.sni||'',fingerprint:o.fp||'chrome',alpn:o.alpn||'',allowInsecure:!!o.allowInsecure};
    }
    if(text.startsWith('ss://')) {
      let body=text.slice(5),tag='Shadowsocks'; const hash=body.indexOf('#'); if(hash>=0){tag=decodeURIComponent(body.slice(hash+1));body=body.slice(0,hash);}
      let creds,hostport;
      if(body.includes('@')){[creds,hostport]=body.split('@');try{creds=b64Decode(creds.replace(/=+$/,''));}catch{creds=decodeURIComponent(creds);}}
      else {const decoded=b64Decode(body); const at=decoded.lastIndexOf('@'); creds=decoded.slice(0,at);hostport=decoded.slice(at+1);}
      const sep=creds.indexOf(':'); if(sep<0) throw Error('لینک Shadowsocks قالب روش:رمز ندارد.');
      const [address,port]=hostport.replace(/^\[|\]$/g,'').split(/:(?=\d+$)/);
      return {name:tag,protocol:'shadowsocks',address,port:Number(port),method:creds.slice(0,sep),password:creds.slice(sep+1),security:'none',network:'tcp'};
    }
    if(text.startsWith('vless://')||text.startsWith('trojan://')) {
      const u=new URL(text), protocol=text.startsWith('vless://')?'vless':'trojan', q=u.searchParams, network=q.get('type')||q.get('network')||'tcp', security=q.get('security')||'tls';
      const p={name:decodeURIComponent(u.hash.slice(1))||(protocol.toUpperCase()),protocol,address:u.hostname,port:Number(u.port||443),identity:protocol==='vless'?decodeURIComponent(u.username):'',password:protocol==='trojan'?decodeURIComponent(u.username):'',security,network,sni:q.get('sni')||'',fingerprint:q.get('fp')||'chrome',publicKey:q.get('pbk')||q.get('publicKey')||'',shortId:q.get('sid')||'',flow:q.get('flow')||'',realityFlow:q.get('flow')||'xtls-rprx-vision',host:q.get('host')||q.get('authority')||'',path:q.get('path')||q.get('spx')||'/',serviceName:q.get('serviceName')||q.get('service')||'',alpn:q.get('alpn')||'',allowInsecure:q.get('allowInsecure')==='1'};
      if(network==='grpc'&&!p.serviceName) p.serviceName=q.get('path')||'';
      return p;
    }
    throw Error('فرمت لینک پشتیبانی نمی‌شود.');
  }
  function fromOutbound(out) {
    const proto=out.protocol, st=out.streamSettings||{}, sec=st.security||'none', set=out.settings||{};
    if(!['vless','vmess','trojan','shadowsocks'].includes(proto)) throw Error(`پروتکل ${proto||'نامشخص'} در این ابزار پشتیبانی نمی‌شود.`);
    let node, user;
    if(proto==='vless'||proto==='vmess'){node=set.vnext?.[0];user=node?.users?.[0];}
    else {node=set.servers?.[0];user=node;}
    if(!node||!user) throw Error('ساختار outbound برای تبدیل کامل نیست.');
    const tls=st.tlsSettings||{}, reality=st.realitySettings||{}, ws=st.wsSettings||{}, grpc=st.grpcSettings||{}, hu=st.httpupgradeSettings||{}, xh=st.xhttpSettings||{};
    const network=st.network||'tcp';
    return {name:out.tag||proto.toUpperCase(),protocol:proto,address:node.address,port:Number(node.port),identity:proto==='vless'||proto==='vmess'?user.id:'',alterId:Number(user.alterId||0),password:proto==='trojan'||proto==='shadowsocks'?user.password:'',method:proto==='shadowsocks'?user.method:undefined,security:sec,network,flow:user.flow||'',sni:sec==='reality'?reality.serverName:(tls.serverName||''),fingerprint:sec==='reality'?reality.fingerprint:(tls.fingerprint||'chrome'),publicKey:reality.publicKey||'',shortId:reality.shortId||'',realityFlow:user.flow||'xtls-rprx-vision',host:network==='ws'?(ws.headers?.Host||''):network==='grpc'?(grpc.authority||''):network==='httpupgrade'?hu.host||'':xh.host||'',path:network==='ws'?ws.path||'':network==='grpc'?(grpc.serviceName||''):network==='httpupgrade'?hu.path||'':xh.path||'',serviceName:grpc.serviceName||'',alpn:(tls.alpn||[]).join(','),allowInsecure:!!tls.allowInsecure};
  }
  function parseImportText(text) {
    const lines=text.split(/[\r\n]+/).map(s=>s.trim()).filter(s=>s&&!s.startsWith('#')&&!s.startsWith('//'));
    if(!lines.length) throw Error('لینک یا JSON را وارد کن.');
    if(lines[0].startsWith('{')) {
      const obj=JSON.parse(text);
      if(Array.isArray(obj.outbounds)) return obj.outbounds.filter(o=>o.tag!=='direct'&&o.tag!=='block'&&o.protocol!=='freedom'&&o.protocol!=='blackhole').map(fromOutbound);
      if(obj.protocol) return [fromOutbound(obj)];
      throw Error('در JSON outbound قابل‌تبدیلی پیدا نشد.');
    }
    return lines.map(parseUri);
  }
  function handleImport() {
    const error=$('import-error'); error.textContent='';
    try {
      const profiles=parseImportText($('import-text').value);
      if(!profiles.length) throw Error('پروفایل پشتیبانی‌شده‌ای پیدا نشد.');
      const valid=profiles.map(p=>({...defaults(),...p}));
      const issues=valid.map(validate).filter(Boolean);
      if(issues.length) throw Error(`ورودی ناقص است: ${issues[0]}`);
      if(valid.length>1){
        const old=getProfiles(), added=[];
        for(const p of valid) if(!old.some(x=>fingerprint(x)===fingerprint(p))) {old.unshift({...p,savedAt:new Date().toISOString()});added.push(p);}
        putProfiles(old); fillForm(valid[0]); showResult(valid[0]); navigate('builder');
        showToast(`${valid.length} پروفایل وارد شد؛ ${added.length} مورد جدید در همین دستگاه ذخیره شد.`);
      } else { fillForm(valid[0]); navigate('builder'); form.requestSubmit(); }
    } catch(e){error.textContent=e.message||'ورودی قابل‌خواندن نیست.';}
  }
  function defaults(){return {name:'',protocol:'vless',address:'',port:443,identity:'',alterId:0,password:'',method:'aes-128-gcm',security:'tls',network:'tcp',flow:'',sni:'',fingerprint:'chrome',publicKey:'',shortId:'',realityFlow:'xtls-rprx-vision',host:'',path:'/',serviceName:'',alpn:'',allowInsecure:false};}

  $('protocol').addEventListener('change',updateFields); $('security').addEventListener('change',updateFields); $('network').addEventListener('change',updateFields);
  form.addEventListener('submit',e=>{e.preventDefault();const p=readForm(), err=validate(p);$('form-error').textContent=err;if(err)return;showResult(p);});
  $('reset-form').addEventListener('click',()=>{form.reset();$('port').value='443';$('method').value='aes-128-gcm';$('path').value='/';$('fingerprint').value='chrome';$('form-error').textContent='';updateFields();resetResult();});
  $('dismiss-notice').addEventListener('click',()=>document.querySelector('.notice').classList.add('hidden'));
  $('save-profile').addEventListener('click',()=>saveCurrent());
  document.querySelectorAll('.tab').forEach(t=>t.addEventListener('click',()=>{activeTab=t.dataset.tab;document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===t));renderOutput();}));
  async function copyText(text) { try {await navigator.clipboard.writeText(text);} catch {const ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';document.body.append(ta);ta.select();document.execCommand('copy');ta.remove();} showToast('در کلیپ‌بورد کپی شد.'); }
  $('copy-output').addEventListener('click',()=>{if(currentOutputs)copyText(activeTab==='uri'?currentOutputs.uri:activeTab==='json'?currentOutputs.json:currentOutputs.share);});
  $('copy-share').addEventListener('click',()=>currentOutputs&&copyText(currentOutputs.share));
  $('download-output').addEventListener('click',()=>{
    if(!currentOutputs)return;const content=activeTab==='json'?currentOutputs.json:currentOutputs.uri;
    const type=activeTab==='json'?'application/json':'text/plain';const ext=activeTab==='json'?'json':'txt';
    const blob=new Blob([content],{type:`${type};charset=utf-8`}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`${safeName(current.name)}.${ext}`;a.click();URL.revokeObjectURL(a.href);
  });
  document.querySelectorAll('.nav-item').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.view)));
  $('import-link-shortcut').addEventListener('click',()=>navigate('import'));
  $('parse-import').addEventListener('click',handleImport);
  $('clear-import').addEventListener('click',()=>{$('import-text').value='';$('import-error').textContent='';});
  $('import-file-btn').addEventListener('click',()=>$('import-file').click());
  $('import-file').addEventListener('change',async e=>{const f=e.target.files?.[0];if(f)$('import-text').value=await f.text();e.target.value='';});
  $('clear-saved').addEventListener('click',()=>{if(getProfiles().length&&!confirm('همه پروفایل‌های ذخیره‌شده در این مرورگر حذف شوند؟'))return;putProfiles([]);showToast('فهرست محلی پاک شد.');});
  $('theme-toggle').addEventListener('click',()=>{document.body.classList.toggle('light-mode');localStorage.setItem('node-xray-theme',document.body.classList.contains('light-mode')?'light':'dark');});
  if(localStorage.getItem('node-xray-theme')==='light')document.body.classList.add('light-mode');
  // Restore a profile encoded only in the URL fragment; fragments are not sent in HTTP requests.
  if(location.hash.startsWith('#profile=')) {
    try {const p={...defaults(),...JSON.parse(b64Decode(decodeURIComponent(location.hash.slice(9))))};fillForm(p);const err=validate(p);if(!err)showResult(p);}
    catch {showToast('لینک پروفایل قابل‌خواندن نیست.');}
  }
  updateFields(); renderSaved();
})();
