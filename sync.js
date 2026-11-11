/* Carnet nature : synchronisation chiffrée de bout en bout (Supabase).
   Le serveur ne reçoit que du contenu chiffré avec une clé dérivée du mot de passe du groupe.
   Dépend de LOCAL, S, openSheet, closeSheet, toast, esc, render (script principal). */
(function(){
const CFG=window.SYNC_CFG||{};
const enc=new TextEncoder(),dec=new TextDecoder();
const b64=buf=>{const a=new Uint8Array(buf);let s="";for(let i=0;i<a.length;i+=0x8000)s+=String.fromCharCode.apply(null,a.subarray(i,i+0x8000));return btoa(s)};
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const hash=str=>{let h=0x811c9dc5;for(let i=0;i<str.length;i++){h^=str.charCodeAt(i);h=Math.imul(h,0x01000193)}return (h>>>0).toString(36)+":"+str.length};
const J=v=>JSON.stringify(v===undefined?null:v);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

/* ---------- Chiffrement ---------- */
const CRY={
  async derive(pass,saltB64){const base=await crypto.subtle.importKey("raw",enc.encode(pass.normalize("NFC")),"PBKDF2",false,["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2",salt:unb64(saltB64),iterations:310000,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])},
  async seal(key,str){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(str));return{data:b64(ct),iv:b64(iv)}},
  async open(key,data,iv){return dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(iv)},key,unb64(data)))},
  salt(){return b64(crypto.getRandomValues(new Uint8Array(16)))}
};
const CHECK="carnet-nature:ok";

/* ---------- Serveur (Supabase) ---------- */
function supaBackend(){
  const sb=window.supabase.createClient(CFG.url,CFG.key,{auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true,storageKey:"carnet-sync-auth"}});
  const ok=r=>{if(r.error)throw r.error;return r.data};
  return{
    async session(){const {data}=await sb.auth.getSession();const u=data&&data.session&&data.session.user;return u?{uid:u.id,email:u.email}:null},
    onAuth(cb){sb.auth.onAuthStateChange((ev,ses)=>cb(ev,ses&&ses.user?{uid:ses.user.id,email:ses.user.email}:null))},
    async signUp(email,pw){const d=ok(await sb.auth.signUp({email,password:pw,options:{emailRedirectTo:location.origin+location.pathname}}));return{needConfirm:!d.session}},
    async signIn(email,pw){ok(await sb.auth.signInWithPassword({email,password:pw}))},
    async resetPw(email){ok(await sb.auth.resetPasswordForEmail(email,{redirectTo:location.origin+location.pathname}))},
    async setPw(pw){ok(await sb.auth.updateUser({password:pw}))},
    async signOut(){await sb.auth.signOut()},
    async spaces(){const d=ok(await sb.from("members").select("space_id,role,spaces(id,name,kdf_salt,check_blob)"));return d.map(r=>r.spaces).filter(Boolean)},
    async members(space){return ok(await sb.from("members").select("user_id,display_name,role,joined_at").eq("space_id",space))},
    async setName(space,uid,name){ok(await sb.from("members").update({display_name:name}).eq("space_id",space).eq("user_id",uid))},
    async createSpace(name,salt,check){return ok(await sb.from("spaces").insert({name,kdf_salt:salt,check_blob:check}).select().single())},
    async createInvite(space,code){ok(await sb.from("invites").insert({code,space_id:space}))},
    async join(code,name){const id=ok(await sb.rpc("join_space",{invite_code:code,name}));const all=await this.spaces();return all.find(s=>s.id===id)},
    async pull(space,since){const out=[];for(let i=0;;i+=500){const d=ok(await sb.from("docs").select("id,data,iv,deleted,updated_at").eq("space_id",space).gt("updated_at",since).not("id","like","photos/%").order("updated_at").range(i,i+499));out.push(...d);if(d.length<500)break}return out},
    async upsert(space,rows){ok(await sb.from("docs").upsert(rows.map(r=>({space_id:space,id:r.id,data:r.data,iv:r.iv,deleted:!!r.deleted})),{onConflict:"space_id,id"}))},
    async getOne(space,id){return ok(await sb.from("docs").select("id,data,iv,deleted,updated_at").eq("space_id",space).eq("id",id).maybeSingle())},
    async ai(prompt,json){const {data}=await sb.auth.getSession();const tok=data&&data.session&&data.session.access_token;if(!tok)throw new Error("Connexion requise");
      const r=await fetch(CFG.url+"/functions/v1/ia",{method:"POST",headers:{"Authorization":"Bearer "+tok,"apikey":CFG.key,"Content-Type":"application/json"},body:JSON.stringify({prompt,json:!!json})});
      const j=await r.json().catch(()=>({}));if(!r.ok){const e=new Error(j.error||("Erreur "+r.status));if(r.status===429)e.code="rate_limited";if(r.status===404)e.message="La fonction « ia » n'est pas encore installée dans Supabase.";throw e}return j.text||""},
    subscribe(space,cb){const ch=sb.channel("docs-"+space).on("postgres_changes",{event:"*",schema:"public",table:"docs",filter:"space_id=eq."+space},()=>cb()).subscribe();return()=>sb.removeChannel(ch)}
  }}

/* ---------- IA : prénoms remplacés avant l'envoi ---------- */
const ACC={a:"[aàâä]",e:"[eéèêë]",i:"[iîï]",o:"[oôö]",u:"[uùûü]",c:"[cç]",y:"[yÿ]"};
const strip=t=>t.normalize("NFD").replace(/[\u0300-\u036f]/g,"");
const tok=(p,i)=>p+"_"+(i<26?String.fromCharCode(65+i):String.fromCharCode(65+Math.floor(i/26)-1)+String.fromCharCode(65+i%26));
const IA_DEF=`Agis en tant qu'assistant de rédaction clinique pour une ergothérapeute et une éducatrice spécialisée (enfants de 0 à 12 ans en classe nature). Réécris les notes d'observation brutes au propre en respectant ces règles :
1. Ton clinique juste et équilibré (ni lunettes roses, ni lunettes noires) : rédige à la troisième personne (aucun « je » ni « nous »). Le texte doit être 100 % factuel et descriptif.
- Pas de lunettes noires : ne dramatise pas et ne sois pas centré uniquement sur les déficits. Décris les comportements difficiles de façon neutre (comme des obstacles à l'occupation), et nomme toujours les forces, les initiatives et les tentatives de l'enfant.
- Pas de lunettes roses : ne minimise pas les difficultés, n'édulcore pas la réalité avec des tournures embellies et n'invente pas d'intentions positives non observées.
2. Structure par habiletés : chaque note commence par le domaine clinique observé (ex. : « Motricité fine : », « Régulation émotionnelle : »).
3. Intégrité des faits : conserve tous les détails, les déclencheurs exacts, les durées et les mots prononcés par l'enfant (entre guillemets). Ne résume pas au point de perdre de l'information.
4. Orientation solutions (facilitateurs) : identifie clairement ce qui soutient l'enfant. Utilise au besoin « Stratégie de succès : » ou « À explorer : » pour mettre en valeur les adaptations de l'environnement ou les interventions de l'adulte qui ont fonctionné.`;
const IA={rules(){const d=LOCAL.cache.get("config/ia");return d&&typeof d.regles==="string"?d.regles:IA_DEF},
  setRules(v){db.doc("config/ia").set({regles:v})},
  on(){try{return localStorage.getItem("carnet-ia")==="1"}catch(e){return false}},
  set(v){try{localStorage.setItem("carnet-ia",v?"1":"0")}catch(e){}IA.apply()},
  apply(){sample=SYNC.on&&IA.on()?IA.sampler():null},
  table(){const pairs=[],back={};let k=0,a=0;
    S.children.forEach(c=>{if(!c||!c.name)return;const t=tok("Enfant",k++);back[t]=c.name;(typeof kidNames==="function"?kidNames(c):[c.name]).forEach(n=>pairs.push([n,t]))});
    const ad=new Set();try{if(getMe())ad.add(getMe())}catch(e){}try{(getSign()||[]).forEach(x=>x&&x.nom&&ad.add(x.nom))}catch(e){}(SYNC._mem||[]).forEach(m=>m.display_name&&ad.add(m.display_name));
    ad.forEach(full=>{const t=tok("Adulte",a++);back[t]=full.split(/\s+/)[0];full.split(/\s+/).filter(w=>w.length>1).forEach(w=>pairs.push([w,t]));pairs.push([full,t])});
    pairs.sort((x,y)=>y[0].length-x[0].length);
    return{rx:pairs.filter(p=>p[0].trim().length>1).map(([n,t])=>[new RegExp("(?<![\\p{L}\\p{N}_])"+[...strip(n.trim())].map(ch=>{const l=ch.toLowerCase();return ACC[l]||ch.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}).join("")+"(?![\\p{L}\\p{N}_])","giu"),t]),back}},
  mask(text){const T=IA.table();let s=String(text).normalize("NFC");T.rx.forEach(([r,t])=>{s=s.replace(r,t)});return{text:s,back:T.back}},
  unmask(s,back){return String(s).replace(/(Enfant|Adulte)_([A-Z]{1,2})(?![A-Za-z])/g,m=>back[m]||m)},
  async ask(prompt,json){const r=IA.rules().trim();if(r)prompt="CONSIGNES DE RÉDACTION DE L'ERGOTHÉRAPEUTE (à suivre pour tout texte que tu écris ; dans le carnet, chaque note reste une entrée séparée et tu respectes le format de réponse demandé plus bas) :\n"+r+"\n\n---\n\n"+prompt;const m=IA.mask(prompt);SYNC.lastSent=m.text;const t=await SYNC.be.ai(m.text,json);SYNC.lastGot=t;return IA.unmask(t,m.back)},
  parse(t){t=String(t).replace(/```(?:json)?/g,"");const i=t.search(/[\[{]/);const j=Math.max(t.lastIndexOf("}"),t.lastIndexOf("]"));if(i<0||j<i)throw {code:"format"};try{return JSON.parse(t.slice(i,j+1))}catch(e){throw {code:"format"}}},
  sampler(){const f=async(prompt,opts)=>{const t=await IA.ask(prompt,false);try{opts&&opts.onText&&opts.onText({text:t})}catch(e){}return{text:t}};
    f.json=async prompt=>IA.parse(await IA.ask(prompt,true));return f}};
window.SYNC_IA=IA;

/* ---------- Moteur ---------- */
const SYNC=window.SYNC={on:false,status:"off",msg:"",user:null,space:null,key:null,be:null,lastAt:null,busy:false,_t:null,_unsub:null,_tombLen:0,
  meta(){return LOCAL.meta.sync||(LOCAL.meta.sync={})},
  dirty(){return LOCAL.meta.dirty||(LOCAL.meta.dirty=[])},
  base(){return LOCAL.meta.base||(LOCAL.meta.base={})},
  async keyGet(){return LOCAL.req("meta","readonly",st=>st.get("synckey"))},
  async keyPut(k){return LOCAL.req("meta","readwrite",st=>k?st.put(k,"synckey"):st.delete("synckey"))},
  setStatus(s,msg){SYNC.status=s;SYNC.msg=msg||"";const el=document.getElementById("syncDot");if(el)el.outerHTML=SYNC.dot();if(document.querySelector("[data-sync-card]"))document.querySelector("[data-sync-card]").outerHTML=SYNC.card()},

  /* appelé par le stockage local à chaque écriture */
  mark(path){const d=SYNC.dirty();if(!d.includes(path))d.push(path);
    const tl=(LOCAL.meta.tomb||[]).length;if(tl!==SYNC._tombLen){SYNC._tombLen=tl;if(!d.includes("_tomb"))d.push("_tomb")}
    LOCAL.saveMeta();SYNC.schedule(1200)},
  markAll(newKeys,photoIds){const d=new Set(SYNC.dirty());[...LOCAL.cache.keys()].forEach(k=>d.add(k));(newKeys||[]).forEach(k=>d.add(k));(photoIds||[]).forEach(id=>d.add("photos/"+id));d.add("_tomb");LOCAL.meta.dirty=[...d]},
  markLocal(){const ids=new Set();S.children.forEach(c=>(c.photos||[]).forEach(p=>ids.add(p.id)));SYNC.markAll([],[...ids]);return LOCAL.saveMeta()},
  schedule(ms){if(!SYNC.on)return;clearTimeout(SYNC._t);SYNC._t=setTimeout(()=>SYNC.run(),ms||0)},

  async run(){if(!SYNC.on||SYNC.busy)return;if(!navigator.onLine){SYNC.setStatus("offline");return}
    SYNC.busy=true;try{await SYNC.pull();await SYNC.push();SYNC.lastAt=new Date();SYNC.setStatus(SYNC.dirty().length?"pending":"ok")}
    catch(e){console.warn("sync",e);SYNC.setStatus(navigator.onLine?"error":"offline",e&&e.message)}
    finally{SYNC.busy=false;if(SYNC._again){SYNC._again=false;SYNC.schedule(300)}}},

  async pull(){const m=SYNC.meta();const since=m.lastPull?new Date(new Date(m.lastPull).getTime()-5000).toISOString():"1970-01-01T00:00:00Z";
    const rows=await SYNC.be.pull(SYNC.space.id,since);let max=m.lastPull||null;
    for(const r of rows){await SYNC.applyRow(r);if(!max||r.updated_at>max)max=r.updated_at}
    if(max!==m.lastPull){m.lastPull=max;await LOCAL.saveMeta()}},

  async applyRow(r){const path=r.id;let val=null;
    if(!r.deleted){try{val=JSON.parse(await CRY.open(SYNC.key,r.data,r.iv))}catch(e){console.warn("déchiffrement impossible",path);return}}
    const h=hash(J(r.deleted?null:val));const base=SYNC.base();if(base[path]===h)return;
    const dirty=SYNC.dirty().includes(path);
    if(path==="_tomb"){const t=new Set([...(LOCAL.meta.tomb||[]),...(val||[])]);LOCAL.meta.tomb=[...t];SYNC._tombLen=t.size;base[path]=h;
      if(t.size>(val||[]).length&&!dirty)SYNC.dirty().push("_tomb");await LOCAL.saveMeta();return}
    const prev=LOCAL.cache.get(path);
    if(r.deleted||val===null){base[path]=h;if(dirty||prev===undefined){await LOCAL.saveMeta();return}
      LOCAL.cache.delete(path);await LOCAL.req("docs","readwrite",st=>st.delete(path));await LOCAL.saveMeta();LOCAL.notify(path,"removed");return}
    let next=val;
    if(dirty&&prev!==undefined){next=LOCAL.prune(LOCAL.mergeVal(prev,val,path.split("/"),[]),new Set(LOCAL.meta.tomb||[]))}
    base[path]=h;
    if(J(next)!==J(prev)){LOCAL.cache.set(path,next);await LOCAL.req("docs","readwrite",st=>st.put(next,path));await LOCAL.saveMeta();LOCAL.notify(path,prev===undefined?"added":"modified")}
    else await LOCAL.saveMeta()},

  async push(){const list=[...SYNC.dirty()];if(!list.length)return;
    const docs=list.filter(p=>!p.startsWith("photos/")),photos=list.filter(p=>p.startsWith("photos/"));
    const done=[];
    for(let i=0;i<docs.length;i+=40){const part=docs.slice(i,i+40);const rows=[];const hs={};
      for(const p of part){const v=p==="_tomb"?(LOCAL.meta.tomb||[]):LOCAL.cache.get(p);const del=v===undefined;const s=J(del?null:v);hs[p]=hash(s);
        const sealed=await CRY.seal(SYNC.key,s);rows.push({id:p,data:sealed.data,iv:sealed.iv,deleted:del})}
      await SYNC.be.upsert(SYNC.space.id,rows);
      part.forEach(p=>{SYNC.base()[p]=hs[p];const cur=p==="_tomb"?(LOCAL.meta.tomb||[]):LOCAL.cache.get(p);if(hash(J(cur===undefined?null:cur))===hs[p])done.push(p)})}
    for(const p of photos){const id=p.slice(7);const b=await LOCAL._getPhoto(id);let row;
      if(b){const du=await new Promise(r=>{const f=new FileReader();f.onload=()=>r(f.result);f.readAsDataURL(b)});const s=await CRY.seal(SYNC.key,du);row={id:p,data:s.data,iv:s.iv,deleted:false}}
      else{const s=await CRY.seal(SYNC.key,"null");row={id:p,data:s.data,iv:s.iv,deleted:true}}
      await SYNC.be.upsert(SYNC.space.id,[row]);done.push(p)}
    LOCAL.meta.dirty=SYNC.dirty().filter(p=>!done.includes(p));await LOCAL.saveMeta()},

  async fetchPhoto(id){if(!SYNC.on)return null;try{const r=await SYNC.be.getOne(SYNC.space.id,"photos/"+id);if(!r||r.deleted)return null;
    const du=await CRY.open(SYNC.key,r.data,r.iv);const b=await (await fetch(du)).blob();await LOCAL.req("photos","readwrite",st=>st.put(b,id));return b}catch(e){return null}},

  async goLive(){SYNC.on=true;SYNC._tombLen=(LOCAL.meta.tomb||[]).length;if(SYNC._unsub)SYNC._unsub();
    try{SYNC._unsub=SYNC.be.subscribe(SYNC.space.id,()=>{if(SYNC.busy)SYNC._again=true;else SYNC.schedule(400)})}catch(e){}
    SYNC.setStatus("pending");IA.apply();try{SYNC._mem=await SYNC.be.members(SYNC.space.id)}catch(e){}try{render()}catch(e){}await SYNC.run()},
  stop(){SYNC.on=false;IA.apply();clearTimeout(SYNC._t);if(SYNC._unsub){SYNC._unsub();SYNC._unsub=null}},

  async start(){if(SYNC.be)return;
    try{SYNC.be=window.SYNC_FAKE?window.SYNC_FAKE():supaBackend()}catch(e){SYNC.setStatus("error","Module de synchro absent");return}
    LOCAL._getPhoto=LOCAL.getPhoto.bind(LOCAL);
    LOCAL.getPhoto=async id=>{const b=await LOCAL._getPhoto(id);return b||(SYNC.on?await SYNC.fetchPhoto(id):null)};
    SYNC.be.onAuth&&SYNC.be.onAuth((ev,u)=>{if(ev==="PASSWORD_RECOVERY"){SYNC.user=u;SYNC.open("newpw")}if(ev==="SIGNED_OUT"){SYNC.user=null;SYNC.stop();SYNC.setStatus("off")}});
    try{SYNC.user=await SYNC.be.session()}catch(e){}
    const m=SYNC.meta();
    if(SYNC.user&&m.space&&m.uid===SYNC.user.uid){SYNC.space=m.space;SYNC.key=await SYNC.keyGet();if(SYNC.key)await SYNC.goLive();else SYNC.setStatus("locked")}
    else SYNC.setStatus("off");
    addEventListener("online",()=>SYNC.schedule(200));
    addEventListener("offline",()=>SYNC.on&&SYNC.setStatus("offline"));
    document.addEventListener("visibilitychange",()=>{if(document.visibilityState==="visible")SYNC.schedule(200)});
    setInterval(()=>{if(SYNC.on&&document.visibilityState==="visible")SYNC.schedule(0)},60000)},

  async link(space,pass,isNew){const key=await CRY.derive(pass,space.kdf_salt);
    if(!isNew){try{if(await CRY.open(key,...space.check_blob.split("."))!==CHECK)throw 0}catch(e){throw new Error("Mot de passe du groupe incorrect.")}}
    SYNC.key=key;SYNC.space={id:space.id,name:space.name};await SYNC.keyPut(key);
    const m=SYNC.meta();const first=m.space?.id!==space.id;m.space=SYNC.space;m.uid=SYNC.user.uid;
    if(first){m.lastPull=null;LOCAL.meta.base={};await SYNC.markLocal()}else await LOCAL.saveMeta();
    await SYNC.goLive()},

  /* ---------- Interface ---------- */
  label(){return{off:"Non activée",locked:"Mot de passe du groupe requis",pending:"Synchronisation…",ok:"À jour",offline:"Hors ligne : les changements partiront au retour du réseau",error:"Problème de synchro"}[SYNC.status]||""},
  dot(){const c={ok:"#3D6A4A",pending:"#C9A227",offline:"#9AA39A",error:"#B5523B",locked:"#B5523B",off:"#C8C2B4"}[SYNC.status];return `<span id="syncDot" title="${esc(SYNC.label())}" style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${c};vertical-align:middle;margin-left:6px"></span>`},
  card(){const n=SYNC.dirty().length;const t=SYNC.lastAt?SYNC.lastAt.toLocaleTimeString("fr-CA",{hour:"2-digit",minute:"2-digit"}):"";
    return `<section class="card" data-sync-card><div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><h3 style="font-size:1.35rem;margin:0">Synchronisation ${SYNC.dot()}</h3><span class="muted small">${esc(SYNC.label())}${SYNC.status==="ok"&&t?" · "+t:""}${SYNC.on&&n?" · "+n+" en attente":""}${SYNC.space?" · "+esc(SYNC.space.name):""}</span>
      <button class="btn small" data-sync="open" style="margin-left:auto">${SYNC.status==="off"?"Activer":"Gérer"}</button></div>
      ${SYNC.status==="error"&&SYNC.msg?`<p class="muted small" style="margin:6px 0 0">${esc(SYNC.msg)}</p>`:""}</section>`},

  open(view){
    const u=SYNC.user;
    if(view==="newpw")return openSheet(`<h3>Nouveau mot de passe</h3><label class="small">Mot de passe du compte<input class="inp" id="syNp" type="password" autocomplete="new-password"></label>
      <div class="row-actions"><button class="btn primary" id="syOk">Enregistrer</button></div>`,s=>{s.querySelector("#syOk").onclick=()=>SYNC.act(async()=>{await SYNC.be.setPw(s.querySelector("#syNp").value);toast("Mot de passe changé");closeSheet()})});
    if(!u)return openSheet(`<h3>Synchronisation</h3>
      <p class="muted small" style="margin:0 0 10px">Le carnet reste sur cet appareil et une copie <b>chiffrée</b> est gardée en ligne (serveur au Canada). Sans le mot de passe du groupe, personne ne peut la lire, même pas le serveur.</p>
      <label class="small">Courriel<input class="inp" id="syEm" type="email" autocomplete="email"></label>
      <label class="small">Mot de passe du compte<input class="inp" id="syPw" type="password" autocomplete="current-password"></label>
      <div class="row-actions"><button class="btn primary" id="syIn">Se connecter</button><button class="btn" id="syUp">Créer un compte</button><button class="btn ghost small" id="syFg">Mot de passe oublié</button></div>`,s=>{
        const v=()=>[s.querySelector("#syEm").value.trim(),s.querySelector("#syPw").value];
        s.querySelector("#syIn").onclick=()=>SYNC.act(async()=>{const [e,p]=v();await SYNC.be.signIn(e,p);SYNC.user=await SYNC.be.session();SYNC.open()});
        s.querySelector("#syUp").onclick=()=>SYNC.act(async()=>{const [e,p]=v();if(p.length<8)throw new Error("Au moins 8 caractères pour le mot de passe du compte.");const r=await SYNC.be.signUp(e,p);
          if(r.needConfirm){openSheet(`<h3>Vérifiez vos courriels</h3><p>Un lien de confirmation a été envoyé à <b>${esc(e)}</b>. Ouvrez-le sur cet appareil, puis revenez ici et connectez-vous.</p><div class="row-actions"><button class="btn primary" onclick="closeSheet()">OK</button></div>`)}
          else{SYNC.user=await SYNC.be.session();SYNC.open()}});
        s.querySelector("#syFg").onclick=()=>SYNC.act(async()=>{const [e]=v();if(!e)throw new Error("Écrivez d'abord votre courriel.");await SYNC.be.resetPw(e);toast("Lien envoyé par courriel")})});
    if(!SYNC.space||SYNC.status==="locked")return SYNC.act(async()=>{
      const list=SYNC.status==="locked"?[SYNC.meta().space]:await SYNC.be.spaces();
      openSheet(`<h3>Synchronisation</h3><p class="muted small" style="margin:0 0 8px">Connectée : ${esc(u.email)}</p>
      ${list.length?`<h4 style="margin:10px 0 4px">${SYNC.status==="locked"?"Déverrouiller":"Ouvrir un carnet en ligne"}</h4>
        ${list.length>1?`<select class="inp" id="sySp">${list.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join("")}</select>`:`<p style="margin:0 0 6px"><b>${esc(list[0].name)}</b></p>`}
        <label class="small">Mot de passe du groupe<input class="inp" id="syGp" type="password" autocomplete="off"></label>
        <label class="chk small"><input type="checkbox" id="syShow"> Afficher</label>
        <div class="row-actions"><button class="btn primary" id="syOpen">Ouvrir</button></div><hr>`:""}
      ${SYNC.status==="locked"?"":`<details${list.length?"":" open"}><summary><b>Créer un carnet en ligne</b></summary>
        <p class="muted small">Tout ce qui est sur cet appareil sera envoyé, chiffré. Le <b>mot de passe du groupe</b> sert à chiffrer : notez-le en lieu sûr. S'il est perdu, la copie en ligne est illisible (le carnet de l'appareil reste intact).</p>
        <label class="small">Nom<input class="inp" id="syNm" value="Carnet nature"></label>
        <label class="small">Mot de passe du groupe (au moins 10 caractères)<input class="inp" id="syG1" type="password" autocomplete="off"></label>
        <label class="small">Encore une fois<input class="inp" id="syG2" type="password" autocomplete="off"></label>
        <div class="row-actions"><button class="btn primary" id="syNew">Créer et envoyer</button></div></details>
      <details><summary><b>Rejoindre avec un code d'invitation</b></summary>
        <label class="small">Code<input class="inp" id="syCode" autocomplete="off" style="text-transform:uppercase"></label>
        <label class="small">Votre prénom<input class="inp" id="syMe" value="${esc(getMe())}"></label>
        <label class="small">Mot de passe du groupe<input class="inp" id="syJp" type="password" autocomplete="off"></label>
        <div class="row-actions"><button class="btn primary" id="syJoin">Rejoindre</button></div></details>`}
      <div class="row-actions" style="margin-top:12px"><button class="btn ghost small" id="syOut">Se déconnecter</button></div>`,s=>{
        const q=x=>s.querySelector(x);
        q("#syShow")&&(q("#syShow").onchange=e=>q("#syGp").type=e.target.checked?"text":"password");
        q("#syOpen")&&(q("#syOpen").onclick=()=>SYNC.act(async()=>{const id=q("#sySp")?q("#sySp").value:list[0].id;let sp=list.find(x=>x.id===id);
          if(!sp.kdf_salt)sp=(await SYNC.be.spaces()).find(x=>x.id===id);await SYNC.link(sp,q("#syGp").value,false);closeSheet();toast("Synchronisation active");render()}));
        q("#syNew")&&(q("#syNew").onclick=()=>SYNC.act(async()=>{const p=q("#syG1").value;if(p.length<10)throw new Error("Le mot de passe du groupe doit avoir au moins 10 caractères.");if(p!==q("#syG2").value)throw new Error("Les deux mots de passe ne sont pas pareils.");
          const salt=CRY.salt();const key=await CRY.derive(p,salt);const c=await CRY.seal(key,CHECK);const sp=await SYNC.be.createSpace(q("#syNm").value.trim()||"Carnet nature",salt,c.data+"."+c.iv);
          try{if(getMe())await SYNC.be.setName(sp.id,SYNC.user.uid,getMe())}catch(e){}await SYNC.link(sp,p,true);closeSheet();toast("Carnet envoyé en ligne, chiffré");render()}));
        q("#syJoin")&&(q("#syJoin").onclick=()=>SYNC.act(async()=>{const sp=await SYNC.be.join(q("#syCode").value.trim().toUpperCase(),q("#syMe").value.trim()||null);if(!sp)throw new Error("Code invalide.");
          await SYNC.link(sp,q("#syJp").value,false);closeSheet();toast("Carnet rejoint : fusion en cours");render()}));
        q("#syOut").onclick=()=>SYNC.signOut()})});
    SYNC.act(async()=>{let mem=[];try{mem=await SYNC.be.members(SYNC.space.id)}catch(e){}
      openSheet(`<h3>Synchronisation ${SYNC.dot()}</h3>
      <p style="margin:0 0 4px"><b>${esc(SYNC.space.name)}</b> · ${esc(SYNC.label())}</p>
      <p class="muted small" style="margin:0 0 10px">Connectée : ${esc(u.email)}${SYNC.lastAt?" · dernière synchro "+SYNC.lastAt.toLocaleTimeString("fr-CA",{hour:"2-digit",minute:"2-digit"}):""}${SYNC.dirty().length?" · "+SYNC.dirty().length+" changement(s) en attente":""}</p>
      ${mem.length?`<p class="small" style="margin:0 0 10px">Membres : ${mem.map(x=>esc(x.display_name||(x.user_id===u.uid?"vous":"collègue"))+(x.role==="responsable"?" (responsable)":"")).join(", ")}</p>`:""}
      <div class="row-actions"><button class="btn primary" id="syNow">Synchroniser maintenant</button><button class="btn" id="syInv">Inviter une collègue</button></div>
      <div id="syInvBox"></div>
      <div class="notice" style="margin-top:12px"><label class="chk"><input type="checkbox" id="syIA" ${IA.on()?"checked":""}> <span><b>IA dans le carnet</b> (Ranger les notes du terrain, Mettre au propre…)</span></label>
        <span class="small">Avant l'envoi, les prénoms des enfants et des adultes sont remplacés par des codes (Enfant_A…), puis remis dans la réponse sur cet appareil. Ni date de naissance ni photo ne sont envoyées.</span>
        <details style="margin-top:6px"><summary class="small"><b>Mes consignes de rédaction</b></summary><textarea class="field" id="syRules" style="min-height:220px;font-size:.85rem">${esc(IA.rules())}</textarea>
          <div class="row-actions"><button class="btn small primary" id="syRulesOk">Enregistrer les consignes</button><button class="btn ghost small" id="syRulesDef">Remettre celles par défaut</button></div></details>
        ${SYNC.lastSent?`<div class="row-actions" style="margin-top:6px"><button class="btn ghost small" id="sySent">Voir le dernier envoi</button></div>`:""}</div>
      <div class="row-actions" style="margin-top:14px"><button class="btn ghost small" id="syLock">Oublier le mot de passe du groupe sur cet appareil</button><button class="btn ghost small" id="syOut">Se déconnecter</button></div>`,s=>{
        const q=x=>s.querySelector(x);
        q("#syNow").onclick=()=>SYNC.act(async()=>{await SYNC.run();SYNC.open()});
        q("#syInv").onclick=()=>SYNC.act(async()=>{const A="ABCDEFGHJKMNPQRSTUVWXYZ23456789";const r=crypto.getRandomValues(new Uint8Array(8));const code=[...r].map(x=>A[x%A.length]).join("");
          await SYNC.be.createInvite(SYNC.space.id,code);
          q("#syInvBox").innerHTML=`<div class="notice" style="margin-top:10px">Code : <b style="font-size:1.3rem;letter-spacing:2px">${code.slice(0,4)}-${code.slice(4)}</b><br><span class="small">Valide 7 jours. Votre collègue installe le carnet test, crée son compte, choisit « Rejoindre avec un code » et entre ce code avec le <b>mot de passe du groupe</b> (dites-le-lui de vive voix, pas dans le même message).</span></div>`});
        q("#syRulesOk").onclick=()=>{IA.setRules(q("#syRules").value);toast("Consignes enregistrées")};
        q("#syRulesDef").onclick=()=>{q("#syRules").value=IA_DEF;IA.setRules(IA_DEF);toast("Consignes par défaut remises")};
        q("#syIA").onchange=e=>{IA.set(e.target.checked);toast(e.target.checked?"IA activée":"IA désactivée")};
        q("#sySent")&&(q("#sySent").onclick=()=>openSheet(`<h3>Dernier envoi à l'IA</h3><p class="muted small" style="margin:0">Exactement ce qui a quitté l'appareil :</p><pre style="white-space:pre-wrap;font-size:.8rem;max-height:55vh;overflow:auto;background:#fff;padding:8px;border-radius:8px">${esc(SYNC.lastSent)}</pre><div class="row-actions"><button class="btn" id="syBack">Retour</button></div>`,s2=>s2.querySelector("#syBack").onclick=()=>SYNC.open()));
        q("#syLock").onclick=()=>SYNC.act(async()=>{SYNC.stop();await SYNC.keyPut(null);SYNC.key=null;SYNC.setStatus("locked");closeSheet();render()});
        q("#syOut").onclick=()=>SYNC.signOut()})})},

  async signOut(){await SYNC.act(async()=>{SYNC.stop();try{await SYNC.be.signOut()}catch(e){}await SYNC.keyPut(null);SYNC.key=null;SYNC.space=null;SYNC.user=null;LOCAL.meta.sync={};LOCAL.meta.base={};LOCAL.meta.dirty=[];await LOCAL.saveMeta();SYNC.setStatus("off");closeSheet();render();toast("Déconnectée. Le carnet reste sur cet appareil.")})},

  async act(fn){try{await fn()}catch(e){console.warn(e);const m=String(e&&e.message||e);
    toast(/Invalid login/i.test(m)?"Courriel ou mot de passe incorrect.":/already registered/i.test(m)?"Ce courriel a déjà un compte : connectez-vous.":/Email not confirmed/i.test(m)?"Courriel pas encore confirmé : ouvrez le lien reçu.":/fetch|network/i.test(m)?"Pas de connexion au serveur.":m.length<140?m:"Erreur : "+m.slice(0,120))}}
};

document.addEventListener("click",e=>{const t=e.target.closest("[data-sync]");if(!t)return;e.preventDefault();SYNC.open()});
(async function boot(){for(let i=0;i<200&&!(LOCAL.idb&&S.ready);i++)await sleep(100);if(LOCAL.idb)SYNC.start()})();
window.SYNC_CRY=CRY;
})();
