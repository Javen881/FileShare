'use strict';
const $ = id => document.getElementById(id);
let token = location.pathname.startsWith('/enter/') ? location.pathname.slice(7) : '', session = null, offset = 0, uploading = false, folderId = "";
history.replaceState(null, '', '/session');
function message(text) { $('message').textContent = text; }
function size(n) { return n >= 1073741824 ? (n/1073741824).toFixed(2)+' GiB' : n >= 1048576 ? (n/1048576).toFixed(1)+' MiB' : (n/1024).toFixed(1)+' KiB'; }
function expired() { session = null; $('workspace').hidden = true; $('login').hidden = false; $('badge').textContent = '未授权'; $('login-form').hidden = !token; $('no-invite').hidden = !!token; }
async function api(url, options = {}) {
  const r = await fetch(url, {credentials:'same-origin', cache:'no-store', ...options});
  const data = await r.json();
  if (!r.ok) { if (r.status === 401 && url !== '/api/login') expired(); throw new Error(data.error || '操作失败'); }
  return data;
}
async function refreshSession() {
  session = await api('/api/me'); $('login').hidden = true; $('workspace').hidden = false;
  $('badge').textContent = '已授权 · '+session.user; $('welcome').textContent = session.user+'，欢迎使用';
  $('session').textContent = '最迟 '+new Date(session.expires*1000).toLocaleTimeString()+' 失效 · 空闲 15 分钟自动退出';
}
async function list(reset=true) {
  if (reset) { offset = 0; $('files').replaceChildren(); }
  const data = await api('/api/files?offset='+offset+'&folder='+encodeURIComponent(folderId));
  if(reset){
    $('breadcrumbs').replaceChildren();
    for(const item of [{id:'',name:'全部文件'},...data.path]){const b=document.createElement('button');b.textContent=item.name;b.className='secondary';b.onclick=()=>{folderId=item.id;list().catch(e=>message(e.message));};$('breadcrumbs').append(b);}
    for(const folder of data.folders){const row=document.createElement('div'),b=document.createElement('button');row.className='file';b.textContent='📁 '+folder.name;b.className='secondary';b.onclick=()=>{folderId=folder.id;list().catch(e=>message(e.message));};row.append(b);$('files').append(row);}
  }
  for (const file of data.files) {
    const row = document.createElement('div'); row.className='file';
    const info = document.createElement('div'), name = document.createElement('strong'), meta = document.createElement('p'), link=document.createElement('a');
    name.textContent = file.name; meta.textContent = size(file.size)+' · '+file.user+' · '+new Date(file.created*1000).toLocaleString();
    info.append(name, meta); link.textContent='下载'; link.href='/api/download/'+file.id; link.download=file.name;
    row.append(info, link); $('files').append(row);
  }
  offset += data.files.length; $('more').hidden=!data.more;
  if (!offset && !data.folders.length) $('files').textContent='还没有文件，上传第一份文件吧。';
}
$('login-form').addEventListener('submit', async e => {
  e.preventDefault(); const button=e.submitter; button.disabled=true; message('');
  try { await api('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token, pin:$('pin').value})}); token=''; $('pin').value=''; await refreshSession(); await list(); }
  catch(e) { message(e.message); } finally { button.disabled=false; }
});
$('logout').onclick = async () => { try { await api('/api/logout', {method:'POST',headers:{'X-CSRF-Token':session.csrf}}); expired(); message('已退出，文件仍保留。'); } catch(e) { message(e.message); } };
$('refresh').onclick = () => list().catch(e => message(e.message));
$('more').onclick = () => list(false).catch(e => message(e.message));
function send(file, folder) { return new Promise((resolve,reject) => {
  const xhr=new XMLHttpRequest(); xhr.open('POST','/api/upload?folder='+encodeURIComponent(folder)+'&name='+encodeURIComponent(file.name));
  xhr.setRequestHeader('X-CSRF-Token',session.csrf); xhr.setRequestHeader('Content-Type','application/octet-stream');
  xhr.upload.onprogress=e=>{if(e.lengthComputable) $('progress').value=e.loaded/e.total*100;};
  xhr.onload=()=>{if(xhr.status===201) resolve(); else {if(xhr.status===401)expired(); try{reject(new Error(JSON.parse(xhr.responseText).error));}catch{reject(new Error('上传失败（HTTP '+xhr.status+'）'));}}};
  xhr.onerror=()=>reject(new Error('网络中断，文件未完成上传，请重试。')); xhr.send(file);
}); }
$('upload').onclick=async()=>{
  const files=Array.from($('file').files),target=folderId; if(!files.length)return message('请先选择文件。');
  if(files.some(f=>f.size>session.max_file_bytes))return message('单文件不能超过 '+size(session.max_file_bytes));
  uploading=true; $('upload').disabled=true; $('file').disabled=true; $('progress').hidden=false; message('');
  try { for(const file of files){$('progress').value=0;$('upload-state').textContent='正在上传：'+file.name; await send(file,target);} $('upload-state').textContent='上传完成，文件已保存。'; $('file').value=''; await list(); }
  catch(e){message(e.message);$('upload-state').textContent='上传未完成，请检查后重试。';}
  finally{uploading=false;$('upload').disabled=false;$('file').disabled=false;$('progress').hidden=true;}
};
setInterval(()=>{if(session) refreshSession().catch(e=>message(e.message));},30000);
window.addEventListener('beforeunload',e=>{if(uploading){e.preventDefault();e.returnValue='';}});
expired(); if(!token) refreshSession().then(()=>list()).catch(()=>{});
