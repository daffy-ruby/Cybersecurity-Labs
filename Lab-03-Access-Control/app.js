function openModal(id){ document.getElementById(id).classList.add('show'); document.body.classList.add('modal-open'); }
function closeModal(id){ document.getElementById(id).classList.remove('show'); document.body.classList.remove('modal-open'); }
function closeOnBackdrop(e,id){ if(e.target.id===id) closeModal(id); }
function openWriteModal(id,name){
  document.getElementById('writeForm').action = `/file/${id}/write`;
  document.getElementById('writeFileName').textContent = name;
  openModal('writeModal');
}
document.addEventListener('keydown', e => { if(e.key==='Escape'){ document.querySelectorAll('.modal-backdrop.show').forEach(m=>m.classList.remove('show')); document.body.classList.remove('modal-open'); }});
