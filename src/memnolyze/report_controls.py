"""Inline, dependency-free controls for local reports."""
SCRIPT = r'''
document.querySelectorAll('details:not(.column-filter)').forEach(detail=>{
 const controls=document.createElement('div'),button=document.createElement('button');
 controls.className='collapse-current';button.type='button';button.textContent='Collapse this section';
 button.addEventListener('click',()=>{
   detail.open=false;
   const summary=detail.querySelector(':scope > summary');
   summary.focus({preventScroll:true});summary.scrollIntoView({block:'start',behavior:'instant'});
 });
 controls.appendChild(button);detail.appendChild(controls);
});
document.querySelectorAll('[data-details-target]').forEach(button=>button.addEventListener('click',()=>{
 const table=document.getElementById(button.dataset.detailsTarget),expand=button.dataset.expand==='true';
 Array.from(table.tBodies[0].rows).filter(row=>!row.hidden).forEach(row=>row.querySelectorAll('details').forEach(detail=>detail.open=expand));
}));
document.querySelectorAll('table').forEach(table=>{
 const rows=Array.from(table.tBodies[0].rows);
 const records=rows.map(row=>({row,text:row.textContent.toLowerCase(),values:Array.from(row.cells).map(cell=>
   cell.dataset.columnValues ? JSON.parse(cell.dataset.columnValues) : [cell.textContent.trim()])}));
 const selections=new Map();
 const activeFilters=new Set();
 const search=document.querySelector('[data-filter="'+table.id+'"]');
 const count=document.querySelector('[data-row-count="'+table.id+'"]');
 const apply=()=>{
   const query=search?search.value.toLowerCase():'';let visible=0;
   records.forEach(record=>{
     record.row.hidden=!(record.text.includes(query)&&Array.from(selections).every(([index,values])=>
       !activeFilters.has(index)||record.values[index].some(value=>values.has(value))));
     if(!record.row.hidden)visible++;
   });
   count.textContent=visible+' / '+records.length+' rows';
 };
 if(search)search.addEventListener('input',apply);
 table.querySelectorAll('th').forEach((th,index)=>{
   const sort=th.querySelector('[data-sort]');let ascending=false;
   sort.addEventListener('click',()=>{
     ascending=!ascending;
     Array.from(table.tBodies[0].rows).sort((a,b)=>{
       const value=cell=>cell.dataset.columnValues?JSON.parse(cell.dataset.columnValues).join(', '):cell.textContent.trim();
       return value(a.cells[index]).localeCompare(value(b.cells[index]),undefined,{numeric:true})*(ascending?1:-1);
     }).forEach(row=>table.tBodies[0].appendChild(row));
     table.querySelectorAll('th').forEach(header=>header.removeAttribute('aria-sort'));
     th.setAttribute('aria-sort',ascending?'ascending':'descending');
   });
   const menu=th.querySelector('.column-filter');
   if(!menu)return;
   const frequencies=new Map();
   records.forEach(record=>new Set(record.values[index]).forEach(value=>frequencies.set(value,(frequencies.get(value)||0)+1)));
   const selected=new Set();selections.set(index,selected);
   const summary=menu.querySelector('summary'),options=menu.querySelector('.filter-options');
   const update=()=>{summary.textContent='Filter ('+frequencies.size+')'+(activeFilters.has(index)?' · '+selected.size+' selected':'');apply();};
   Array.from(frequencies).sort(([a],[b])=>a.localeCompare(b,undefined,{numeric:true})).forEach(([value,total])=>{
     const label=document.createElement('label'),checkbox=document.createElement('input'),text=document.createElement('span');
     checkbox.type='checkbox';checkbox.value=value;
     text.textContent=(value||'(empty)')+' ('+total+')';
     checkbox.addEventListener('change',()=>{activeFilters.add(index);if(checkbox.checked)selected.add(value);else selected.delete(value);update();});
     label.append(checkbox,text);label.dataset.value=value.toLowerCase();options.appendChild(label);
   });
   menu.querySelector('input[type="search"]').addEventListener('input',event=>{
     const query=event.target.value.toLowerCase();options.querySelectorAll('label').forEach(label=>label.hidden=!label.dataset.value.includes(query));
   });
   menu.querySelector('[data-select-all-column]').addEventListener('click',()=>{
     activeFilters.add(index);frequencies.forEach((total,value)=>selected.add(value));
     options.querySelectorAll('input').forEach(input=>input.checked=true);update();
   });
   const clear=()=>{activeFilters.delete(index);selected.clear();options.querySelectorAll('input').forEach(input=>input.checked=false);update();};
   menu.querySelector('[data-clear-column]').addEventListener('click',clear);
   menu.addEventListener('toggle',()=>{if(menu.open)table.querySelectorAll('.column-filter').forEach(other=>{if(other!==menu)other.open=false;});});
   update();
 });
 document.querySelector('[data-clear-filters="'+table.id+'"]').addEventListener('click',()=>{
   if(search)search.value='';activeFilters.clear();selections.forEach(values=>values.clear());
   table.querySelectorAll('.column-filter').forEach(menu=>{
     menu.querySelectorAll('input[type="checkbox"]').forEach(input=>input.checked=false);
     const input=menu.querySelector('input[type="search"]');input.value='';input.dispatchEvent(new Event('input'));
     menu.querySelector('summary').textContent='Filter ('+menu.querySelectorAll('input[type="checkbox"]').length+')';
   });apply();
 });apply();
});
const openFinding=()=>{const el=document.getElementById(location.hash.slice(1));if(el&&el.tagName==='DETAILS')el.open=true;};
window.addEventListener('hashchange',openFinding);openFinding();
'''
