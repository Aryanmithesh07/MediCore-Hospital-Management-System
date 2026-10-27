function toggleDarkMode(){
  document.body.classList.toggle("dark");
  localStorage.setItem("darkMode", document.body.classList.contains("dark") ? "1" : "0");
}
if(localStorage.getItem("darkMode")==="1") document.body.classList.add("dark");
function toggleSidebar(){ document.getElementById("sidebar").classList.toggle("show"); }
function calculateTotal(){
  let ids=["consultation","medicine","tests","room","other"];
  let total=ids.reduce((s,id)=>s+(parseFloat(document.getElementById(id)?.value)||0),0);
  let el=document.getElementById("total"); if(el) el.textContent="₹"+total.toFixed(2);
}
document.addEventListener("DOMContentLoaded", calculateTotal);
