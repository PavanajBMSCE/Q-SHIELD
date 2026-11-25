import React, { useEffect, useMemo, useState } from "react";
import { ShieldCheck, UploadCloud, FileArchive, ArrowRightLeft, FileText, Download, Activity, LockKeyhole, AlertTriangle, CheckCircle2, RefreshCw, FlaskConical, Shield, DownloadCloud, ClipboardCheck, FileCode2, Check, X, Eye, Server, Database, Search, Gauge, Layers3, ArrowUpRight, Play, ChevronRight, Trash2 } from "lucide-react";

const API = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";
const fmt = (v) => Number(v || 0).toLocaleString();
const formatFileSize = (bytes) => bytes < 1024 * 1024
  ? `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB selected`
  : `${(bytes / 1024 / 1024).toFixed(2)} MB selected`;
function FilePicker({label, hint, file, onChange, tone}) {
  return <label className={`upload-card ${tone}`}>
    <div className="upload-icon"><FileArchive size={23}/></div>
    <div><span className="eyebrow">{label}</span><h3>{file ? file.name : "Choose project ZIP"}</h3><p>{file ? formatFileSize(file.size) : hint}</p></div>
    <input type="file" accept=".zip,application/zip" onChange={e=>onChange(e.target.files?.[0] || null)}/>
    <span className="browse">{file ? "Change file" : "Browse ZIP"}</span>
  </label>
}
function Metric({label,value,sub,icon:Icon}) { return <div className="metric"><div className="metric-top"><span>{label}</span><Icon size={18}/></div><strong>{value}</strong><small>{sub}</small></div> }
function Bars({before,after}) {
 const keys=[...new Set([...Object.keys(before||{}),...Object.keys(after||{})])].filter(k=>!["Cryptographic API"].includes(k));
 const max=Math.max(1,...keys.flatMap(k=>[before?.[k]||0,after?.[k]||0]));
 return <div className="bar-list">{keys.map(k=><div className="bar-row" key={k}><div className="bar-label">{k}</div><div className="bar-pair"><div className="bar-track"><div className="bar before" style={{width:`${(before?.[k]||0)/max*100}%`}}/></div><b>{before?.[k]||0}</b><div className="bar-track"><div className="bar after" style={{width:`${(after?.[k]||0)/max*100}%`}}/></div><b>{after?.[k]||0}</b></div></div>)}</div>
}
export default function App(){
 const [before,setBefore]=useState(null),[after,setAfter]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState(""),[result,setResult]=useState(null),[detail,setDetail]=useState(null),[tab,setTab]=useState("overview");
 const pageItems=[
  {id:"overview",label:"Overview",icon:Gauge,group:"WORKSPACE"},
  {id:"scanner-inventory",label:"Scanner & Inventory",icon:Search},
  {id:"readiness",label:"Readiness & Recommendations",icon:Activity},
  {id:"assisted-migration",label:"Assisted Migration",icon:ClipboardCheck,group:"MIGRATION"},
  {id:"comparison",label:"Project Comparison",icon:ArrowRightLeft},
  {id:"benchmarking",label:"Benchmarking",icon:Activity},
  {id:"pqc-migration",label:"PQC Migration Lab",icon:FlaskConical},
  {id:"end-to-end-audit",label:"End-to-End Audit",icon:ShieldCheck}
 ];
 const pageFromHash=()=>{const id=window.location.hash.replace(/^#\/?/,"");return pageItems.some(x=>x.id===id)?id:"overview"};
 const [page,setPage]=useState(pageFromHash),[clearBusy,setClearBusy]=useState(false);
 useEffect(()=>{const sync=()=>setPage(pageFromHash());window.addEventListener("hashchange",sync);return()=>window.removeEventListener("hashchange",sync);},[]);
 function navigateTo(id){window.location.hash=id;setPage(id);window.scrollTo({top:0,behavior:"smooth"});}
 async function loadRecentScanHistory(){
  try{
   const response=await fetch(`${API}/api/projects`);if(!response.ok)return;
   const rows=await response.json();
   const history=await Promise.all((Array.isArray(rows)?rows:[]).slice(0,6).map(async project=>{
    try{const r=await fetch(`${API}/api/scanner/summary/${project.id}`);const d=await r.json();
     const inv=await fetch(`${API}/api/inventory/${project.id}`);const iv=inv.ok?await inv.json():{};
     return {id:project.id,name:project.project_name,created_at:project.created_at,findings:d.total_findings??0,inventory:iv.total_inventory_records??0,status:r.ok?"Stored":"Unavailable"};
    }catch{return {id:project.id,name:project.project_name,created_at:project.created_at,status:"Unavailable"};}
   }));
   setRecentScanHistory(history);
  }catch{/* History is optional; never block scanner operation. */}
 }
 const [pqcFile,setPqcFile]=useState(null),[pqcBusy,setPqcBusy]=useState(false),[pqcError,setPqcError]=useState(""),[pqcResult,setPqcResult]=useState(null);
 const [verifyBusy,setVerifyBusy]=useState(false),[verifyResult,setVerifyResult]=useState(null),[verifyError,setVerifyError]=useState("");
 const [auditFile,setAuditFile]=useState(null),[auditBusy,setAuditBusy]=useState(false),[auditError,setAuditError]=useState(""),[auditJob,setAuditJob]=useState(null),[auditHistory,setAuditHistory]=useState([]),[auditProfile,setAuditProfile]=useState("TRANSITION");
 const [auditSelectedFinding,setAuditSelectedFinding]=useState(""),[auditDecision,setAuditDecision]=useState("APPROVE_REMEDIATION_PLAN"),[auditNote,setAuditNote]=useState(""),[auditExpiry,setAuditExpiry]=useState(""),[auditDecisionBusy,setAuditDecisionBusy]=useState(false);
 const [assistFile,setAssistFile]=useState(null),[assistBusy,setAssistBusy]=useState(false),[assistError,setAssistError]=useState(""),[assistJob,setAssistJob]=useState(null),[assistDecisions,setAssistDecisions]=useState({}),[assistApplied,setAssistApplied]=useState(null);
 const ready=!!before&&!!after&&!busy;
 const [health,setHealth]=useState(null),[projects,setProjects]=useState([]),[selectedProject,setSelectedProject]=useState(""),[scanFile,setScanFile]=useState(null),[scanName,setScanName]=useState(""),[scanBusy,setScanBusy]=useState(false),[scanError,setScanError]=useState(""),[scanResult,setScanResult]=useState(null),[inventory,setInventory]=useState(null),[readiness,setReadiness]=useState(null),[recommendations,setRecommendations]=useState(null),[benchmarkCatalog,setBenchmarkCatalog]=useState(null),[benchmarkRuns,setBenchmarkRuns]=useState([]),[benchmarkBusy,setBenchmarkBusy]=useState(false),[benchmarkResult,setBenchmarkResult]=useState(null),[benchmarkError,setBenchmarkError]=useState(""),[recentScanHistory,setRecentScanHistory]=useState([]);
 useEffect(()=>{refreshWorkspace();loadBenchmarkWorkspace();loadRecentScanHistory();},[]);
 useEffect(()=>{if(selectedProject)loadProjectIntelligence();},[selectedProject]);
 async function clearAllWorkspace(){
  const confirmed=window.confirm("Clear all Q-SHIELD workspace data? This permanently deletes scanned projects, findings, inventories, assessments, recommendations, benchmark history, migration/comparison outputs and audit history. The application source code and bundled sample files will remain untouched.");
  if(!confirmed)return;
  setClearBusy(true);
  try{
   const response=await fetch(`${API}/api/workspace/clear-all`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirmation:"CLEAR_ALL_QSHIELD_DATA"})});
   const data=await response.json().catch(()=>({error:"The backend returned an invalid response."}));
   if(!response.ok)throw new Error(data.error||data.message||"Could not clear the workspace.");
   setBefore(null);setAfter(null);setBusy(false);setError("");setResult(null);setDetail(null);setTab("overview");
   setPqcFile(null);setPqcBusy(false);setPqcError("");setPqcResult(null);
   setVerifyBusy(false);setVerifyResult(null);setVerifyError("");
   setAuditFile(null);setAuditBusy(false);setAuditError("");setAuditJob(null);setAuditHistory([]);
   setAuditSelectedFinding("");setAuditDecision("APPROVE_REMEDIATION_PLAN");setAuditNote("");setAuditExpiry("");setAuditDecisionBusy(false);
   setAssistFile(null);setAssistBusy(false);setAssistError("");setAssistJob(null);setAssistDecisions({});setAssistApplied(null);
   setProjects([]);setSelectedProject("");setScanFile(null);setScanName("");setScanBusy(false);setScanError("");setScanResult(null);
   setInventory(null);setReadiness(null);setRecommendations(null);setBenchmarkRuns([]);setBenchmarkBusy(false);setBenchmarkResult(null);setBenchmarkError("");setRecentScanHistory([]);
   await refreshWorkspace();
   await Promise.all([loadBenchmarkWorkspace(),loadRecentScanHistory(),loadAuditHistory()]);
   window.location.hash="overview";setPage("overview");window.scrollTo({top:0,behavior:"smooth"});
   window.alert(data.message||"Q-SHIELD workspace cleared. You can start fresh.");
  }catch(e){window.alert(`Clear all failed: ${e.message}`);}
  finally{setClearBusy(false);}
 }
 async function refreshWorkspace(){
  try{const [h,p]=await Promise.all([fetch(`${API}/api/health`),fetch(`${API}/api/projects`)]);const hd=await h.json();const pd=await p.json();setHealth(h.ok?hd:{status:"unhealthy"});if(p.ok){setProjects(Array.isArray(pd)?pd:[]);if(pd.length&&!selectedProject)setSelectedProject(String(pd[0].id));}}
  catch(e){setHealth({status:"offline",error:e.message});}
 }
 async function loadBenchmarkWorkspace(){
  try{const [c,r]=await Promise.all([fetch(`${API}/api/benchmarks/catalog`),fetch(`${API}/api/benchmarks/runs`)]);const cd=await c.json(),rd=await r.json();if(c.ok)setBenchmarkCatalog(cd);if(r.ok)setBenchmarkRuns(rd.runs||[]);}
  catch(e){setBenchmarkError(e.message);}
 }
 async function uploadAndScan(){
  if(!scanFile)return;setScanBusy(true);setScanError("");setScanResult(null);setInventory(null);setReadiness(null);setRecommendations(null);
  try{const fd=new FormData();fd.append("file",scanFile);fd.append("project_name",scanName.trim()||scanFile.name.replace(/\.zip$/i,""));const r=await fetch(`${API}/api/scanner/upload`,{method:"POST",body:fd});const d=await r.json();if(!r.ok)throw new Error(d.error||"Scanner upload failed");setScanResult(d);const id=d.project_id;await refreshWorkspace();setSelectedProject(String(id));const [summary,inv]=await Promise.all([fetch(`${API}/api/scanner/summary/${id}`),fetch(`${API}/api/inventory/${id}`)]);const sd=await summary.json(),iv=await inv.json();if(summary.ok)setScanResult(prev=>({...prev,...sd}));if(inv.ok)setInventory(iv);await loadRecentScanHistory();}
  catch(e){setScanError(e.message+" — confirm the Flask API is running.");}finally{setScanBusy(false);}
 }
 async function loadProjectIntelligence(){
  if(!selectedProject)return;setScanError("");const id=selectedProject;
  try{const [inv,assess,recs]=await Promise.all([fetch(`${API}/api/inventory/${id}`),fetch(`${API}/api/assessment/${id}`),fetch(`${API}/api/recommendations/${id}`)]);const [iv,ad,rd]=await Promise.all([inv.json(),assess.json(),recs.json()]);if(inv.ok)setInventory(iv);if(assess.ok)setReadiness(ad.assessment);else setReadiness(null);if(recs.ok)setRecommendations(rd);else setRecommendations(null);const sr=await fetch(`${API}/api/scanner/summary/${id}`);const sd=await sr.json();if(sr.ok)setScanResult(prev=>({...prev,...sd}));}
  catch(e){setScanError(e.message);}
 }
 async function generateProjectIntelligence(){
  if(!selectedProject)return;
  setScanBusy(true);setScanError("");
  const id=selectedProject;
  const safeJson=async response=>{try{return await response.json();}catch{return {error:`Unexpected response (${response.status})`};}};
  const [assessmentResult,recommendationResult]=await Promise.allSettled([
   fetch(`${API}/api/assessment/${id}/generate`,{method:"POST"}),
   fetch(`${API}/api/recommendations/${id}/generate`,{method:"POST"})
  ]);
  const errors=[];
  if(assessmentResult.status==="fulfilled"){
   const response=assessmentResult.value,data=await safeJson(response);
   if(response.ok&&data.assessment)setReadiness(data.assessment);
   else errors.push(`Readiness: ${data.error||"generation failed"}`);
  }else errors.push(`Readiness: ${assessmentResult.reason?.message||"request failed"}`);
  if(recommendationResult.status==="fulfilled"){
   const response=recommendationResult.value,data=await safeJson(response);
   if(response.ok&&Array.isArray(data.recommendations))setRecommendations(data);
   else errors.push(`Recommendations: ${data.error||"generation failed"}`);
  }else errors.push(`Recommendations: ${recommendationResult.reason?.message||"request failed"}`);
  // Refresh each workspace resource independently; a failed refresh must not erase
  // a successfully generated assessment or recommendation.
  const refreshes=await Promise.allSettled([
   fetch(`${API}/api/inventory/${id}`).then(async r=>({ok:r.ok,data:await safeJson(r)})),
   fetch(`${API}/api/scanner/summary/${id}`).then(async r=>({ok:r.ok,data:await safeJson(r)}))
  ]);
  if(refreshes[0].status==="fulfilled"&&refreshes[0].value.ok)setInventory(refreshes[0].value.data);
  if(refreshes[1].status==="fulfilled"&&refreshes[1].value.ok)setScanResult(prev=>({...prev,...refreshes[1].value.data}));
  if(errors.length)setScanError(errors.join(" · "));
  setScanBusy(false);
 }
 async function runComparativeBenchmark(){
  setBenchmarkBusy(true);setBenchmarkError("");setBenchmarkResult(null);try{const r=await fetch(`${API}/api/benchmarks/run`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({repetitions:30,warmups:3})});const d=await r.json();if(!r.ok)throw new Error(d.error||"Benchmark run failed");setBenchmarkResult(d);await loadBenchmarkWorkspace();}catch(e){setBenchmarkError(e.message);}finally{setBenchmarkBusy(false);}
 }
 async function prepareAssisted(){
  if(!assistFile)return;
  setAssistBusy(true);setAssistError("");setAssistJob(null);setAssistApplied(null);setAssistDecisions({});
  try{
   const fd=new FormData();fd.append("file",assistFile);
   const res=await fetch(`${API}/api/project-migration/assisted/prepare`,{method:"POST",body:fd});
   const data=await res.json();if(!res.ok)throw new Error(data.error||"Could not prepare assisted migration");
   setAssistJob(data);
  }catch(e){setAssistError(e.message+" — ensure Flask is running on port 5000.");}
  finally{setAssistBusy(false);}
 }
 async function submitAssistedDecisions(){
  if(!assistJob)return;
  const decisions=Object.entries(assistDecisions).map(([proposal_id,decision])=>({proposal_id,decision}));
  if(!decisions.length){setAssistError("Choose approve or reject for at least one patchable proposal.");return;}
  setAssistBusy(true);setAssistError("");
  try{
   const res=await fetch(`${API}/api/project-migration/assisted/${assistJob.job_id}/decisions`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({decisions})});
   const data=await res.json();if(!res.ok)throw new Error(data.error||"Could not apply decisions");
   setAssistApplied(data);setAssistJob(data.report);setAssistDecisions({});
  }catch(e){setAssistError(e.message);}
  finally{setAssistBusy(false);}
 }
 async function runPqcMigration(){
  setPqcError("");setPqcResult(null);setPqcBusy(true);
  try{
   const fd=new FormData();fd.append("file",pqcFile);
   const res=await fetch(`${API}/api/comparison/pqc-migrate`,{method:"POST",body:fd});
   const data=await res.json();if(!res.ok)throw new Error(data.error||"PQC migration failed");
   setPqcResult(data);
  }catch(e){setPqcError(e.message+" — ensure Flask is running on port 5000.");}
  finally{setPqcBusy(false);}
 }
 async function verifyPqc(){
  if(!result?.comparison_id)return;
  setVerifyBusy(true);setVerifyError("");setVerifyResult(null);
  try{
   const res=await fetch(`${API}/api/comparison/${result.comparison_id}/verify-pqc`,{method:"POST"});
   const data=await res.json();if(!res.ok)throw new Error(data.error||"PQC verification failed");
   setVerifyResult(data.pqc_verification);
   const refreshed=await fetch(`${API}/api/comparison/${result.comparison_id}`);
   const full=await refreshed.json();if(refreshed.ok)setDetail(full);
  }catch(e){setVerifyError(e.message+" — ensure Flask is running and the comparison evidence is available.");}
  finally{setVerifyBusy(false);}
 }
 async function compare(){
  setError("");setResult(null);setDetail(null);setBusy(true);
  try{
   const fd=new FormData();fd.append("before_file",before);fd.append("after_file",after);
   fd.append("before_name",before.name.replace(/\.zip$/i,""));fd.append("after_name",after.name.replace(/\.zip$/i,""));
   const res=await fetch(`${API}/api/comparison/analyze`,{method:"POST",body:fd});
   const data=await res.json().catch(()=>({error:`Backend returned HTTP ${res.status} with a non-JSON response.`}));
   if(!res.ok)throw new Error(data.error||`Comparison failed (HTTP ${res.status}).`);
   setResult(data);const r=await fetch(`${API}/api/comparison/${data.comparison_id}`);
   const full=await r.json().catch(()=>({error:`Could not read comparison report (HTTP ${r.status}).`}));
   if(!r.ok)throw new Error(full.error||"Could not retrieve comparison details");
   setDetail(full);
  }catch(e){setError(e.message||"Comparison request failed. Check the browser network panel and Flask terminal.");}
  finally{setBusy(false);}
 }
 async function runEndToEndAudit(){
  if(!auditFile)return;
  setAuditBusy(true);setAuditError("");setAuditJob(null);
  try{
   let health;
   try{health=await fetch(`${API}/api/health`,{cache:"no-store"});}
   catch(_){throw new Error(`Cannot reach Flask at ${API}. Start the backend from the backend folder with: python app.py`);}
   if(!health.ok)throw new Error(`Flask is reachable but its health check returned HTTP ${health.status}. Check the backend terminal.`);
   const healthData=await health.json();
   if(healthData.status!=="healthy")throw new Error("Flask is running, but its database health check failed. Check the backend terminal.");
   const fd=new FormData();fd.append("file",auditFile);fd.append("policy_profile",auditProfile);
   let res;
   try{res=await fetch(`${API}/api/end-to-end-audit/run`,{method:"POST",body:fd});}
   catch(_){throw new Error(`The audit request could not reach ${API}. Confirm Flask is still running on port 5000 and check the backend terminal.`);}
   const data=await res.json().catch(()=>({error:`Backend returned a non-JSON response (HTTP ${res.status}). Check the Flask terminal for the traceback.`}));
   if(!res.ok)throw new Error(data.error||`End-to-end audit failed (HTTP ${res.status})`);
   setAuditJob(data);
   const h=await fetch(`${API}/api/end-to-end-audit/history`);
   const hd=await h.json().catch(()=>({audits:[]}));
   if(h.ok)setAuditHistory(hd.audits||[]);
  }catch(e){setAuditError(e.message||"End-to-end audit failed.");}
  finally{setAuditBusy(false);}
 }
 async function loadAuditHistory(){try{const r=await fetch(`${API}/api/end-to-end-audit/history`);const d=await r.json();if(r.ok)setAuditHistory(d.audits||[]);}catch(e){setAuditError(e.message);}}
 async function submitAuditDecision(){
  if(!auditJob||!auditSelectedFinding)return;setAuditDecisionBusy(true);setAuditError("");
  try{const item={finding_id:auditSelectedFinding,decision:auditDecision,note:auditNote};if(auditDecision==="ACCEPT_TIME_BOUND_EXCEPTION")item.exception_expiry=auditExpiry;const res=await fetch(`${API}/api/end-to-end-audit/${auditJob.audit_id}/decisions`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({actor:"reviewer",decisions:[item]})});const data=await res.json();if(!res.ok)throw new Error(data.error||"Could not record reviewer decision");setAuditJob(data.audit);setAuditNote("");setAuditExpiry("");setAuditSelectedFinding("");}
  catch(e){setAuditError(e.message);}finally{setAuditDecisionBusy(false);}
 }
 const s=result?.summary, c=detail?.comparison;
 const beforeA=detail?.before?.analysis,afterA=detail?.after?.analysis;
 return <div className="app-shell">
  <header className="topbar"><div className="brand"><div className="brand-mark"><ShieldCheck/></div><div className="brand-copy"><b>Q-SHIELD</b><span>POST-QUANTUM SECURITY WORKBENCH</span></div></div><div className="topbar-right"><div className={`connection-pill ${health?.status==="healthy"?"online":"offline"}`}><span/>{health?.status==="healthy"?"API CONNECTED":"API NOT CONNECTED"}</div><div className="module-tag">SECURITY OPERATIONS <span>CLASSICAL → POST-QUANTUM</span></div><button className="clear-all-button" onClick={clearAllWorkspace} disabled={clearBusy||busy||scanBusy||auditBusy||assistBusy||pqcBusy||verifyBusy||benchmarkBusy} title="Permanently clear all saved workspace data">{clearBusy?<RefreshCw className="spin" size={15}/>:<Trash2 size={15}/>}<span>{clearBusy?"Clearing…":"Clear all"}</span></button></div></header>
  <div className="workbench-layout">
   <aside className="sidebar" aria-label="Module navigation"><div className="sidebar-caption">SECURITY WORKSPACE</div>{pageItems.map((item,index)=><React.Fragment key={item.id}>{item.group&&<div className="sidebar-group">{item.group}</div>}<button className={`sidebar-link ${page===item.id?"active":""}`} onClick={()=>navigateTo(item.id)} aria-current={page===item.id?"page":undefined}><item.icon size={17}/><span>{item.label}</span>{page===item.id&&<ChevronRight className="sidebar-chevron" size={15}/>}</button></React.Fragment>)}<div className="sidebar-foot"><ShieldCheck size={16}/><span>Post-quantum security<br/>migration workbench</span></div></aside>
  <main className="main" data-page={page}>
    <section className="workspace" id="workspace">
     <div className="workspace-heading"><div><span className="eyebrow">SECURITY OPERATIONS CENTER</span><h1>Cryptographic <em>posture overview</em></h1><p>Scan a project, inspect its cryptographic inventory, assess migration readiness and launch the controlled PQC workflows.</p></div><button className="decision refresh-button" onClick={refreshWorkspace}><RefreshCw size={15}/> Refresh status</button></div>
     <div className="workspace-metrics"><div className="workspace-metric"><span><Server size={17}/> Backend</span><b>{health?.status==="healthy"?"Online":health?"Offline":"Checking…"}</b><small>Flask API</small></div><div className="workspace-metric"><span><Database size={17}/> Database</span><b>{health?.database||"—"}</b><small>SQLite persistence</small></div><div className="workspace-metric"><span><Layers3 size={17}/> Projects</span><b>{projects.length}</b><small>Registered projects</small></div><div className="workspace-metric"><span><ShieldCheck size={17}/> PQC provider</span><b>{benchmarkCatalog?.provider||"Checking…"}</b><small>{benchmarkCatalog?.supported_algorithms?.length||0} benchmark algorithms available</small></div></div>
     <div className="posture-dashboard">
      <div className="posture-card posture-score"><span className="eyebrow">CRYPTOGRAPHIC READINESS</span><strong>{readiness?.readiness_score??readiness?.score??"—"}<small>{readiness?"/100":"Not assessed"}</small></strong><b>{readiness?.risk_level||"Not assessed"}</b><p>Heuristic risk assessment; not a certification or proof of quantum safety.</p></div>
      <div className="posture-card"><span className="eyebrow">CLASSICAL EXPOSURE</span><strong>{inventory?.inventory?.filter(x=>["RSA","ECC","DES","MD5","SHA-1"].includes(String(x.algorithm).toUpperCase())).length??"—"}</strong><p>{inventory?"Detected legacy / quantum-vulnerable inventory records":"Not collected"}</p></div>
      <div className="posture-card"><span className="eyebrow">PQC IMPLEMENTATION EVIDENCE</span><strong>{verifyResult?.verification_level??"Verification pending"}</strong><p>{verifyResult?"Source-level checks are available; provider self-test is separate and does not execute the uploaded application.":"Static source evidence has not been assessed in this session."} <a href="#comparison">Open Project Comparison</a>.</p></div>
      <div className="posture-card"><span className="eyebrow">REMAINING ACTIONS</span><strong>{recommendations?.total_recommendations??recommendations?.recommendations?.length??"—"}</strong><p>{recommendations?"Stored migration recommendations":"Not generated"}</p></div>
     </div>
     <div className="workspace-grid">
      <div className="workspace-card"><div className="card-heading"><div><span className="eyebrow">MODULE 01 · MODULE 02</span><h3><Search size={18}/> Scan & build inventory</h3><p>Upload a ZIP archive for static cryptographic discovery and inventory generation.</p></div><span className="mini-status">STATIC ANALYSIS</span></div>
       <div className="scan-form"><label className="lab-file"><FileArchive size={19}/><span>{scanFile?scanFile.name:"Choose project ZIP to scan"}</span><input type="file" accept=".zip,application/zip" onChange={e=>setScanFile(e.target.files?.[0]||null)}/></label><input value={scanName} onChange={e=>setScanName(e.target.value)} placeholder="Project name (optional)"/><button className="primary" disabled={!scanFile||scanBusy} onClick={uploadAndScan}>{scanBusy?<RefreshCw className="spin" size={15}/>:<UploadCloud size={16}/>} Scan project</button></div>
       {scanError&&<div className="error"><AlertTriangle size={16}/>{scanError}</div>}
       {scanResult&&<div className="scan-summary"><div><b>{scanResult.project?.project_name||scanResult.project_name||"Scan completed"}</b><small>{scanResult.total_findings??scanResult.findings?.length??0} finding(s) detected</small></div><div className="severity-chips">{Object.entries(scanResult.severity_breakdown||{}).filter(([,v])=>v>0).map(([k,v])=><span key={k} className={k.toLowerCase()}>{k} {v}</span>)}</div></div>}
      </div>
      <div className="workspace-card"><div className="card-heading"><div><span className="eyebrow">MODULE 03 · MODULE 04</span><h3><Gauge size={18}/> Readiness & recommendations</h3><p>Load a previously scanned project and generate a migration assessment.</p></div></div>
       <div className="scan-form"><select value={selectedProject} onChange={e=>setSelectedProject(e.target.value)}><option value="">Select registered project</option>{projects.map(x=><option key={x.id} value={String(x.id)}>{x.project_name} · #{x.id}</option>)}</select><button className="primary" disabled={!selectedProject||scanBusy} onClick={generateProjectIntelligence}>{scanBusy?<RefreshCw className="spin" size={15}/>:<Activity size={16}/>} Generate assessment</button></div>
       {(readiness||recommendations||inventory)&&<div className="intelligence-summary"><span>Inventory: <b>{inventory?.total_inventory_records??"—"}</b></span><span>Readiness: <b>{readiness?.readiness_score??readiness?.score??"Not generated"}</b></span><span>Recommendations: <b>{recommendations?.recommendations?.length??recommendations?.total_recommendations??"Loaded"}</b></span></div>}
       {readiness&&selectedProject&&<div className="report-actions readiness-report-action"><a href={`${API}/api/reports/${selectedProject}/pdf`} target="_blank" rel="noreferrer"><FileText size={16}/> Download Readiness Audit PDF</a></div>}
       {readiness?.summary?.risk_breakdown&&<div className="readiness-breakdown"><b>Heuristic score breakdown · Base 100</b><div>{Object.entries(readiness.summary.risk_breakdown).map(([key,item])=><span key={key}>{key.replaceAll("_"," ")}: {item.count} · −{item.deduction}</span>)}</div><small>{readiness.summary.total_risk_points} total risk points deducted. {readiness.summary.limitations?.[0]||"Not a formal certification."}</small></div>}
      </div>
     <div className="scanner-side-panel">
      <div className="workspace-card"><div className="card-heading"><div><span className="eyebrow">RECENT SCAN HISTORY</span><h3>Stored projects</h3><p>Records loaded from the local Q-SHIELD database.</p></div><button className="decision" onClick={loadRecentScanHistory}>Refresh</button></div>
       {recentScanHistory.length?<div className="recent-scan-list">{recentScanHistory.map(item=><div className="recent-scan-item" key={item.id}><div><b>{item.name}</b><small>{item.created_at?new Date(item.created_at).toLocaleString():"Timestamp unavailable"}</small></div><span>{item.findings??"—"} findings · {item.inventory??"—"} inventory</span></div>)}</div>:<p className="muted">No stored scan records available.</p>}
      </div>
      <div className="workspace-card"><span className="eyebrow">STATIC ANALYSIS GUIDE</span><h3>What the scanner checks</h3><ul className="scanner-guide"><li>Cryptographic algorithms and API patterns in supported source/configuration files.</li><li>Severity and migration-priority heuristics.</li><li>Inventory records and source-level references.</li></ul><p className="muted">ZIP only · Up to 20 MB compressed · 500 entries · 50 MB expanded · 2 MB per file. Generated Q-SHIELD evidence, caches and build/dependency folders are skipped. Uploaded code is never executed. Static analysis cannot guarantee discovery of runtime calls, external services or deployed TLS settings.</p></div>
     </div>
     </div>
     {inventory?.inventory?.length>0&&<div className="workspace-card inventory-card"><div className="card-heading"><div><span className="eyebrow">CRYPTOGRAPHIC INVENTORY</span><h3>Detected algorithm records</h3></div><span className="mini-status">{inventory.total_inventory_records} RECORDS</span></div><div className="table-wrap"><table><thead><tr><th>Algorithm</th><th>File</th><th>Purpose</th><th>Migration priority</th></tr></thead><tbody>{inventory.inventory.slice(0,12).map((x,i)=><tr key={i}><td>{x.algorithm}</td><td>{x.file_name}</td><td>{x.purpose||x.usage||"—"}</td><td>{x.migration_priority||"—"}</td></tr>)}</tbody></table></div></div>}
    </section>
   <section className="assisted-workflow" id="assisted-migration">
    <div className="lab-heading"><div><span className="eyebrow">MODULE 07 / HUMAN-IN-THE-LOOP MIGRATION</span><h2><ClipboardCheck size={22}/> Assisted Migration Review</h2><p>Generate source-aware patch proposals, approve or reject each supported change, then download a separate migrated archive.</p><p className="scope-note"><strong>Scope:</strong> Assisted Migration currently applies narrowly supported secret-management and TLS-verification patches. It does not automatically replace RSA/ECC or add ML-KEM. Use the <strong>PQC Migration Lab</strong> for its limited ML-KEM demonstration scaffold; protocol-level migration still requires manual engineering.</p></div><span className="lab-badge"><Eye size={15}/> Human approval required</span></div>
    <div className="lab-warning"><AlertTriangle size={17}/> Uploaded code is never executed. Only narrowly matched credential assignments and Python TLS verification flags currently receive applicable source patches. Complex RSA/ECC, DES, AES-mode and password-hash redesigns remain guidance-only.</div>
    <div className="lab-controls"><label className="lab-file"><FileArchive size={20}/><span>{assistFile?assistFile.name:"Choose original project ZIP"}</span><input type="file" accept=".zip,application/zip" onChange={e=>{setAssistFile(e.target.files?.[0]||null);setAssistJob(null);setAssistApplied(null);}}/></label><button className="primary" disabled={!assistFile||assistBusy} onClick={prepareAssisted}>{assistBusy?<><RefreshCw className="spin" size={16}/> Preparing…</>:<><FileCode2 size={17}/> Generate review proposals</>}</button></div>
    {assistError&&<div className="error"><AlertTriangle size={17}/>{assistError}</div>}
    {assistJob&&<div className="assist-review">
      <div className="assist-summary"><div><span className="eyebrow">REVIEW JOB · {assistJob.job_id}</span><h3>{assistJob.proposal_count} proposal(s) generated</h3><p>{assistJob.patchable_count} patchable · {assistJob.guidance_only_count} guidance-only</p></div><span className="lab-badge">{assistJob.workflow||"PATCH REVIEW"}</span></div>
      <div className="assist-proposals">{assistJob.proposals?.map(item=><article className="assist-proposal" key={item.proposal_id}>
       <div className="assist-proposal-head"><div><span className="eyebrow">{item.proposal_id} · {item.category}</span><h4>{item.title}</h4><p>{item.file}</p></div><span className={`proposal-status ${item.status?.toLowerCase()}`}>{item.status?.replaceAll("_"," ")}</span></div>
       <p>{item.rationale}</p>
       {item.patch_available?<><details className="proposal-diff"><summary>Review proposed code diff</summary><pre>{item.diff}</pre></details>{item.status==="PENDING_REVIEW"?<div className="proposal-actions"><button className={`decision approve ${assistDecisions[item.proposal_id]==="approve"?"selected":""}`} onClick={()=>setAssistDecisions(v=>({...v,[item.proposal_id]:"approve"}))}><Check size={15}/> Approve</button><button className={`decision reject ${assistDecisions[item.proposal_id]==="reject"?"selected":""}`} onClick={()=>setAssistDecisions(v=>({...v,[item.proposal_id]:"reject"}))}><X size={15}/> Reject</button></div>:null}<small>{item.validation_note}</small></>:<small className="guidance-note">Guidance only — no safe automated source patch is available for this finding.</small>}
      </article>)}</div>
      {assistJob.proposals?.some(x=>x.patch_available&&x.status==="PENDING_REVIEW")&&<button className="primary apply-approved" disabled={assistBusy||!Object.keys(assistDecisions).length} onClick={submitAssistedDecisions}>{assistBusy?<><RefreshCw className="spin" size={16}/> Applying decisions…</>:<><ClipboardCheck size={17}/> Submit decisions & build migrated ZIP</>}</button>}
      {assistApplied&&<div className="assist-complete"><CheckCircle2 size={20}/><div><b>Review decisions saved</b><p>{assistApplied.approved_patch_count} approved · {assistApplied.rejected_patch_count} rejected · {assistApplied.pending_patch_count} pending</p><a href={`${API}${assistApplied.download_endpoint}`}><DownloadCloud size={16}/> Download approved migration ZIP</a></div></div>}
    </div>}
   </section>
   <section className="hero" id="comparison"><div className="hero-copy"><div className="kicker"><span className="pulse"/> CRYPTOGRAPHIC MIGRATION VERIFICATION</div><h1>Classical vs <em>Post-Quantum.</em></h1><p>Compare two project archives, inspect cryptographic changes, identify residual risks and generate an evidence-backed migration audit.</p></div><div className="hero-art"><div className="orbit orbit-a"/><div className="orbit orbit-b"/><div className="core"><ShieldCheck size={42}/><span>PQC</span></div><div className="node n1">RSA</div><div className="node n2">ML-KEM</div><div className="node n3">ECC</div><div className="node n4">ML-DSA</div></div></section>
   <section className="section-head"><div><span className="eyebrow">01 / INPUT ARCHIVES</span><h2>Upload both project versions</h2><p>Use the original project and its migrated counterpart. ZIP archives only.</p></div><div className="secure-note"><LockKeyhole size={16}/> Uploaded source is analysed, never executed</div></section>
   <div className="upload-grid"><FilePicker label="BEFORE PQC · CLASSICAL" hint="Original source project (.zip)" file={before} onChange={setBefore} tone="amber"/><div className="swap"><ArrowRightLeft size={20}/></div><FilePicker label="AFTER PQC · MIGRATED" hint="Post-quantum migrated project (.zip)" file={after} onChange={setAfter} tone="mint"/></div>
   <div className="action-row"><div className="file-hint">Maximum combined upload: 45 MB · Supported source types follow the Q-SHIELD scanner.</div><button className="primary" disabled={!ready} onClick={compare}>{busy?<><RefreshCw className="spin" size={17}/> Analysing projects…</>:<><Activity size={17}/> Compare projects</>}</button></div>
   {error&&<div className="error"><AlertTriangle size={18}/>{error}</div>}
   {result&&detail&&<section className="results" id="results">
    <div className="result-title"><div><span className="eyebrow">02 / COMPARISON RESULTS</span><h2>Migration impact overview</h2><p>Comparison ID · {result.comparison_id}</p></div><div className="report-actions"><a href={`${API}/api/comparison/${result.comparison_id}/pdf`}><FileText size={16}/> Download PDF</a><a href={`${API}/api/comparison/${result.comparison_id}/download`}><Download size={16}/> Evidence ZIP</a></div></div>
    <div className="metric-grid"><Metric label="Findings resolved" value={fmt(s.resolved)} sub={`${s.migration_effectiveness_percent}% of original finding signatures`} icon={CheckCircle2}/><Metric label="Remaining findings" value={fmt(s.remaining)} sub="Matched findings still present" icon={AlertTriangle}/><Metric label="New findings" value={fmt(s.new)} sub="Detected only in migrated project" icon={Activity}/><Metric label="PQC detections" value={fmt(Object.values(s.after_pqc_algorithms||{}).reduce((a,b)=>a+b,0))} sub="Token detections in after project" icon={ShieldCheck}/></div>
    <div className="score-grid"><div className="score-card"><span>BEFORE · READINESS</span><strong>{s.before_readiness.score}<small>/100</small></strong><b>{s.before_readiness.risk_level}</b></div><div className="score-arrow"><ArrowRightLeft/></div><div className="score-card good"><span>AFTER · READINESS</span><strong>{s.after_readiness.score}<small>/100</small></strong><b>{s.after_readiness.risk_level}</b></div><div className="score-note"><h3>Readiness movement</h3><strong>{s.after_readiness.score-s.before_readiness.score>0?"+":""}{(s.after_readiness.score-s.before_readiness.score).toFixed(2)} points</strong><p>Heuristic comparison indicator. Not a certification or proof of quantum resistance.</p></div></div>
    <div className="classification-strip"><div><span>CONVENTIONAL HARDENING</span><strong>{s.conventional_hardening_count||0} adoption(s)</strong><small>Modern digest adoption is reported separately from PQC migration.</small></div><div><span>PQC MIGRATION STATUS</span><strong>{s.pqc_migration_status||"NOT_ASSESSED"}</strong><small>Algorithm references are evidence only; implementation requires verification.</small></div></div>
    <div className="pqc-verification-panel"><div><span className="eyebrow">04 / IMPLEMENTATION VERIFICATION</span><h3>Verify PQC implementation evidence</h3><p>Statically inspect the migrated source and run a Q-SHIELD provider self-test. Uploaded project code is never executed.</p></div><button className="primary" disabled={verifyBusy} onClick={verifyPqc}>{verifyBusy?<><RefreshCw className="spin" size={16}/> Verifying…</>:<><ShieldCheck size={16}/> Verify PQC implementation</>}</button>{verifyError&&<div className="error">{verifyError}</div>}{(verifyResult||detail.pqc_verification)&&(()=>{const v=verifyResult||detail.pqc_verification;return <div className="verify-result"><strong>{v.verification_level}</strong><p>Static checks: {v.source_checks_passed}/{v.source_checks_total} · Provider self-test: {v.runtime_self_test?.status}</p><div className="verify-checks">{Object.entries(v.source_checks||{}).map(([k,ok])=><span key={k} className={ok?"pass":"miss"}>{ok?"✓":"○"} {k.replaceAll("_"," ")}</span>)}</div><p>{v.runtime_self_test?.detail}</p><small>Provider self-test tests Q-SHIELD's installed cryptography library, not the uploaded application. Static source checks do not prove protocol security.</small></div>})()}</div>
    <div className="tabs"><button className={tab==="overview"?"active":""} onClick={()=>setTab("overview")}>Algorithms</button><button className={tab==="findings"?"active":""} onClick={()=>setTab("findings")}>Findings</button><button className={tab==="code"?"active":""} onClick={()=>setTab("code")}>Code changes</button><button className={tab==="bench"?"active":""} onClick={()=>setTab("bench")}>Module 5 benchmarks</button></div>
    {tab==="overview"&&<div className="panel"><div className="panel-head"><div><h3>Cryptographic algorithm distribution</h3><p>Occurrence counts from independently scanned source files</p></div><div className="legend"><span className="dot amber"/> Before <span className="dot green"/> After</div></div><Bars before={beforeA.algorithms} after={afterA.algorithms}/><div className="pqc-detected"><h4>Post-quantum algorithm tokens detected after migration</h4>{Object.keys(afterA.pqc_algorithms).length?Object.entries(afterA.pqc_algorithms).map(([k,v])=><span key={k}>{k} <b>{v}</b></span>):<p>No recognized PQC API/name tokens detected in supported source/configuration files. Generated migration reports and README files are excluded.</p>}{afterA.pqc_evidence?.length>0&&<div className="pqc-evidence-list"><h4>PQC evidence review</h4>{afterA.pqc_evidence.slice(0,30).map((item,i)=><div className="pqc-evidence-row" key={`${item.file}-${item.line}-${i}`}><b>{item.algorithm}</b><span>{item.file}:{item.line}</span><em>{item.classification === "API_USAGE_CANDIDATE" ? "API usage candidate" : "Token reference"}</em><small>{item.verification}</small></div>)}</div>}<div className="pqc-evidence-note"><strong>Verification status:</strong> Token references and API-shaped expressions are not proof of a correct PQC implementation. All detections remain UNVERIFIED until API semantics, parameter sets, key handling, protocol integration and test evidence are reviewed.</div><div className="adoption-list"><h4>Conventional hardening · modern algorithm adoption</h4>{(c.modern_algorithm_adoptions||[]).length?(c.modern_algorithm_adoptions||[]).map((item,i)=><div className="adoption-row" key={`${item.file}-${item.line}-${i}`}><b>{item.algorithm}</b><span>{item.file}:{item.line}</span><small>{item.review_note}</small></div>):<p>No modern digest API adoption was separately identified.</p>}</div></div></div>}
    {tab==="findings"&&<div className="panel"><div className="finding-columns">{["resolved","remaining","new"].map(k=><div className="finding-col" key={k}><h3>{k} <b>{c.findings[k].length}</b></h3>{c.findings[k].slice(0,100).map((x,i)=><div className="finding" key={i}><b>{x.algorithm}</b><span>{x.file_name}:{x.line_number}</span><small>{x.finding}</small></div>)}{!c.findings[k].length&&<p className="muted">None detected</p>}</div>)}</div></div>}
    {tab==="code"&&<div className="panel"><div className="file-change-summary"><div><b>{c.files?.added?.length||0}</b><span>Added files</span></div><div><b>{c.code_diffs?.length||0}</b><span>Modified files</span></div><div><b>{c.files?.removed?.length||0}</b><span>Removed files</span></div><div><b>{c.files?.renamed_identical_hash?.length||0}</b><span>Rename hints</span></div></div>
      {[ ["Added",c.files?.added||[]], ["Modified",(c.code_diffs||[]).map(x=>x.file)], ["Removed",c.files?.removed||[]] ].map(([label,files])=><div className="file-change-list" key={label}><h4>{label} files <small>{files.length}</small></h4>{files.length?files.slice(0,100).map(file=><span key={file}>{file}</span>):<p className="muted">None detected</p>}</div>)}
      {(c.files?.renamed_identical_hash||[]).length>0&&<div className="file-change-list"><h4>Identical-content rename hints</h4>{c.files.renamed_identical_hash.map((x,i)=><span key={i}>{x.from} → {x.to} · {x.match}</span>)}</div>}
      {c.code_diffs?.length?(c.code_diffs).map((d,i)=><details className="diff" key={i} open={i===0}><summary>{d.file}<span>+{d.added_lines} / -{d.removed_lines}</span></summary><pre>{d.diff}</pre></details>):<p className="muted">No line-level changes for files with matching relative paths.</p>}
      <p className="muted">Unique finding signatures: {c.findings?.counts?.before??"—"} before / {c.findings?.counts?.after??"—"} after. Raw scanner occurrences: {c.findings?.counts?.raw_scanner_before??"—"} before / {c.findings?.counts?.raw_scanner_after??"—"} after.</p></div>}
    {tab==="bench"&&<div className="panel"><h3>Historical benchmark records</h3><p className="muted">{detail.benchmark_note}</p>{detail.benchmarks?.length?<div className="table-wrap"><table><thead><tr><th>Algorithm</th><th>Family / mode</th><th>Operation</th><th>Mean (ms)</th><th>Median (ms)</th><th>P95 (ms)</th><th>Samples</th><th>Public key (bytes)</th><th>Ciphertext (bytes)</th><th>Record source</th></tr></thead><tbody>{detail.benchmarks.map((b,i)=><tr key={`${b.benchmark_id||"legacy"}-${b.algorithm}-${b.operation}-${i}`}><td>{b.algorithm}</td><td>{b.family||b.mode||"—"}</td><td>{String(b.operation||"—").replaceAll("_"," ")}</td><td>{b.mean_ms??b.execution_time??"—"}</td><td>{b.median_ms??"—"}</td><td>{b.p95_ms??"—"}</td><td>{b.samples??"—"}</td><td>{b.key_size??"—"}</td><td>{b.ciphertext_size??"—"}</td><td>{b.source||"Historical record"}</td></tr>)}</tbody></table></div>:<p>No historical benchmark records were found in either benchmark storage table. Run a benchmark in the Benchmarking workspace to create a new session.</p>}</div>}
    <div className="footnote"><AlertTriangle size={16}/> Migration effectiveness compares matching scanner finding signatures. PQC names are token detections only; correct implementation, protocol design and key management require separate verification.</div>
   </section>}
   <section className="pqc-lab" id="pqc-migration">
    <div className="lab-heading"><div><span className="eyebrow">03 / CONTROLLED TRANSFORMATION</span><h2><FlaskConical size={22}/> PQC Migration Lab</h2><p>Generate a real ML-KEM-768 demonstration migration from a narrowly-scoped Python ECDH demo stub.</p></div><span className="lab-badge"><Shield size={15}/> FIPS 203 · ML-KEM-768</span></div>
    <div className="lab-warning"><AlertTriangle size={17}/> This is a safe, limited demonstration transformation. It does not blindly rewrite live ECDH exchanges, RSA encryption or digital-signature flows. Those require protocol-aware engineering.</div>
    <div className="lab-controls"><label className="lab-file"><FileArchive size={20}/><span>{pqcFile?pqcFile.name:"Choose original classical project ZIP"}</span><input type="file" accept=".zip,application/zip" onChange={e=>{setPqcFile(e.target.files?.[0]||null);setPqcResult(null);}}/></label><button className="primary" disabled={!pqcFile||pqcBusy} onClick={runPqcMigration}>{pqcBusy?<><RefreshCw className="spin" size={16}/> Preparing migration…</>:<><FlaskConical size={17}/> Generate PQC migration ZIP</>}</button></div>
    {pqcError&&<div className="error"><AlertTriangle size={17}/>{pqcError}</div>}
    {pqcResult&&<div className="pqc-result"><div><span className="eyebrow">MIGRATION JOB · {pqcResult.job_id}</span><h3>{pqcResult.report.pqc_status}</h3><p>{pqcResult.report.modified_files.length} file(s) transformed · {pqcResult.report.manual_migration_actions.length} manual action(s)</p></div><a href={`${API}${pqcResult.download_endpoint}`}><DownloadCloud size={17}/> Download PQC project ZIP</a><details><summary>View migration report</summary><pre>{JSON.stringify(pqcResult.report,null,2)}</pre></details></div>}
   </section>
   <section className="pqc-lab e2e-audit" id="end-to-end-audit">
    <div className="lab-heading"><div><span className="eyebrow">FINAL MILESTONE · MODULE 7.10</span><h2><ShieldCheck size={22}/> End-to-End PQC Migration Audit</h2><p>One project upload. Unified cryptographic discovery, migration policy, readiness heuristic, governance and downloadable evidence.</p></div><span className="lab-badge"><ClipboardCheck size={15}/> Human review supported</span></div>
    <div className="lab-warning"><AlertTriangle size={17}/> Static analysis only. Uploaded code is never executed or retained. Readiness is a heuristic; provider self-tests and implementation verification remain separate evidence.</div>
    <div className="lab-controls"><label className="lab-file"><FileArchive size={20}/><span>{auditFile?auditFile.name:"Choose project ZIP for unified audit"}</span><input type="file" accept=".zip,application/zip" onChange={e=>{setAuditFile(e.target.files?.[0]||null);setAuditJob(null);}}/></label><select value={auditProfile} onChange={e=>{setAuditProfile(e.target.value);setAuditJob(null);setAuditError("");}}><option value="TRANSITION">Transition policy</option><option value="STRICT">Strict policy</option></select><span className="file-hint">{auditProfile==="STRICT"?"Strict: unresolved RSA/ECC, hash and AES configuration findings require policy review.":"Transition: supports managed migration plans for eligible RSA/ECC and AES findings."}</span><button className="primary" disabled={!auditFile||auditBusy} onClick={runEndToEndAudit}>{auditBusy?<><RefreshCw className="spin" size={16}/> Running audit…</>:<><Activity size={17}/> Run unified audit</>}</button></div>
    {auditError&&<div className="error"><AlertTriangle size={17}/>{auditError}</div>}
    {auditJob&&<div className="assist-review"><div className="assist-summary"><div><span className="eyebrow">AUDIT · {auditJob.audit_id}</span><h3>{auditJob.summary.total_findings} finding(s) · {auditJob.summary.scanned_files} file(s)</h3><p>{auditJob.summary.critical_or_high} critical/high · {auditJob.summary.pending_decisions} pending review · {auditJob.summary.decision_counts?.APPROVED||0} approved · {auditJob.summary.decision_counts?.EXCEPTION||0} exceptions · {auditJob.summary.decision_counts?.DEFERRED||0} deferred</p><p className="muted">Policy applied: <strong>{auditJob.policy_profile==="STRICT"?"STRICT":"TRANSITION"}</strong> · Scanner detections stay constant; policy classifications below change with the selected profile.</p></div><span className="lab-badge">{auditJob.status}</span></div>
     <div className="metric-grid"><Metric label="Readiness heuristic" value={`${auditJob.readiness.score}/100`} sub={auditJob.readiness.risk_level} icon={Activity}/><Metric label="Total findings" value={auditJob.summary.total_findings} sub="Unchanged scanner detections" icon={AlertTriangle}/><Metric label="Remediation required" value={auditJob.summary.status_counts?.REMEDIATION_REQUIRED||0} sub="Direct corrective action" icon={FileCode2}/><Metric label="Migration plan required" value={auditJob.summary.status_counts?.MIGRATION_PLAN_REQUIRED||0} sub="Transition migration obligations" icon={ArrowRightLeft}/><Metric label="Policy review required" value={auditJob.summary.status_counts?.POLICY_REVIEW_REQUIRED||0} sub="Strict governance gate" icon={Shield}/><Metric label="Informational / compliant" value={auditJob.summary.status_counts?.COMPLIANT_OR_INFORMATIONAL||0} sub="No immediate policy action" icon={CheckCircle2}/></div>
     <div className="policy-compare-panel"><div className="policy-compare-heading"><div><span className="eyebrow">POLICY PROFILE DIFFERENCE</span><h3>Same source · Different governance requirements</h3><p className="muted">{auditJob.policy_profile_comparison?.interpretation||"The two profiles evaluate the same scanner detections."}</p></div><div className="policy-delta-count"><strong>{auditJob.policy_profile_comparison?.changed_findings_count||0}</strong><span>finding classifications change</span></div></div><div className="policy-compare-grid">{["TRANSITION","STRICT"].map(profile=><div className="policy-compare-card" key={profile}><h4>{profile==="STRICT"?"Strict policy":"Transition policy"}</h4><strong>{auditJob.policy_profile_comparison?.profiles?.[profile]?.total_findings??auditJob.summary.total_findings} findings</strong>{Object.entries(auditJob.policy_profile_comparison?.profiles?.[profile]?.status_counts||{}).map(([status,count])=><div className="policy-count-row" key={status}><span>{status.replaceAll("_"," ")}</span><b>{count}</b></div>)}</div>)}</div>{(auditJob.policy_profile_comparison?.changed_findings||[]).length>0&&<><h4 className="policy-delta-title">Finding-level policy changes</h4><div className="table-wrap"><table><thead><tr><th>Finding</th><th>Algorithm</th><th>Transition status</th><th>Strict status</th></tr></thead><tbody>{auditJob.policy_profile_comparison.changed_findings.map(x=><tr key={x.finding_id}><td>{x.finding_id}<br/><small>{x.file}:{x.line_number||"?"}</small></td><td>{x.algorithm}</td><td>{x.transition_status.replaceAll("_"," ")}</td><td>{x.strict_status.replaceAll("_"," ")}</td></tr>)}</tbody></table></div></>}</div>
     <h3 style={{marginTop:22}}>Policy recommendations</h3><div className="table-wrap"><table><thead><tr><th>Policy status</th><th>Required action</th><th>Guidance</th><th>Findings</th></tr></thead><tbody>{(auditJob.recommendations||[]).map((x,i)=><tr key={`${x.policy_status}-${x.policy_action}-${i}`}><td>{x.policy_status?.replaceAll("_"," ")}</td><td>{x.policy_action}</td><td>{x.target_guidance}</td><td>{x.affected_findings}</td></tr>)}</tbody></table></div>
     {auditJob.transition_roadmap&&<section className="transition-roadmap"><div className="eyebrow">TRANSITION PROFILE · IMPLEMENTATION ROADMAP</div><h3>{auditJob.transition_roadmap.title}</h3><p className="muted">{auditJob.transition_roadmap.purpose}</p><div className="roadmap-phases">{auditJob.transition_roadmap.phases.map(phase=><article className="roadmap-phase" key={phase.phase}><div className="roadmap-phase-number">PHASE {phase.phase}</div><h4>{phase.name}</h4><p>{phase.goal}</p><ul>{phase.tasks.map((task,i)=><li key={i}>{task}</li>)}</ul><p className="roadmap-exit"><b>Exit criteria:</b> {phase.exit_criteria}</p></article>)}</div><h4>Algorithm-specific migration guidance</h4><div className="table-wrap"><table><thead><tr><th>Algorithm / priority</th><th>Suggested target</th><th>Source files</th><th>Implementation guidance</th></tr></thead><tbody>{auditJob.transition_roadmap.algorithm_plans.map((plan,i)=><tr key={`${plan.algorithm}-${i}`}><td>{plan.algorithm}<br/><small>{plan.priority}</small></td><td>{plan.suggested_target}</td><td>{plan.files.join(", ")}</td><td>{plan.implementation_guidance}</td></tr>)}</tbody></table></div><h4>Governance and limitations</h4><ul>{[...auditJob.transition_roadmap.governance,...auditJob.transition_roadmap.limitations].map((item,i)=><li key={i}>{item}</li>)}</ul></section>}
     <div className="report-actions" style={{marginTop:16}}><a href={`${API}/api/end-to-end-audit/${auditJob.audit_id}/pdf`}><FileText size={16}/> Consolidated PDF</a><a href={`${API}/api/end-to-end-audit/${auditJob.audit_id}/evidence`}><Download size={16}/> Evidence ZIP</a><a href={`${API}/api/end-to-end-audit/${auditJob.audit_id}/report`}><Download size={16}/> JSON report</a></div>
     <h3 style={{marginTop:22}}>Human governance decision</h3><div className="lab-controls" style={{marginBottom:14,flexWrap:"wrap"}}><select value={auditSelectedFinding} onChange={e=>setAuditSelectedFinding(e.target.value)}><option value="">Select pending finding</option>{auditJob.findings.filter(x=>x.decision==="PENDING").map(x=><option key={x.finding_id} value={x.finding_id}>{x.finding_id} · {x.algorithm} · {x.severity}</option>)}</select><select value={auditDecision} onChange={e=>setAuditDecision(e.target.value)}><option value="APPROVE_REMEDIATION_PLAN">Approve remediation plan</option><option value="ACCEPT_TIME_BOUND_EXCEPTION">Accept time-bound exception</option><option value="DEFER_WITH_RATIONALE">Defer with rationale</option></select><input aria-label="Decision rationale" placeholder="Reviewer rationale (required for exception/defer)" value={auditNote} onChange={e=>setAuditNote(e.target.value)}/>{auditDecision==="ACCEPT_TIME_BOUND_EXCEPTION"&&<input aria-label="Exception expiry" type="date" value={auditExpiry} onChange={e=>setAuditExpiry(e.target.value)}/>}<button className="primary" disabled={!auditSelectedFinding||auditDecisionBusy} onClick={submitAuditDecision}>{auditDecisionBusy?"Saving…":"Record decision"}</button></div>
     <h3 style={{marginTop:22}}>Migration policy findings</h3><div className="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th><th>Algorithm</th><th>File</th><th>Policy action</th><th>Policy status</th><th>Decision</th></tr></thead><tbody>{auditJob.findings.slice(0,100).map(x=><tr key={x.finding_id}><td>{x.finding_id}</td><td>{x.severity}</td><td>{x.algorithm}</td><td>{x.file}:{x.line_number||"?"}</td><td>{x.policy_action}</td><td><span className="mini-status">{(x.policy_status||"UNCLASSIFIED").replaceAll("_"," ")}</span></td><td>{x.decision}</td></tr>)}</tbody></table></div>
     <p className="muted">Source SHA-256: {auditJob.source_sha256} · Original ZIP retained: no · Source modified: no · Provider self-test: {auditJob.verification_evidence.provider_self_test.status}</p>
    </div>}
    <div className="action-row"><span className="file-hint">Previously generated unified audits</span><button className="decision" onClick={loadAuditHistory}>Refresh history</button></div>
    {auditHistory.length>0&&<div className="table-wrap"><table><thead><tr><th>Audit ID</th><th>Source</th><th>Status</th><th>Findings</th><th>Created</th></tr></thead><tbody>{auditHistory.map(x=><tr key={x.audit_id}><td>{x.audit_id.slice(0,8)}</td><td>{x.source_filename}</td><td>{x.status}</td><td>{x.summary.total_findings}</td><td>{new Date(x.created_at).toLocaleString()}</td></tr>)}</tbody></table></div>}
   </section>
    <section className="workspace benchmark-workspace" id="benchmarking">
     <div className="workspace-heading"><div><span className="eyebrow">MODULE 06 · COMPARATIVE BENCHMARKING</span><h2>Classical vs post-quantum performance</h2><p>Run the backend's comparative KEM benchmark and inspect persisted benchmark sessions.</p></div><button className="primary" disabled={benchmarkBusy||!benchmarkCatalog?.supported_algorithms?.length} onClick={runComparativeBenchmark}>{benchmarkBusy?<><RefreshCw className="spin" size={15}/> Running benchmark…</>:<><Play size={15}/> Run 30-repetition benchmark</>}</button></div>
     {benchmarkError&&<div className="error"><AlertTriangle size={16}/>{benchmarkError}</div>}
     {benchmarkCatalog&&<div className="benchmark-catalog"><span>Provider: <b>{benchmarkCatalog.provider}</b></span><span>Supported: <b>{benchmarkCatalog.supported_algorithms.join(", ")}</b></span><span>Unavailable: <b>{(benchmarkCatalog.unavailable_algorithms||[]).join(", ")||"None"}</b></span></div>}
     {benchmarkResult&&<div className="workspace-card benchmark-result"><div className="card-heading"><div><span className="eyebrow">LATEST RUN · {benchmarkResult.benchmark_id}</span><h3>Benchmark completed</h3><p>{benchmarkResult.repetitions} repetitions · {benchmarkResult.warmups} warmups · results persisted</p></div><span className="mini-status">SAVED</span></div><div className="table-wrap"><table><thead><tr><th>Algorithm</th><th>Operation</th><th>Mean time (ms)</th><th>Public key (bytes)</th><th>Ciphertext (bytes)</th><th>Secret (bytes)</th></tr></thead><tbody>{(benchmarkResult.results||[]).flatMap((x)=>Object.entries(x.operations||{}).map(([operation,stats])=><tr key={`${x.algorithm}-${operation}`}><td>{x.algorithm}</td><td>{operation.replaceAll("_"," ")}</td><td>{stats.mean_ms}</td><td>{x.sizes_bytes?.public_key??"—"}</td><td>{x.sizes_bytes?.ciphertext??"—"}</td><td>{x.sizes_bytes?.shared_secret??"—"}</td></tr>))}</tbody></table></div></div>}
     <div className="workspace-card"><div className="card-heading"><div><span className="eyebrow">PERSISTED HISTORY</span><h3>Previous benchmark sessions</h3></div><button className="decision" onClick={loadBenchmarkWorkspace}>Refresh history</button></div>{benchmarkRuns.length?<div className="table-wrap"><table><thead><tr><th>Benchmark ID</th><th>Repetitions</th><th>Warmups</th><th>Created</th></tr></thead><tbody>{benchmarkRuns.slice(0,8).map(x=><tr key={x.benchmark_id}><td>{x.benchmark_id}</td><td>{x.repetitions}</td><td>{x.warmups}</td><td>{x.created_at}</td></tr>)}</tbody></table></div>:<p className="muted">No comparative benchmark sessions are available yet.</p>}</div>
     <p className="benchmark-caveat">Benchmark values are local microbenchmark observations. They exclude network, serialization and application overhead and should not be interpreted as universal performance rankings. X25519 key agreement and KEM encapsulation are different operations.</p>
    </section>
    <footer>Q-SHIELD · POST-QUANTUM SECURITY WORKBENCH <span>Classical cryptography → Post-quantum migration verification</span></footer>
  </main></div>
 </div>
}
