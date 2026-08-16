"""Apply the minimal safety/compatibility patch to the retained native SPA bundle.

The original React source is not present in this repository.  Keep every edit
here deterministic and fail closed when the expected native bundle changes.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return source.replace(old, new, 1)


def replace_once_or_current(source: str, old: str, new: str, label: str) -> str:
    """Apply a canonical hotfix once, or verify it is already present."""
    old_count = source.count(old)
    if old_count == 1:
        return source.replace(old, new, 1)
    if old_count == 0 and source.count(new) == 1:
        return source
    raise RuntimeError(f"{label}: expected one old or current match, found {old_count}")


def replace_between(source: str, start: str, end: str, replacement: str, label: str) -> str:
    start_at = source.find(start)
    if start_at < 0:
        raise RuntimeError(f"{label}: start anchor missing")
    end_at = source.find(end, start_at)
    if end_at < 0:
        raise RuntimeError(f"{label}: end anchor missing")
    return source[:start_at] + replacement + source[end_at:]


def patch(source: str) -> str:
    # Native SPECTRUM is the actionable confirmed-exposure work queue.  An
    # explicit history link may load a past false-positive decision for review.
    source = replace_once_or_current(
        source,
        "/api/spectrum/findings?limit=2000",
        "window.location.search.includes('history=1')?'/api/spectrum/findings?limit=2000':'/api/spectrum/findings?limit=2000&scope=confirmed_exposure'",
        "SPECTRUM canonical scope",
    )

    # A missing aggregate is a real state, not zero and not a render error.
    source = replace_once_or_current(
        source,
        "children:e.aggregate_tes.toFixed(1)",
        "children:e.aggregate_tes==null?`N/A`:e.aggregate_tes.toFixed(1)",
        "SYNTHESIS null TES",
    )
    source = replace_once_or_current(
        source,
        "strokeDashoffset:502-502*(e.aggregate_tes/10)",
        "strokeDashoffset:e.aggregate_tes==null?502:502-502*(e.aggregate_tes/10)",
        "SYNTHESIS null gauge",
    )
    source = replace_once(
        source,
        "children:`CRITICAL RISK`",
        "children:e.aggregate_tes==null?`No confirmed scoreable exposure`:`CURRENT TENANT RISK`",
        "SYNTHESIS null explanation",
    )

    # Native SPOTLIGHT keeps its report workflow, but its live cards consume
    # the canonical tenant posture rather than the global catalogue.
    source = replace_once(
        source,
        "Promise.all([$(`/api/scout/stats`),$(`/api/scout/findings?limit=3&ransomware_only=true`),$(`/api/synthesis/dashboard`),$(`/api/spotlight/history`),$(`/api/assets/stats`)])",
        "Promise.all([Promise.resolve({}),Promise.resolve({data:[]}),$(`/api/synthesis/dashboard`),$(`/api/spotlight/history`),$(`/api/assets/stats`)])",
        "SPOTLIGHT canonical sources",
    )
    source = replace_once(
        source,
        "t(e),r(n.data||[]),a({...i,assetTotal:s?.total||0}),h(o||[])",
        "t({total_findings:i?.exposure_coverage?.asset_linked_count??0,ransomware_linked:i?.exposure_coverage?.confirmed_ransomware_linked_count??0}),r([]),a({...i,assetTotal:s?.total||0}),h(o||[])",
        "SPOTLIGHT canonical metrics",
    )
    source = replace_once(source, "let S=i?.aggregate_tes||0,C=S>=7?", "let S=i?.aggregate_tes??null,C=S==null?`Unavailable`:S>=7?", "SPOTLIGHT null TES")
    source = replace_once(source, "value:S?S.toFixed(1):`—`", "value:S==null?`N/A`:S.toFixed(1)", "SPOTLIGHT TES display")
    source = source.replace("label:`KEV Findings`", "label:`Confirmed Exposures`")
    source = source.replace("sub:`CISA Catalog`", "sub:`Customer posture`")
    source = source.replace("label:`Ransomware-Linked`", "label:`Confirmed Ransomware`")
    source = source.replace("sub:`Active campaigns`", "sub:`Confirmed exposure`")
    source = source.replace("children:`CISA KEV`", "children:`Canonical Posture`")
    source = source.replace("Source: CISA KEV Catalog v2026.05.22", "Source: canonical customer posture snapshot")
    source = source.replace("Top Ransomware Threats", "Confirmed Ransomware Exposure")

    # SPECTRUM keeps the native deep-dive but does not receive or render the
    # server's private scoring composition.
    source = replace_between(
        source,
        "n.tes_breakdown&&(0,Y.jsxs)(Y.Fragment",
        ",(0,Y.jsxs)(`div`,{className:`pt-3 mt-3",
        "(0,Y.jsx)(`p`,{className:`text-sm text-text-muted`,children:`TES is calculated by the server from validated technical and contextual inputs. Exact factors are not exposed.`})",
        "SPECTRUM TES internals",
    )
    source = source.replace("TES Score Breakdown (Calculated via API)", "Contextual Exposure Summary")
    source = replace_once(
        source,
        "children:[n.vendor||`Unknown`,` `,n.product||``]",
        "children:n.asset?.name||n.asset?.hostname||`Confirmed asset`",
        "SPECTRUM canonical asset presentation",
    )
    source = replace_once(
        source,
        "(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "(0,Y.jsxs)(`section`,{className:`px-6 pb-2`,children:[(0,Y.jsx)(`h3`,{className:`text-sm font-semibold uppercase tracking-wider text-text-muted mb-3`,children:`Linked assets and evidence`}),(n.assets||[]).length?(0,Y.jsx)(`div`,{className:`space-y-2`,children:n.assets.map(e=>(0,Y.jsxs)(`div`,{className:`text-sm border border-border rounded-lg p-3`,children:[(0,Y.jsx)(`strong`,{children:e.name||e.hostname||e.asset_id}),(0,Y.jsx)(`p`,{className:`text-text-muted text-xs mt-1`,children:e.evidence||`No assignment note recorded.`})]},e.asset_id))}):(0,Y.jsx)(`p`,{className:`text-sm text-text-muted`,children:`No confirmed customer asset is linked.`}),(n.evidence_files||[]).length?(0,Y.jsxs)(`div`,{className:`mt-3 text-xs text-text-muted`,children:[`Attached evidence: `,n.evidence_files.map(e=>e.filename).join(`, `)]}):null]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "SPECTRUM linked assets and evidence",
    )
    source = replace_once(
        source,
        "n.evidence_files.map(e=>e.filename).join(`, `)]}):null]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "n.evidence_files.map(e=>e.filename).join(`, `)]}):null,(0,Y.jsx)(`a`,{href:`/sss-intake?finding=${encodeURIComponent(n.id)}`,className:`inline-flex mt-3 text-sm text-primary-400 hover:underline`,children:`Edit linked assets & evidence`})]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "SPECTRUM evidence editor link",
    )
    source = source.replace("Decision Recorded", "Current decision — revise if new evidence is recorded")

    # Remove the old client-side GRC scoring implementation while retaining
    # the native SOP, gap, evidence, and policy workflows.
    source, count = re.subn(
        r",tes_modifier:`[^`]*`,tes_impact:`[^`]*`",
        "",
        source,
    )
    if count != 7:
        raise RuntimeError(f"GRC control metadata: expected 7 matches, found {count}")
    source = replace_between(source, ",rm={0:`agm-0`", "function fm(e)", ";", "GRC scoring helpers")
    source = replace_once(
        source,
        "function pm(){let[e,t]=(0,v.useState)(`tes`)",
        "function pm(){let[R,I]=(0,v.useState)(null);(0,v.useEffect)(()=>{$(`/api/grc/tes-score`).then(I).catch(()=>I(null))},[]);let[e,t]=(0,v.useState)(`tes`)",
        "GRC public risk state",
    )
    source = replace_between(
        source,
        "se=(0,v.useCallback)((e,t)=>{Mp(`/api/grc/state`",
        ",ue=(e,t,r)=>",
        "se=(0,v.useCallback)((e,t)=>{Mp(`/api/grc/state`,{toggles:e,sop_state:t}).catch(()=>{})},[]),ce=(e,t)=>{a(e),se(t,e)}",
        "GRC server state update",
    )
    source = replace_between(
        source,
        ",M=sm(n),de=cm(n),fe=lm(n)",
        ",be=i.filter(e=>fm(e)===`Completed`).length",
        "",
        "GRC client score variables",
    )
    safe_tes = """e===`tes`&&(0,Y.jsxs)(`div`,{className:`space-y-6`,children:[(0,Y.jsxs)(`div`,{className:`glass-panel p-7 relative overflow-hidden`,children:[(0,Y.jsx)(`span`,{className:`text-[11px] text-text-muted font-mono uppercase tracking-wider block mb-2`,children:`AI-System Risk Score`}),(0,Y.jsxs)(`div`,{className:`flex items-center justify-between flex-wrap gap-5`,children:[(0,Y.jsx)(`span`,{className:`font-mono text-6xl font-bold text-primary-400`,children:R?.score??`N/A`}),(0,Y.jsx)(`span`,{className:`font-mono text-xs font-bold px-4 py-1.5 rounded-md border border-primary-500/30 text-primary-400`,children:R?.band||`Unavailable`})]}),(0,Y.jsxs)(`p`,{className:`mt-4 text-xs text-text-muted`,children:[`Scope: `,R?.scope||`AI_SYSTEM`,` · Calculated by the server. Exact factors, weights, ranges, and formulas are not sent to the browser.`]})]}),(0,Y.jsx)(hm,{icon:`◆`,iconBg:`bg-primary-500/20`,title:`Qualitative Risk Drivers`,subtitle:`Server-authoritative context`,children:(0,Y.jsx)(`div`,{className:`space-y-2`,children:(R?.drivers||[]).length?(R.drivers.map(e=>(0,Y.jsx)(`div`,{className:`text-sm text-text-muted border-b border-border/50 py-2`,children:e},e))):(0,Y.jsx)(`div`,{className:`text-sm text-text-muted`,children:`No qualitative drivers are recorded.`})})})]})"""
    source = replace_between(
        source,
        "e===`tes`&&(0,Y.jsxs)(`div`",
        ",e===`grc`&&(0,Y.jsxs)(`div`",
        safe_tes,
        "GRC safe TES tab",
    )
    source = source.replace("TES Modifier Impact", "Control posture")
    source = source.replace("Auto-feeds TES modifiers", "Server-authoritative governance status")
    source = source.replace("`TES Impact`", "`Status`")
    source = source.replace("children:e.tes_impact", "children:r")
    source = source.replace("value:e.tes_impact", "value:fm(r)")
    source = source.replace("evidence, and TES modifiers.", "evidence, and server-authoritative risk.")

    # Keep the canonical custom-policy lifecycle reachable from the restored
    # native library. The API remains the authority for role/reference rules.
    source = replace_once(
        source,
        "},ae=e=>{E(e),k.current?.click()}",
        "},policyArchive=async(e,t)=>{try{let n=await jp(`/api/grc/policies/${e}/archive`,{method:`PATCH`,body:JSON.stringify({archived:t})});if(!n.ok)throw Error();ee()}catch{alert(`Failed to ${t?`archive`:`restore`} policy.`)}},policySupersede=async e=>{try{let t=await $(`/api/grc/policies/${e}`),n=window.prompt(`New policy version`,t.version||`2.0`);if(!n)return;await Mp(`/api/grc/policies/${e}/supersede`,{version:n,content:t.content,title:t.title}),ee()}catch{alert(`Failed to supersede policy.`)}},policyDelete=async e=>{if(confirm(`Delete this custom policy? Referenced policies will be archived instead.`))try{await Pp(`/api/grc/policies/${e}`),ee()}catch{alert(`Failed to delete policy.`)}},ae=e=>{E(e),k.current?.click()}",
        "GRC policy lifecycle handlers",
    )
    source = replace_once(
        source,
        "(0,Y.jsx)(`button`,{className:`text-[11px] font-mono text-purple-400 bg-purple-500/10 border border-purple-500/20 px-3 py-1.5 rounded-lg hover:bg-purple-500/20 transition-colors opacity-0 group-hover:opacity-100`,children:`View Document →`})",
        "(0,Y.jsxs)(`div`,{className:`flex items-center gap-2`,children:[e.source===`custom`&&(0,Y.jsxs)(Y.Fragment,{children:[(0,Y.jsx)(`button`,{onClick:t=>{t.stopPropagation(),policyArchive(e.id,!e.archived)},className:`text-[10px] font-mono text-yellow-400`,children:e.archived?`Restore`:`Archive`}),(0,Y.jsx)(`button`,{onClick:t=>{t.stopPropagation(),policySupersede(e.id)},className:`text-[10px] font-mono text-cyan-400`,children:`Supersede`}),(0,Y.jsx)(`button`,{onClick:t=>{t.stopPropagation(),policyDelete(e.id)},className:`text-[10px] font-mono text-red-400`,children:`Delete`})]}),(0,Y.jsx)(`button`,{className:`text-[11px] font-mono text-purple-400 bg-purple-500/10 border border-purple-500/20 px-3 py-1.5 rounded-lg hover:bg-purple-500/20 transition-colors opacity-0 group-hover:opacity-100`,children:`View Document →`})]})",
        "GRC policy lifecycle controls",
    )

    # STANDARD displays coverage separately from compliance among assessed.
    source = replace_once(
        source,
        "(0,Y.jsxs)(`span`,{className:`text-3xl font-black ${e.score<80?`text-danger`:e.score<90?`text-warning`:`text-success`}`,children:[e.score,`%`]})",
        "(0,Y.jsxs)(`div`,{children:[(0,Y.jsxs)(`div`,{className:`text-sm font-bold text-primary-400`,children:[`Assessment coverage: `,e.assessment_coverage_label,` (`,e.assessment_coverage_pct,`%)`]}),(0,Y.jsxs)(`div`,{className:`text-xs text-text-muted mt-1`,children:[`Compliance among assessed: `,e.compliance_among_assessed_label]})]})",
        "STANDARD framework metrics",
    )
    source = replace_once(
        source,
        "style:{width:`${e.score}%`}",
        "style:{width:`${e.assessment_coverage_pct}%`}",
        "STANDARD coverage bar",
    )
    source = replace_once(
        source,
        "oe=async()=>{x(!0);try{let e=await Mp(`/api/standard/mas-trm/incident-report`,{incident_type:`cyber_security_incident`,severity:`high`,description:``,affected_systems:``});",
        "oe=async()=>{x(!0);try{let t=await $(`/api/incidents?limit=50`),n=t.items||[];if(!n.length)throw Error(`Create an Incident before generating a MAS draft.`);let r=n.length===1?n[0].id:window.prompt(`Incident ID for this MAS draft:\\n${n.map(e=>`${e.id} - ${e.title}`).join(`\\n`)}`,n[0].id);if(!r)return;let e=await Mp(`/api/standard/mas-trm/incident-report`,{incident_id:r});",
        "STANDARD incident selection",
    )

    # Human-readable STRIKE semantics while keeping the native matrix/workflow.
    source = source.replace(" blocked (", " no exposure observed (")
    source = source.replace("children:`Blocked`", "children:`No Exposure Observed`")
    source = source.replace("children:e.result", "children:String(e.result||``).replaceAll(`_`,` `)")
    source = source.replace("children:[(e.confidence*100).toFixed(0),`%`]", "children:[`Check confidence `,(e.confidence*100).toFixed(0),`%`]")
    source = source.replace("${t.exploitable} exploitable, ${t.blocked} no exposure observed", "${t.exploitable_observed} exploitable observed, ${t.no_exposure_observed} no exposure observed")
    source = replace_once(source, "if(e)try{d({message:`Launching scan against ${e}...`", "if(e&&confirm(`I confirm this target is explicitly authorised for non-destructive testing.`))try{d({message:`Launching scan against ${e}...`", "STRIKE quick-scan acknowledgement")
    source = replace_once(
        source,
        "te={exploitable:`bg-red-500/20 text-red-400 border-red-500/40`,blocked:`bg-green-500/20 text-green-400 border-green-500/40`,not_applicable:`bg-gray-500/20 text-gray-400 border-gray-500/40`,error:`bg-yellow-500/20 text-yellow-400 border-yellow-500/40`},ne={exploitable:`bg-red-500/15 border-red-500/30`,blocked:`bg-green-500/15 border-green-500/30`}",
        "te={EXPLOITABLE_OBSERVED:`bg-red-500/20 text-red-400 border-red-500/40`,NO_EXPOSURE_OBSERVED:`bg-green-500/20 text-green-400 border-green-500/40`,DEFENSIVE_BLOCK_VERIFIED:`bg-blue-500/20 text-blue-400 border-blue-500/40`,UNTESTED:`bg-gray-500/20 text-gray-400 border-gray-500/40`,ERROR:`bg-yellow-500/20 text-yellow-400 border-yellow-500/40`},ne={EXPLOITABLE_OBSERVED:`bg-red-500/15 border-red-500/30`,NO_EXPOSURE_OBSERVED:`bg-green-500/15 border-green-500/30`,DEFENSIVE_BLOCK_VERIFIED:`bg-blue-500/15 border-blue-500/30`}",
        "STRIKE outcome styles",
    )

    # A catalogue record with no decision is unreviewed, not "active".
    source = replace_once(
        source,
        "let A=async()=>{if(w){C(!0)",
        "let A=async()=>{if(w&&confirm(`I confirm this target is explicitly authorised for this SCOUT scan.`)){C(!0)",
        "SCOUT scan acknowledgement",
    )
    source = replace_once(
        source,
        "(0,Y.jsx)(`span`,{className:`text-primary-400`,children:`Active`})",
        "(0,Y.jsx)(`span`,{className:`text-text-muted`,children:`No EDIP decision`})",
        "SCOUT unreviewed label",
    )

    forbidden = (
        "TES Modifier Impact",
        "Auto-feeds TES modifiers",
        "tes_modifier:",
        "AGM ↑ if gap",
        "Base CVSS (",
        " × 0.35",
    )
    present = [value for value in forbidden if value in source]
    if present:
        raise RuntimeError(f"private scoring remnants remain: {present}")
    return source


def patch_canonical_bundle(source: str) -> str:
    """Apply this hotfix to the last validated canonical native bundle.

    The repository has no editable SPA source.  The canonical release bundle is
    therefore the reproducible compatibility base; do not regress its earlier
    safety and bootstrap patches by starting from an older artifact.
    source = source.replace("Decision Recorded", "Current decision — revise if new evidence is recorded")
    return source.replace("✓ Mitigated", "✓ Mitigation planned")

    """
    source = replace_once_or_current(
        source,
        "$(\u0060/api/spectrum/findings?limit=2000&scope=confirmed_exposure\u0060)",
        "$(window.location.search.includes(\u0060history=1\u0060)?\u0060/api/spectrum/findings?limit=2000\u0060:\u0060/api/spectrum/findings?limit=2000&scope=confirmed_exposure\u0060)",
        "SPECTRUM historical decision access",
    )
    source = replace_once_or_current(
        source,
        "Mp(`/api/grc/policies`,{...x,content:x.content||`# ${x.title}\\n\\n`})",
        "Mp(`/api/grc/policies`,{...x,content:x.content||`# ${x.title}\\n\\n`,unmapped:!0})",
        "GRC explicit unmapped policy state",
    )
    source = replace_once_or_current(
        source,
        "[y,b]=(0,v.useState)(!1),[x,S]=(0,v.useState)({title:``,category:`Custom`,owner:`CSRO`,review_cycle:`Annual`,content:``}),[C,w]",
        "[y,b]=(0,v.useState)(!1),[x,S]=(0,v.useState)({title:``,category:`Custom`,owner:`CSRO`,review_cycle:`Annual`,content:``,framework_id:null,control_ids:[],unmapped:!0}),[policyQuery,setPolicyQuery]=(0,v.useState)(``),[policyFramework,setPolicyFramework]=(0,v.useState)(``),[policyControl,setPolicyControl]=(0,v.useState)(``),[policySource,setPolicySource]=(0,v.useState)(``),[policyLifecycle,setPolicyLifecycle]=(0,v.useState)(`active`),[policyPage,setPolicyPage]=(0,v.useState)(1),[policyMeta,setPolicyMeta]=(0,v.useState)({total:0,page:1,page_size:25}),[C,w]",
        "GRC policy filter state",
    )
    source = replace_once_or_current(
        source,
        "let ee=(0,v.useCallback)(()=>{$(`/api/grc/policies`).then(e=>{s(e.policies||[])}).catch(()=>{})},[])",
        "let ee=(0,v.useCallback)(()=>{let e=new URLSearchParams;policyQuery&&e.set(`q`,policyQuery),policyFramework&&e.set(`framework_id`,policyFramework),policyControl&&e.set(`control_id`,policyControl),policySource&&e.set(`source`,policySource),policyLifecycle&&e.set(`lifecycle`,policyLifecycle),e.set(`page`,String(policyPage)),e.set(`page_size`,`25`),$(`/api/grc/policies?${e.toString()}`).then(e=>{s(e.policies||[]),setPolicyMeta({total:e.total||0,page:e.page||1,page_size:e.page_size||25})}).catch(()=>{})},[policyQuery,policyFramework,policyControl,policySource,policyLifecycle,policyPage])",
        "GRC policy filters request",
    )
    source = replace_once_or_current(
        source,
        "S({title:``,category:`Custom`,owner:`CSRO`,review_cycle:`Annual`,content:``}),ee(),te(e.id)",
        "S({title:``,category:`Custom`,owner:`CSRO`,review_cycle:`Annual`,content:``,framework_id:null,control_ids:[],unmapped:!0}),ee(),te(e.id)",
        "GRC policy form reset",
    )
    source = replace_once_or_current(
        source,
        "(0,Y.jsx)(`div`,{className:`flex justify-end mb-4`,children:(0,Y.jsxs)(`button`,{onClick:()=>b(!y),className:`text-[11px] font-mono text-primary-400 bg-primary-500/10 border border-primary-500/20 px-3 py-1.5 rounded-lg hover:bg-primary-500/20 transition-colors flex items-center gap-1.5`,children:[(0,Y.jsx)(Nr,{className:`w-3.5 h-3.5`}),` New Policy`]})})",
        "(0,Y.jsxs)(`div`,{className:`flex flex-wrap items-end justify-between gap-3 mb-4`,children:[(0,Y.jsxs)(`div`,{className:`flex flex-wrap gap-2 flex-1`,children:[(0,Y.jsx)(`input`,{value:policyQuery,onChange:e=>{setPolicyPage(1),setPolicyQuery(e.target.value)},placeholder:`Search policy title`,className:`min-w-44 bg-surface border border-border rounded-lg px-3 py-2 text-xs outline-none focus:border-primary-500/50`}),(0,Y.jsxs)(`select`,{value:policyFramework,onChange:e=>{setPolicyPage(1),setPolicyFramework(e.target.value)},className:`bg-surface border border-border rounded-lg px-3 py-2 text-xs`,children:[(0,Y.jsx)(`option`,{value:``,children:`All frameworks`}),(0,Y.jsx)(`option`,{value:`iso-iec-42001-2023`,children:`ISO/IEC 42001:2023`})]}),(0,Y.jsxs)(`select`,{value:policyControl,onChange:e=>{setPolicyPage(1),setPolicyControl(e.target.value)},className:`bg-surface border border-border rounded-lg px-3 py-2 text-xs`,children:[(0,Y.jsx)(`option`,{value:``,children:`All linked controls`}),...nm.map(e=>(0,Y.jsx)(`option`,{value:e.id,children:e.id},e.id))]}),(0,Y.jsxs)(`select`,{value:policySource,onChange:e=>{setPolicyPage(1),setPolicySource(e.target.value)},className:`bg-surface border border-border rounded-lg px-3 py-2 text-xs`,children:[(0,Y.jsx)(`option`,{value:``,children:`Bundled and custom`}),(0,Y.jsx)(`option`,{value:`bundled`,children:`Bundled`}),(0,Y.jsx)(`option`,{value:`custom`,children:`Custom`})]}),(0,Y.jsxs)(`select`,{value:policyLifecycle,onChange:e=>{setPolicyPage(1),setPolicyLifecycle(e.target.value)},className:`bg-surface border border-border rounded-lg px-3 py-2 text-xs`,children:[(0,Y.jsx)(`option`,{value:`active`,children:`Active`}),(0,Y.jsx)(`option`,{value:`archived`,children:`Archived`}),(0,Y.jsx)(`option`,{value:``,children:`All lifecycle states`})]})]}),(0,Y.jsxs)(`div`,{className:`flex items-center gap-2`,children:[(0,Y.jsx)(`button`,{disabled:policyPage<=1,onClick:()=>setPolicyPage(e=>Math.max(1,e-1)),className:`text-xs text-text-muted disabled:opacity-40`,children:`‹ Prev`}),(0,Y.jsxs)(`span`,{className:`text-[10px] text-text-muted font-mono`,children:[policyMeta.total?`${policyPage} / ${Math.ceil(policyMeta.total/25)}`:`0 / 0`]}),(0,Y.jsx)(`button`,{disabled:policyPage>=Math.ceil(policyMeta.total/25),onClick:()=>setPolicyPage(e=>e+1),className:`text-xs text-text-muted disabled:opacity-40`,children:`Next ›`}),(0,Y.jsxs)(`button`,{onClick:()=>b(!y),className:`text-[11px] font-mono text-primary-400 bg-primary-500/10 border border-primary-500/20 px-3 py-1.5 rounded-lg hover:bg-primary-500/20 transition-colors flex items-center gap-1.5`,children:[(0,Y.jsx)(Nr,{className:`w-3.5 h-3.5`}),` New Policy`]})]})]})",
        "GRC policy library filters and pagination",
    )
    source = replace_once_or_current(
        source,
        "(0,Y.jsx)(`textarea`,{value:x.content,onChange:e=>S(t=>({...t,content:e.target.value})),placeholder:`# Policy title\n\nWrite the policy in Markdown...`,className:`w-full min-h-40 bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500/50 resize-y`}),(0,Y.jsxs)(`div`,{className:`flex justify-end gap-2`",
        "(0,Y.jsx)(`textarea`,{value:x.content,onChange:e=>S(t=>({...t,content:e.target.value})),placeholder:`# Policy title\n\nWrite the policy in Markdown...`,className:`w-full min-h-40 bg-surface border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-primary-500/50 resize-y`}),(0,Y.jsxs)(`div`,{className:`grid grid-cols-1 md:grid-cols-2 gap-3`,children:[(0,Y.jsxs)(`div`,{children:[(0,Y.jsx)(`label`,{className:`block text-[10px] text-text-muted font-mono uppercase tracking-wide mb-1`,children:`Controls supported (ISO/IEC 42001:2023)`}),(0,Y.jsx)(`select`,{multiple:!0,disabled:x.unmapped,value:x.control_ids,onChange:e=>S(t=>({...t,framework_id:`iso-iec-42001-2023`,control_ids:Array.from(e.target.selectedOptions,e=>e.value),unmapped:!1})),className:`w-full min-h-28 bg-surface border border-border rounded-lg px-3 py-2 text-xs disabled:opacity-40`,children:nm.map(e=>(0,Y.jsxs)(`option`,{value:e.id,children:[e.id,` · `,e.title]},e.id))})]}),(0,Y.jsxs)(`label`,{className:`flex items-center gap-2 self-end text-xs text-text-muted`,children:[(0,Y.jsx)(`input`,{type:`checkbox`,checked:x.unmapped,onChange:e=>S(t=>({...t,unmapped:e.target.checked,framework_id:e.target.checked?null:`iso-iec-42001-2023`,control_ids:e.target.checked?[]:t.control_ids})),className:`accent-primary-500`}),`Supporting document only — no controls linked; no scoring effect`]})]}),(0,Y.jsxs)(`div`,{className:`flex justify-end gap-2`",
        "GRC policy explicit control mapping form",
    )
    source = replace_once_or_current(
        source,
        "(0,Y.jsxs)(`div`,{className:`flex items-center gap-2 mt-2`,children:[e.available?",
        "(0,Y.jsx)(`div`,{className:`mt-2 text-[10px] text-text-muted font-mono`,children:[`Framework: `,e.framework_id?`ISO/IEC 42001:2023`:`None`,` · Linked controls: `,(e.linked_controls||[]).map(t=>t.control_id).join(`, `)||`None`,` · Scoring effect: None directly — supporting evidence only`]}),(0,Y.jsxs)(`div`,{className:`flex items-center gap-2 mt-2`,children:[e.available?",
        "GRC policy card mapping disclosure",
    )
    # The committed native bundle already includes the SPECTRUM evidence panel.
    # Do not match a later generic layout container and add it a second time.
    if "Linked assets and evidence" in source:
        source = source.replace("Decision Recorded", "Current decision — revise if new evidence is recorded")
        return source.replace("✓ Mitigated", "✓ Mitigation planned")

    source = replace_once_or_current(
        source,
        "(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "(0,Y.jsxs)(`section`,{className:`px-6 pb-2`,children:[(0,Y.jsx)(`h3`,{className:`text-sm font-semibold uppercase tracking-wider text-text-muted mb-3`,children:`Linked assets and evidence`}),(n.assets||[]).length?(0,Y.jsx)(`div`,{className:`space-y-2`,children:n.assets.map(e=>(0,Y.jsxs)(`div`,{className:`text-sm border border-border rounded-lg p-3`,children:[(0,Y.jsx)(`strong`,{children:e.name||e.hostname||e.asset_id}),(0,Y.jsx)(`p`,{className:`text-text-muted text-xs mt-1`,children:e.evidence||`No assignment note recorded.`})]},e.asset_id))}):(0,Y.jsx)(`p`,{className:`text-sm text-text-muted`,children:`No confirmed customer asset is linked.`}),(n.evidence_files||[]).length?(0,Y.jsxs)(`div`,{className:`mt-3 text-xs text-text-muted`,children:[`Attached evidence: `,n.evidence_files.map(e=>e.filename).join(`, `)]}):null]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "SPECTRUM linked assets and evidence",
    )
    source = replace_once_or_current(
        source,
        "n.evidence_files.map(e=>e.filename).join(`, `)]}):null]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "n.evidence_files.map(e=>e.filename).join(`, `)]}):null,(0,Y.jsx)(`a`,{href:`/sss-intake?finding=${encodeURIComponent(n.id)}`,className:`inline-flex mt-3 text-sm text-primary-400 hover:underline`,children:`Edit linked assets & evidence`})]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "SPECTRUM evidence editor link",
    )
    """
    source = replace_once_or_current(
        source,
        "n.evidence_files.map(e=>e.filename).join(`, `)]}):null,(0,Y.jsx)(`a`,{href:`/sss-intake?finding=${encodeURIComponent(n.id)}`,className:`inline-flex mt-3 text-sm text-primary-400 hover:underline`,children:`Edit linked assets & evidence`})]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "n.evidence_files.map(e=>e.filename).join(`, `)]}):null,(0,Y.jsx)(`a`,{href:`/sss-intake?finding=${encodeURIComponent(n.id)}`,className:`inline-flex mt-3 text-sm text-primary-400 hover:underline`,children:`Edit linked assets & evidence`}),(0,Y.jsxs)(`div`,{className:`mt-3 text-xs text-text-muted`,children:[`Business impact: `,n.business_impact?.assessed?`Analyst assessed (${n.business_impact.value}/10)`:`Unassessed — neutral server context`,(0,Y.jsx)(`button`,{onClick:async()=>{let e=window.prompt(`Business impact (0–10)`,String(n.business_impact?.value??5));if(e===null)return;let t=window.prompt(`Justification (minimum 10 characters)`);if(!t||t.trim().length<10)return alert(`A justification of at least 10 characters is required.`);let r=await fetch(`/api/spectrum/findings/${n.id}/business-impact`,{method:`PATCH`,headers:{"Content-Type":`application/json`,Authorization:`Bearer ${localStorage.getItem(`tempris_token`)||``}`},body:JSON.stringify({value:Number(e),justification:t.trim()})});if(!r.ok)return alert(`Business impact was not saved.`);window.location.reload()},className:`ml-3 text-primary-400 hover:underline`,children:`Assess / update`})]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[",
        "SPECTRUM business impact action",
    )
    source = source.replace("Decision Recorded", "Current decision — revise if new evidence is recorded")
    return source.replace("✓ Mitigated", "✓ Mitigation planned")

    """
    source = source.replace("Decision Recorded", "Current decision — revise if new evidence is recorded")
    return source.replace("✓ Mitigated", "✓ Mitigation planned")


_canonical_bundle_base_patch = patch_canonical_bundle


def patch_canonical_bundle(source: str) -> str:
    """Add the current SPECTRUM business-impact control after base patches."""
    source = _canonical_bundle_base_patch(source)
    return replace_once_or_current(
        source,
        '''n.evidence_files.map(e=>e.filename).join(`, `)]}):null,(0,Y.jsx)(`a`,{href:`/sss-intake?finding=${encodeURIComponent(n.id)}`,className:`inline-flex mt-3 text-sm text-primary-400 hover:underline`,children:`Edit linked assets & evidence`})]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[''',
        '''n.evidence_files.map(e=>e.filename).join(`, `)]}):null,(0,Y.jsx)(`a`,{href:`/sss-intake?finding=${encodeURIComponent(n.id)}`,className:`inline-flex mt-3 text-sm text-primary-400 hover:underline`,children:`Edit linked assets & evidence`}),(0,Y.jsxs)(`div`,{className:`mt-3 text-xs text-text-muted`,children:[`Business impact: `,n.business_impact?.assessed?`Analyst assessed (${n.business_impact.value}/10)`:`Unassessed - neutral server context`,(0,Y.jsx)(`button`,{onClick:async()=>{let e=window.prompt(`Business impact (0-10)`,String(n.business_impact?.value??5));if(e===null)return;let t=window.prompt(`Justification (minimum 10 characters)`);if(!t||t.trim().length<10)return alert(`A justification of at least 10 characters is required.`);let r=await fetch(`/api/spectrum/findings/${n.id}/business-impact`,{method:`PATCH`,headers:{"Content-Type":`application/json`,Authorization:`Bearer ${localStorage.getItem(`tempris_token`)||``}`},body:JSON.stringify({value:Number(e),justification:t.trim()})});if(!r.ok)return alert(`Business impact was not saved.`);window.location.reload()},className:`ml-3 text-primary-400 hover:underline`,children:`Assess / update`})]}),(0,Y.jsxs)(`div`,{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:[''',
        "SPECTRUM business impact action",
    )


def patch_canonical_bundle(source: str) -> str:
    """Build a native SPECTRUM business-impact action without an overlay."""
    source = _canonical_bundle_base_patch(source)
    old = (
        "n.evidence_files.map(e=>e.filename).join(`, `)]}):null,"
        "(0,Y.jsx)(`a`,{href:`/sss-intake?finding=${encodeURIComponent(n.id)}`,"
        "className:`inline-flex mt-3 text-sm text-primary-400 hover:underline`,"
        "children:`Edit linked assets & evidence`})]}),(0,Y.jsxs)(`div`,"
        "{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:["
    )
    new = (
        "n.evidence_files.map(e=>e.filename).join(`, `)]}):null,"
        "(0,Y.jsx)(`a`,{href:`/sss-intake?finding=${encodeURIComponent(n.id)}`,"
        "className:`inline-flex mt-3 text-sm text-primary-400 hover:underline`,"
        "children:`Edit linked assets & evidence`}),(0,Y.jsx)(`button`,{"
        "onClick:async()=>{let e=window.prompt(`Business impact (0-10)`,"
        "String(n.business_impact?.value??5));if(e===null)return;let t=window.prompt("
        "`Justification (minimum 10 characters)`);if(!t||t.trim().length<10)return "
        "alert(`A justification of at least 10 characters is required.`);let r=await "
        "jp(`/api/spectrum/findings/${n.id}/business-impact`,{method:`PATCH`,body:"
        "JSON.stringify({value:Number(e),justification:t.trim()})});if(!r.ok)return "
        "alert(`Business impact was not saved.`);window.location.reload()},"
        "className:`inline-flex mt-3 ml-3 text-sm text-primary-400 hover:underline`,"
        "children:n.business_impact?.assessed?`Update business impact (${n.business_impact.value}/10)`"
        ":`Assess business impact`})]}),(0,Y.jsxs)(`div`,"
        "{className:`p-6 grid grid-cols-1 md:grid-cols-2 gap-8`,children:["
    )
    return replace_once_or_current(source, old, new, "SPECTRUM business impact action")


def main() -> None:
    if len(sys.argv) not in {2, 4} or (len(sys.argv) == 4 and sys.argv[2] != "--git-ref"):
        raise SystemExit("usage: patch_native_frontend.py <bundle.js> [--git-ref <revision>]")
    path = Path(sys.argv[1])
    if len(sys.argv) == 4:
        ref = f"{sys.argv[3]}:{path.as_posix()}"
        original = subprocess.run(
            ["git", "show", ref], check=True, capture_output=True
        ).stdout.decode("utf-8")
    else:
        original = path.read_text(encoding="utf-8")
    updated = patch_canonical_bundle(original) if "scope=confirmed_exposure" in original else patch(original)
    path.write_text(updated, encoding="utf-8", newline="")
    print(f"patched {path} ({len(original)} -> {len(updated)} bytes)")


if __name__ == "__main__":
    main()
