import argparse, html, json
from pathlib import Path
TITLES=['Server inventory','CPU and memory monitoring','Storage assessment','Inbound/outbound traffic monitoring','Ports and connection discovery','Shared drives and external storage','Application and service inventory','Dependency mapping','Cloud sizing recommendations','Readiness and reporting']
def e(v): return html.escape(str(v),quote=True)
def value(v):
    if v is None: return '<span class="muted">Not available</span>'
    if isinstance(v,float): return e(round(v,3))
    if isinstance(v,dict): return facts(v)
    if isinstance(v,list):
        if v and all(isinstance(x,dict) for x in v): return table(v)
        return '<ul>'+''.join('<li>'+value(x)+'</li>' for x in v)+'</ul>' if v else '<span class="muted">No records returned</span>'
    return e(v)
def table(rows):
    if not rows: return '<p class="muted">No records returned; absence is not verified.</p>'
    keys=list(dict.fromkeys(k for r in rows for k in r))
    return '<div class="scroll"><table><thead><tr>'+''.join('<th>'+e(k.replace('_',' ').title())+'</th>' for k in keys)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+value(r.get(k))+'</td>' for k in keys)+'</tr>' for r in rows)+'</tbody></table></div>'
def facts(d):
    return '<table class="facts"><tbody>'+''.join('<tr><th>'+e(k.replace('_',' ').title())+'</th><td>'+value(v)+'</td></tr>' for k,v in d.items())+'</tbody></table>'
def block(title,data): return '<h3>'+e(title)+'</h3>'+value(data)
def note(text): return '<p class="notice">'+e(text)+'</p>'
def render_report(report):
    i=report.get('inventory') or {}; a=report.get('assessment') or {}; p=i.get('platform_discovery') or {}; deps=report.get('dependencies') or []
    def select(keys): return {k:i.get(k) for k in keys}
    def discover(keys): return ''.join(block(k.replace('_',' ').title(),p.get(k,{'status':'Not collected on this platform or unavailable'})) for k in keys)
    bodies=[]
    bodies.append(facts(select(['hostname','collected_utc','os','architecture','cpu_model','physical_cores','logical_processors','ram_gib','swap_gib','boot_utc']))+discover(['hardware','cpu'])+note('Physical/virtual indicators require interpretation. Logical processors are not equivalent to cloud vCPUs.'))
    bodies.append(facts({k:a.get(k) for k in ['sample_count','observed_seconds','cpu_percent','memory_used_gib']})+note('Memory-percent and swap time series remain in metrics.csv and samples.jsonl. Memory pressure is not independently diagnosed.'))
    bodies.append(block('Volumes, capacity and filesystems',i.get('disks',[]))+block('Per-device IOPS, throughput and service-time estimates',a.get('disks',{}))+block('Provisional capacity with headroom',a.get('storage_candidates',[]))+note('Deduplicate mountpoints and stacked devices before totaling. Service time is not application end-to-end latency. No cloud storage tier is selected.'))
    bodies.append(block('Observed traffic per interface',a.get('interfaces',{}))+block('Interface configuration',i.get('interfaces',{}))+note('Rates are Mbps; totals are binary GiB, not decimal GB. Includes internal/VPN/internet traffic. Internet-only bytes are not measured. Do not sum virtual interfaces blindly.'))
    connections=i.get('connections',[])
    bodies.append(block('Listening sockets',[c for c in connections if c.get('status')=='LISTEN'])+block('Other observed sockets',[c for c in connections if c.get('status')!='LISTEN'])+discover(['firewall_rules'])+note('Socket observations are not approved firewall requirements. Connection direction and full firewall port filters are not established.'))
    bodies.append(discover(['mapped_shares','global_mapped_shares','hosted_shares','smb_connections'])+''.join(discover([k]) for k in ['mounts','hosted_nfs_exports','hosted_smb_config'] if k in p)+block('Network-storage candidates',[d for d in i.get('disks',[]) if d.get('network_storage_candidate')])+note('Mappings are user-session sensitive. Empty results do not prove no shared storage exists. Provider-side storage relationships need manual verification.'))
    bodies.append(discover(['installed_apps','services','scheduled_tasks','containers'])+('' if 'user_crontab' not in p else discover(['user_crontab']))+'<details><summary>Running processes</summary>'+value(i.get('processes',[]))+'</details>'+note('Database/web-server roles are not comprehensively classified or inspected. Application-specific dependencies may be missing.'))
    rows=[]
    for d in deps:
        c=d.get('connection') or {}; local=c.get('local') or {}; remote=c.get('remote') or {}
        rows.append({'local_host':i.get('hostname'),'process':c.get('process'),'pid':c.get('pid'),'local_ip':local.get('ip'),'local_port':local.get('port'),'remote_ip':remote.get('ip'),'remote_port':remote.get('port'),'protocol':c.get('protocol'),'status':c.get('status'),'first_seen_utc':d.get('first_seen_utc'),'last_seen_utc':d.get('last_seen_utc'),'observations':d.get('observations')})
    bodies.append(table(rows)+note('Tabular endpoint map only. Remote roles, connection direction and migration groups are not automatically verified. Short-lived connections can be missed; no multi-server aggregation is performed.'))
    bodies.append(block('Current allocation reference',a.get('like_for_like',{}))+block('Provisional right-sizing',a.get('candidate_sizing'))+facts({k:a.get(k) for k in ['headroom_percent','confidence']})+note('Current allocation is not validated like-for-like cloud sizing. No cloud SKU, pricing, CPU-equivalence benchmark or destination validation is performed. No samples means no utilization-based recommendation.'))
    checks=['Confirm representative peak, backup and batch-job coverage','Review destination OS support and application compatibility','Validate CPU performance, RAM, disk tier and storage growth','Confirm licensing and destination cloud requirements','Review inbound/outbound rules, DNS, routes and VPN/private connectivity','Confirm share access and unresolved application dependencies','Test backup restore, rollback and application acceptance','Protect reports and obtain workload-owner approval']
    bodies.append(block('Collection warnings / missing evidence',i.get('warnings',[]))+block('Scope and sizing assumptions',a.get('limitations',[]))+block('Migration review checklist',[{'review_item':x,'status':'Manual review required'} for x in checks])+discover(['dns','routes'])+note('No automated migration-readiness certification. Supporting files: assessment.json, metrics.csv, dependencies.csv and samples.jsonl. A separately converted JSON report may not have those files alongside it.'))
    descriptions=[('OS, architecture, processor topology and installed RAM.','Current-server specifications.'),('Observed CPU/memory utilization and monitoring coverage.','Evidence for choosing target CPU and RAM.'),('Capacity, used/free space, filesystems and disk activity.','Capacity and performance inputs for destination storage.'),('Received/sent rates, observed transfer totals and interface usage.','Bandwidth evidence and transfer-cost inputs.'),('Listening ports, endpoints, protocols and processes.','Connectivity inventory for migration review.'),('Consumed/hosted shares and network-storage evidence.','Storage dependencies to keep accessible.'),('Applications, services, processes, containers and scheduled tasks.','Workloads and supporting components to review.'),('Observed local process-to-remote-endpoint relationships.','Dependency list for manually planning migration groups.'),('Current allocation, measured demand and headroom.','Current-allocation reference and provisional right-sizing.'),('Missing evidence, limitations, assumptions and manual checks.','Organized report and migration review checklist.')]
    sections=''
    for n,(title,body,desc) in enumerate(zip(TITLES,bodies,descriptions),1):
        sections+='<section id="pillar-'+str(n)+'"><div class="eyebrow">PILLAR '+str(n)+'</div><h2>'+str(n)+'. '+e(title)+'</h2><p>'+e(desc[0])+'</p><p class="outcome"><strong>What you get:</strong> '+e(desc[1])+'</p>'+body+'</section>'
    nav='<nav>'+''.join('<a href="#pillar-'+str(n)+'">'+str(n)+'. '+e(t)+'</a>' for n,t in enumerate(TITLES,1))+'</nav>'
    css='body{font:15px/1.5 system-ui;margin:0;background:#edf3f8;color:#18304a}header,main{padding:24px;max-width:1300px;margin:auto}header{background:#12324f;color:white}section{background:white;padding:24px;margin:24px 0;border:1px solid #d6e2ec;border-radius:10px}h2{color:#174f79}h3{margin-top:25px}.eyebrow{font-size:12px;letter-spacing:2px;color:#52718a}.outcome{background:#eaf4fc;padding:12px}.notice{background:#fff4d8;padding:12px;border-left:4px solid #c89a33}.muted{color:#667b8b}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}th,td{border:1px solid #dce5ed;padding:9px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf3f8}.facts>tbody>tr>th{width:25%}nav{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}nav a{background:white;color:#174f79;padding:10px;text-decoration:none;border-radius:5px}summary{cursor:pointer;font-weight:bold}@media print{nav{display:none}body{background:white}section{break-before:page;border:0}.scroll{overflow:visible}table{font-size:10px}header{background:white;color:black}}'
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cloud Migration Assessment - 10 Pillars</title><style>'+css+'</style></head><body><header><h1>Cloud Migration Assessment</h1><p>10-pillar report | '+e(i.get('hostname','Unknown host'))+' | '+e(i.get('collected_utc','Time unavailable'))+'</p><p>Read-only evidence. Provisional sizing. Protect infrastructure identifiers in this report.</p></header><main>'+nav+sections+'</main></body></html>'
def main():
    parser=argparse.ArgumentParser(description='Convert existing assessment.json into a ten-pillar HTML report.')
    parser.add_argument('input'); parser.add_argument('--output'); args=parser.parse_args()
    source=Path(args.input); data=json.loads(source.read_text(encoding='utf-8'))
    if not isinstance(data,dict) or 'inventory' not in data or 'assessment' not in data: parser.error('Expected assessment.json from the assessment app.')
    dest=Path(args.output) if args.output else source.with_name('report_10_pillars.html')
    if dest.resolve()==source.resolve(): parser.error('Output cannot overwrite source JSON.')
    dest.write_text(render_report(data),encoding='utf-8'); print('Saved: '+str(dest.resolve()))
if __name__=='__main__': main()
