"""Local read-only migration assessment. No remote scanning or telemetry."""
import argparse, csv, datetime as dt, html, ipaddress, json, math, os
import platform, queue, shutil, socket, statistics, subprocess, threading, time
from pathlib import Path
import psutil

GIB=1024**3

def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def command(args, timeout=30):
    try:
        p=subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                         creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0) if os.name=='nt' else 0)
        return {'status':'discovered' if p.returncode==0 else 'unavailable',
                'output':p.stdout.strip(), 'error':p.stderr.strip(), 'returncode':p.returncode}
    except Exception as e: return {'status':'unavailable','error':str(e)}

def powershell(script):
    r=command(['powershell.exe','-NoProfile','-NonInteractive','-Command',
               "$ErrorActionPreference='Stop'; "+script+' | ConvertTo-Json -Depth 5 -Compress'])
    if r['status']=='discovered':
        try: r['data']=json.loads(r['output']) if r['output'] else []
        except ValueError: r['status']='unavailable'; r['error']='Invalid JSON returned'
    r.pop('output',None)
    return r

def scope(address):
    try:
        a=ipaddress.ip_address(address.split('%')[0])
        if a.is_loopback: return 'loopback'
        if a.is_link_local: return 'link-local'
        if a.is_global: return 'public address (internet path unverified)'
        return 'non-global address (private path unverified)'
    except ValueError: return 'unclassified'

def connections():
    rows=[]; warnings=[]
    try:
        for c in psutil.net_connections(kind='inet'):
            def addr(a): return {'ip':a.ip,'port':a.port} if a else None
            name=None
            if c.pid:
                try: name=psutil.Process(c.pid).name()
                except (psutil.Error,OSError): pass
            rows.append({'protocol':'TCP' if c.type==socket.SOCK_STREAM else 'UDP',
                'local':addr(c.laddr),'remote':addr(c.raddr),'status':c.status,
                'pid':c.pid,'process':name,
                'remote_scope':scope(c.raddr.ip) if c.raddr else 'not applicable',
                'evidence':'observed','direction':'listener' if c.status=='LISTEN' else 'not established by socket snapshot'})
    except (psutil.Error,OSError) as e: warnings.append('Connection collection unavailable: '+str(e))
    return rows,warnings

def inventory():
    warnings=[]; vm=psutil.virtual_memory()
    result={'evidence':'discovered','collected_utc':now(),'hostname':socket.gethostname(),
        'os':platform.platform(),'architecture':platform.machine(),
        'cpu_model':platform.processor() or 'unknown',
        'physical_cores':psutil.cpu_count(logical=False),'logical_processors':psutil.cpu_count(),
        'ram_gib':round(vm.total/GIB,3),'swap_gib':round(psutil.swap_memory().total/GIB,3),
        'boot_utc':dt.datetime.fromtimestamp(psutil.boot_time(),dt.timezone.utc).isoformat(),
        'hardware_details':{},'disks':[],'interfaces':{},'processes':[], 'platform_discovery':{}}
    for p in psutil.disk_partitions(all=True):
        row={'device':p.device,'mountpoint':p.mountpoint,'filesystem':p.fstype,'options':p.opts}
        row['network_storage_candidate']=p.fstype.lower() in ('nfs','nfs4','cifs','smbfs') or p.device.startswith('\\\\')
        try:
            u=psutil.disk_usage(p.mountpoint)
            row.update(total_gib=round(u.total/GIB,3),used_gib=round(u.used/GIB,3),free_gib=round(u.free/GIB,3))
        except (OSError,psutil.Error) as e: row['collection_error']=str(e)
        result['disks'].append(row)
    stats=psutil.net_if_stats()
    for name, addresses in psutil.net_if_addrs().items():
        s=stats.get(name)
        result['interfaces'][name]={'addresses':[{'family':str(a.family),'address':a.address,'netmask':a.netmask} for a in addresses],
            'up':s.isup if s else None,'link_speed_mbps':s.speed if s else None,'mtu':s.mtu if s else None}
    for p in psutil.process_iter(['pid','name']):
        try: result['processes'].append(p.info)
        except psutil.Error: pass
    result['connections'],w=connections(); warnings.extend(w)
    if os.name=='nt':
        scripts={
          'hardware':"Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,NumberOfProcessors,HypervisorPresent",
          'cpu':"Get-CimInstance Win32_Processor | Select-Object Name,SocketDesignation,NumberOfCores,NumberOfLogicalProcessors",
          'mapped_shares':"Get-SmbMapping | Select-Object LocalPath,RemotePath,Status",
          'global_mapped_shares':"Get-SmbGlobalMapping | Select-Object LocalPath,RemotePath,Status",
          'hosted_shares':"Get-SmbShare | Select-Object Name,Path,Description",
          'smb_connections':"Get-SmbConnection | Select-Object ServerName,ShareName,Dialect,NumOpens",
          'services':"Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode",
          'scheduled_tasks':"Get-ScheduledTask | Select-Object TaskName,TaskPath,State",
          'dns':"Get-DnsClientServerAddress | Select-Object InterfaceAlias,AddressFamily,ServerAddresses",
          'routes':"Get-NetRoute | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric",
          'firewall_rules':"Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Action,Profile",
          'installed_apps':"Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher"
        }
        for label,script in scripts.items():
            r=powershell(script); result['platform_discovery'][label]=r
            if r['status']=='unavailable': warnings.append(label+': '+r.get('error','unavailable'))
    else:
        cmds={'cpu':['lscpu'],'hardware':['systemd-detect-virt'],
              'services':['systemctl','list-units','--type=service','--all','--no-pager'],
              'routes':['ip','route','show'],'ipv6_routes':['ip','-6','route','show'],
              'scheduled_tasks':['systemctl','list-timers','--all','--no-pager'],
              'user_crontab':['crontab','-l'],'hosted_nfs_exports':['exportfs','-v'],
              'hosted_smb_config':['testparm','-s'],'firewall_rules':['nft','list','ruleset']}
        if shutil.which('dpkg-query'): cmds['installed_apps']=['dpkg-query','-W','-f=${Package} ${Version}\n']
        elif shutil.which('rpm'): cmds['installed_apps']=['rpm','-qa']
        for label,args in cmds.items():
            r=command(args); result['platform_discovery'][label]=r
            if r['status']=='unavailable': warnings.append(label+': '+r.get('error','unavailable'))
        for label,path in [('dns','/etc/resolv.conf'),('mounts','/proc/mounts')]:
            try: result['platform_discovery'][label]={'status':'discovered','output':Path(path).read_text()}
            except OSError as e: warnings.append(label+': '+str(e))
    if shutil.which('docker'):
        result['platform_discovery']['containers']=command(['docker','ps','-a','--format','{{json .}}'])
    else: result['platform_discovery']['containers']={'status':'unavailable','error':'Docker CLI not found; container absence not verified'}
    result['warnings']=warnings
    return result

def counters():
    return {'time':time.monotonic(),'net':psutil.net_io_counters(pernic=True),
            'disk':psutil.disk_io_counters(perdisk=True) or {}}

def sample(previous):
    current=counters(); elapsed=current['time']-previous['time']; mem=psutil.virtual_memory()
    row={'timestamp_utc':now(),'interval_seconds':elapsed,'cpu_percent':psutil.cpu_percent(None),
         'memory_percent':mem.percent,'memory_used_gib':(mem.total-mem.available)/GIB,
         'swap_percent':psutil.swap_memory().percent,'interfaces':{},'disks':{},'counter_resets':[]}
    def delta(new,old,field,label):
        v=getattr(new,field)-getattr(old,field)
        if v<0: row['counter_resets'].append(label+':'+field); return None
        return v
    for name,n in current['net'].items():
        old=previous['net'].get(name)
        if old is None: continue
        rx=delta(n,old,'bytes_recv',name); tx=delta(n,old,'bytes_sent',name)
        row['interfaces'][name]={'rx_bytes':rx,'tx_bytes':tx,
             'rx_mbps':rx*8/elapsed/1e6 if rx is not None else None,
             'tx_mbps':tx*8/elapsed/1e6 if tx is not None else None}
    for name,n in current['disk'].items():
        old=previous['disk'].get(name)
        if old is None: continue
        d={k:delta(n,old,k,name) for k in ('read_count','write_count','read_bytes','write_bytes')}
        def rate(k): return d[k]/elapsed if d[k] is not None else None
        row['disks'][name]={'read_iops':rate('read_count'),'write_iops':rate('write_count'),
            'read_mib_s':rate('read_bytes')/1024**2 if rate('read_bytes') is not None else None,
            'write_mib_s':rate('write_bytes')/1024**2 if rate('write_bytes') is not None else None}
        for kind in ('read','write'):
            field=kind+'_time'; count=d[kind+'_count']
            if hasattr(n,field):
                ms=delta(n,old,field,name)
                row['disks'][name][kind+'_mean_service_ms']=ms/count if ms is not None and count else None
    return row,current

def summary(values):
    values=sorted(v for v in values if v is not None)
    if not values: return None
    return {'average':statistics.mean(values),'peak':values[-1],
            'p95':values[max(0,math.ceil(len(values)*.95)-1)]}

def assessment(inv,samples,headroom=30):
    out={'evidence':'inferred','sample_count':len(samples),'observed_seconds':sum(s['interval_seconds'] for s in samples),
         'headroom_percent':headroom,'confidence':'not validated; representative business-cycle coverage must be confirmed',
         'like_for_like':{'logical_processors_not_equivalent_vcpus':inv['logical_processors'],'ram_gib':inv['ram_gib']},
         'cpu_percent':summary([s['cpu_percent'] for s in samples]),
         'memory_used_gib':summary([s['memory_used_gib'] for s in samples]),'interfaces':{},'disks':{},
         'candidate_sizing':None,
         'limitations':['No cloud SKU, pricing, licensing, OS support or provider-side network validation.',
          'Logical processors are not equivalent to destination vCPUs; CPU sizing is a heuristic, not a benchmark.',
          'Interface traffic includes internal and external traffic. No internet-only bytes or per-process byte attribution.',
          'Socket snapshots can miss short-lived connections; direction is not inferred from ephemeral ports.',
          'Disk counters may include stacked devices; do not sum them or partition capacities blindly.',
          'SMB mappings are session-sensitive. Re-run in relevant user contexts; do not assume no shares exist.',
          'No packet capture, file-content collection, password collection, active remote scan, or cloud API access.',
          'No application-config parsing or comprehensive database, remote-resource, or multi-server discovery.',
          'Firewall inventory is not a complete port-rule assessment. Review associated filters manually.',
          'Memory estimate uses total minus available; application/cache requirements need validation.']}
    if samples:
        factor=1+headroom/100
        out['candidate_sizing']={'provisional_vcpu_heuristic':max(2,math.ceil((inv['logical_processors'] or 1)*out['cpu_percent']['p95']/100*factor)),
          'provisional_ram_gib':max(2,math.ceil(out['memory_used_gib']['p95']*factor)),
          'formula':'nearest-rank p95; CPU = logical processors * p95 CPU fraction * headroom factor; RAM = p95 used GiB * factor',
          'approval':'Requires workload owner review, benchmark and destination validation before provisioning'}
    for name in sorted({n for s in samples for n in s['interfaces']}):
        rows=[s['interfaces'][name] for s in samples if name in s['interfaces']]
        out['interfaces'][name]={'rx_mbps':summary([r['rx_mbps'] for r in rows]),'tx_mbps':summary([r['tx_mbps'] for r in rows]),
            'observed_rx_gib':sum(r['rx_bytes'] or 0 for r in rows)/GIB,'observed_tx_gib':sum(r['tx_bytes'] or 0 for r in rows)/GIB,
            'internet_only':'not measured'}
    for name in sorted({n for s in samples for n in s['disks']}):
        rows=[s['disks'][name] for s in samples if name in s['disks']]
        out['disks'][name]={k:summary([r.get(k) for r in rows]) for k in ('read_iops','write_iops','read_mib_s','write_mib_s','read_mean_service_ms','write_mean_service_ms')}
    out['storage_candidates']=[{'device':d['device'],'mountpoint':d['mountpoint'],
        'used_gib':d.get('used_gib'),'capacity_with_headroom_gib':math.ceil(d['used_gib']*(1+headroom/100)) if 'used_gib' in d else None,
        'review':'Deduplicate devices; confirm growth, filesystem overhead and remote-storage treatment'} for d in inv['disks']]
    return out

class Session:
    def __init__(self,folder,headroom=30):
        self.folder=Path(folder); self.folder.mkdir(parents=True,exist_ok=True)
        self.headroom=headroom; self.inv=None; self.samples=[]; self.deps={}; self.stop=threading.Event()
    def add_connections(self):
        rows,w=connections()
        if self.inv: self.inv['warnings'].extend(x for x in w if x not in self.inv['warnings'])
        for r in rows:
            key=json.dumps(r,sort_keys=True)
            if key not in self.deps: self.deps[key]={'connection':r,'first_seen_utc':now(),'last_seen_utc':now(),'observations':1}
            else: self.deps[key]['last_seen_utc']=now(); self.deps[key]['observations']+=1
    def run(self,seconds,interval,notify=lambda s:None):
        notify('Discovering local inventory...'); self.inv=inventory()
        for r in self.inv['connections']:
            self.deps[json.dumps(r,sort_keys=True)]={'connection':r,'first_seen_utc':now(),'last_seen_utc':now(),'observations':1}
        self.export(); psutil.cpu_percent(None); prev=counters(); start=time.monotonic()
        with (self.folder/'samples.jsonl').open('a',encoding='utf-8') as stream:
            while not self.stop.is_set() and time.monotonic()-start<seconds:
                remaining=seconds-(time.monotonic()-start)
                if self.stop.wait(min(interval,remaining)): break
                row,prev=sample(prev); self.samples.append(row)
                stream.write(json.dumps(row)+'\n'); stream.flush(); self.add_connections()
                notify('Monitoring: %d samples | CPU %.1f%% | memory %.1f%%' %(len(self.samples),row['cpu_percent'],row['memory_percent']))
        self.export(); notify('Finished. Reports saved to '+str(self.folder.resolve()))
    def export(self):
        report={'inventory':self.inv,'assessment':assessment(self.inv,self.samples,self.headroom),
                'dependencies':list(self.deps.values()),'sample_file':'samples.jsonl'}
        (self.folder/'assessment.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        with (self.folder/'metrics.csv').open('w',newline='',encoding='utf-8') as f:
            fields=['timestamp_utc','interval_seconds','cpu_percent','memory_percent','memory_used_gib','swap_percent']
            w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader(); w.writerows(self.samples)
        with (self.folder/'dependencies.csv').open('w',newline='',encoding='utf-8') as f:
            fields=['process','pid','protocol','local_ip','local_port','remote_ip','remote_port','status','remote_scope','first_seen_utc','last_seen_utc','observations']
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
            for d in self.deps.values():
                c=d['connection']; local=c['local'] or {}; remote=c['remote'] or {}
                w.writerow(dict(process=c['process'],pid=c['pid'],protocol=c['protocol'],local_ip=local.get('ip'),local_port=local.get('port'),remote_ip=remote.get('ip'),remote_port=remote.get('port'),status=c['status'],remote_scope=c['remote_scope'],first_seen_utc=d['first_seen_utc'],last_seen_utc=d['last_seen_utc'],observations=d['observations']))
        from report_renderer import render_report
        page=render_report(report)
        (self.folder/'report.html').write_text(page,encoding='utf-8')
        return report

def gui():
    import tkinter as tk
    from tkinter import ttk,messagebox,filedialog
    import webbrowser
    window=tk.Tk(); window.title('Cloud Migration Assessment | Local Edition'); window.geometry('1000x720')
    events=queue.Queue(); state={'session':None,'busy':False}
    ttk.Label(window,text='Cloud Migration Assessment',font=('Segoe UI',20,'bold')).pack(anchor='w',padx=20,pady=15)
    ttk.Label(window,text='Read-only local scan. No upload. No remote probing. Only assess systems you are authorized to inspect.').pack(anchor='w',padx=20)
    controls=ttk.Frame(window); controls.pack(fill='x',padx=20,pady=15)
    minutes=tk.StringVar(value='15'); interval=tk.StringVar(value='5'); headroom=tk.StringVar(value='30')
    for label,var in [('Minutes (0 = inventory only)',minutes),('Interval seconds',interval),('Headroom %',headroom)]:
        ttk.Label(controls,text=label).pack(side='left',padx=4); ttk.Entry(controls,textvariable=var,width=7).pack(side='left',padx=4)
    authorized=tk.BooleanVar(value=False)
    ttk.Checkbutton(window,text='I am authorized to assess this machine and store its infrastructure metadata.',variable=authorized).pack(anchor='w',padx=20)
    status=tk.StringVar(value='Ready. Run in the relevant user session for mapped drives. Permission failures will be reported.')
    ttk.Label(window,textvariable=status,wraplength=950).pack(anchor='w',padx=20,pady=10)
    buttons=ttk.Frame(window); buttons.pack(fill='x',padx=20)
    notebook=ttk.Notebook(window); notebook.pack(fill='both',expand=True,padx=20,pady=15)
    tabs={}
    for name in ['Summary','Inventory','Dependencies','Discovery','Warnings']:
        frame=ttk.Frame(notebook); notebook.add(frame,text=name)
        text=tk.Text(frame,wrap='word',font=('Consolas',10)); bar=ttk.Scrollbar(frame,command=text.yview)
        text.configure(yscrollcommand=bar.set); bar.pack(side='right',fill='y'); text.pack(fill='both',expand=True); tabs[name]=text
    def display(report):
        inv=report['inventory']; data={'Summary':report['assessment'],'Inventory':{k:v for k,v in inv.items() if k not in ('platform_discovery','warnings','connections')},'Dependencies':report['dependencies'],'Discovery':inv['platform_discovery'],'Warnings':inv['warnings']}
        for name,value in data.items(): tabs[name].delete('1.0','end'); tabs[name].insert('end',json.dumps(value,indent=2))
    def start():
        if state['busy']: return
        if not authorized.get(): messagebox.showwarning('Authorization required','Confirm authorization before scanning.'); return
        try:
            seconds=float(minutes.get())*60; step=float(interval.get()); margin=float(headroom.get())
            if not (0<=seconds<=30*86400 and 1<=step<=3600 and 0<=margin<=300): raise ValueError()
        except ValueError: messagebox.showerror('Invalid settings','Minutes: 0 to 43200. Interval: 1 to 3600. Headroom: 0 to 300.'); return
        base=filedialog.askdirectory(title='Choose a local report folder')
        if not base: return
        session=Session(Path(base)/('assessment_'+dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f')),margin)
        state.update(session=session,busy=True); startbutton.config(state='disabled')
        def worker():
            try: session.run(seconds,step,lambda s:events.put(('status',s))); events.put(('report',session.export()))
            except Exception as e: events.put(('error',str(e)))
            finally: events.put(('done',None))
        threading.Thread(target=worker,daemon=True).start()
    def stop():
        if state['session']: state['session'].stop.set(); status.set('Stopping and saving reports...')
    def open_report():
        if state['session'] and (state['session'].folder/'report.html').exists(): webbrowser.open((state['session'].folder/'report.html').resolve().as_uri())
    startbutton=ttk.Button(buttons,text='Start assessment',command=start); startbutton.pack(side='left',padx=4)
    ttk.Button(buttons,text='Stop and save',command=stop).pack(side='left',padx=4)
    ttk.Button(buttons,text='Open HTML report',command=open_report).pack(side='left',padx=4)
    def poll():
        try:
            while True:
                kind,value=events.get_nowait()
                if kind=='status': status.set(value)
                elif kind=='report': display(value)
                elif kind=='error': messagebox.showerror('Assessment error',value); status.set('Error: '+value)
                elif kind=='done': state['busy']=False; startbutton.config(state='normal')
        except queue.Empty: pass
        window.after(250,poll)
    def close():
        if state['busy']:
            stop(); messagebox.showinfo('Saving','Stop requested. Close the window after the Finished message to preserve reports.'); return
        window.destroy()
    window.protocol('WM_DELETE_WINDOW',close); poll(); window.mainloop()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cli',action='store_true'); p.add_argument('--authorized',action='store_true')
    p.add_argument('--seconds',type=float,default=60); p.add_argument('--interval',type=float,default=5)
    p.add_argument('--headroom',type=float,default=30); p.add_argument('--output',default=None)
    a=p.parse_args()
    if not a.cli: gui(); return
    if not a.authorized: p.error('Use --authorized only when you have permission to assess this machine.')
    if not (0<=a.seconds<=30*86400 and 1<=a.interval<=3600 and 0<=a.headroom<=300): p.error('Invalid duration, interval or headroom')
    folder=a.output or ('reports/assessment_'+dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    if Path(folder).exists() and any(Path(folder).iterdir()): p.error('Output folder must be empty to avoid mixing sessions')
    session=Session(folder,a.headroom)
    try: session.run(a.seconds,a.interval,print)
    except KeyboardInterrupt:
        if session.inv: session.export()
        print('Interrupted; collected reports saved.')
if __name__=='__main__': main()
