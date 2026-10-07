"""Measure actual private backend overhead, with harmless loopback workload only."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import psutil

ROOT=Path(__file__).resolve().parents[1]
WORKLOAD=r'''
import http.server,threading,time,urllib.request,tempfile,pathlib,subprocess,sys
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'harmless-local-test')
 def log_message(self,*args):pass
server=http.server.HTTPServer(('127.0.0.1',0),H)
threading.Thread(target=server.serve_forever,daemon=True).start()
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(6)'])
try:
 with tempfile.TemporaryDirectory(prefix='big-brother-benign-') as directory:
  for i in range(24):
   pathlib.Path(directory,f'example-{i}.txt').write_text('harmless temporary file')
   with urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/') as r:r.read(100)
   time.sleep(.25)
finally:
 server.shutdown();child.wait(timeout=5)
'''

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=ROOT/'artifacts'/'performance.json');args=parser.parse_args()
    env={**os.environ,'PYTHONIOENCODING':'utf-8','PYTHONUNBUFFERED':'1','TEMP':str(ROOT/'.cache'/'temp'),'TMP':str(ROOT/'.cache'/'temp')}
    Path(env['TEMP']).mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='benchmark-',dir=ROOT/'.cache') as data:
        service=subprocess.Popen([sys.executable,'-u','-m','backend.service','--resources',str(ROOT/'resources'),'--data-dir',data],cwd=ROOT,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding='utf-8',creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        process=psutil.Process(service.pid);request_id=0
        def rpc(method,params=None):
            nonlocal request_id
            request_id+=1;service.stdin.write(json.dumps({'id':request_id,'method':method,'params':params or {}})+'\n');service.stdin.flush()
            result=json.loads(service.stdout.readline())
            if result.get('error'):raise RuntimeError(result['error'])
            return result['result']
        def measure(name,seconds,action=None):
            processes={p.pid:p for p in [process,*process.children(recursive=True)]}
            for p in processes.values(): p.cpu_percent()
            cpu=[];rss=[];started=time.perf_counter();actions=0
            while time.perf_counter()-started<seconds:
                if action:action();actions+=1
                time.sleep(.25)
                for p in process.children(recursive=True):
                    if p.pid not in processes: processes[p.pid]=p; p.cpu_percent()
                current_cpu=0;current_rss=0
                for p in list(processes.values()):
                    try: current_cpu+=p.cpu_percent();current_rss+=p.memory_info().rss
                    except psutil.Error: processes.pop(p.pid,None)
                cpu.append(current_cpu);rss.append(current_rss)
            elapsed=time.perf_counter()-started
            return {'workload':name,'seconds':elapsed,'backend_cpu_percent_mean_one_core':statistics.mean(cpu),'backend_cpu_percent_peak_one_core':max(cpu),'backend_rss_mib_mean':statistics.mean(rss)/1024**2,'backend_rss_mib_peak':max(rss)/1024**2,'actions':actions}
        workload=None
        try:
            state=rpc('state');results={'platform':platform.platform(),'cpu':platform.processor(),'logical_cpus':psutil.cpu_count(),'ram_gib':psutil.virtual_memory().total/1024**3,'python':sys.version,'measured_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'model':state['model'],'notes':['CPU100% = one logical core. Backend plus Windows Python launcher children; excludes Electron renderer.','Polling backend; Sysmon service overhead not measured.','Short engineering smoke workload, not a broad personal-computer benchmark.'],'measurements':[]}
            results['measurements'].append(measure('idle: no selected session',5))
            workload=subprocess.Popen([sys.executable,'-c',WORKLOAD],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            rpc('watch',{'pid':workload.pid});results['measurements'].append(measure('normal: selected benign temporary files, child, loopback HTTP',7))
            workload.wait(timeout=5);workload=None;rpc('stop')
            results['measurements'].append(measure('replay: one13-event investigation session per250ms',5,lambda:rpc('replay',{'scenario':'investigation'})))
            final=rpc('state');results['last_replay']={'events':len(final['events']),'processes':len(final['processes']),'incidents':len(final['incidents'])}
            args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(results,indent=2),encoding='utf-8');print(json.dumps(results,indent=2))
        finally:
            if workload:workload.wait(timeout=12)
            try:rpc('shutdown')
            except Exception:pass
            service.wait(timeout=10)

if __name__=='__main__':main()
