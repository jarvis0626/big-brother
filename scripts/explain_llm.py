"""Two-step optional provider use. First preview, then explicit approved hash."""
import argparse
import getpass
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.llm import ApprovedProvider, WindowsCredentials, approval_hash, evidence_preview, preview_bytes, validate_endpoint

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path)
    parser.add_argument('--preview',type=Path,default=Path('artifacts/llm-preview.json'))
    parser.add_argument('--endpoint',default='http://127.0.0.1:11434/api/generate')
    parser.add_argument('--model',default='')
    parser.add_argument('--send',action='store_true')
    parser.add_argument('--approve-sha256')
    parser.add_argument('--remote-opt-in',action='store_true')
    parser.add_argument('--store-key',action='store_true')
    parser.add_argument('--output',type=Path,default=Path('artifacts/llm-commentary.json'))
    args=parser.parse_args()
    validate_endpoint(args.endpoint,args.remote_opt_in)
    if args.store_key:
        WindowsCredentials.store(args.endpoint,getpass.getpass('Provider credential (stored only in Windows Credential Manager): '))
        print('Credential stored in Windows Credential Manager.'); return
    if not args.report or not args.report.is_file(): parser.error('--report must name an exported Big Brother JSON report')
    if args.report.stat().st_size>16*1024*1024: parser.error('Report exceeds the 16 MiB preview input limit')
    report=json.loads(args.report.read_text(encoding='utf-8'))
    packet=evidence_preview(report); digest=approval_hash(packet)
    args.preview.parent.mkdir(parents=True,exist_ok=True); args.preview.write_bytes(preview_bytes(packet))
    print(f'Redacted preview: {args.preview}\nSHA256: {digest}')
    if not args.send:
        print('No data sent. Review the entire preview. Redaction can miss secrets and personal information.'); return
    if args.approve_sha256!=digest: parser.error('--send requires --approve-sha256 matching the reviewed preview')
    result=ApprovedProvider(args.endpoint,args.model,args.remote_opt_in).summarize(packet,args.approve_sha256)
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(f'Supplemental commentary saved: {args.output}')

if __name__=='__main__': main()
