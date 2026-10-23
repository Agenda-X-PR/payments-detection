import hashlib, json, os, time, uuid
from datetime import datetime, timezone
from pathlib import Path
import psycopg, yaml
from psycopg.rows import dict_row

DB=os.getenv('DATABASE_URL','postgresql://app:dev@localhost/payments')
RULES=Path(os.getenv('RULES_DIR','/rules'))
POLL=float(os.getenv('POLL_INTERVAL','2'))

def db(): return psycopg.connect(DB,row_factory=dict_row)
def load_rules():
    rules={}
    for path in sorted(RULES.glob('*.yml')):
        rule=yaml.safe_load(path.read_text()); rules[rule['id']]=rule
    return rules

def insert_alert(cur, rule, rows, context, fingerprint):
    if not rows: return False
    ids=[r['id'] for r in rows]
    cur.execute('''INSERT INTO alerts(rule_id,severity,event_ids,context,fingerprint) VALUES (%s,%s,%s,%s::jsonb,%s) ON CONFLICT(fingerprint) DO NOTHING RETURNING id''',
      (rule['id'],rule['level'],ids,json.dumps(context),fingerprint))
    return cur.fetchone() is not None

def evaluate_once(cur, rules):
    fired=0
    new_events=cur.execute("SELECT * FROM events WHERE created_at >= now()-interval '24 hours' ORDER BY created_at,id").fetchall()
    if not new_events: return 0
    # Event UUIDs are not monotonic; durable detection scans a bounded horizon and relies on fingerprints.
    now=datetime.now(timezone.utc)
    for rule in rules.values():
        kind=rule['aggregation']['kind']; threshold=rule['aggregation'].get('threshold',0); seconds=rule['aggregation'].get('window_seconds',60)
        if kind in ('count_by','count_invalid_by'):
            invalid=(kind=='count_invalid_by')
            groups={}
            for e in new_events:
                age=(now-e['created_at'].astimezone(timezone.utc)).total_seconds()
                eligible=(e['event_type'].startswith('payment.') if not invalid else not e['signature_valid']) and age<=seconds
                if eligible: groups.setdefault(str(e['source_ip']),[]).append(e)
            for ip,events in groups.items():
                if len(events)>threshold:
                    key=f"{rule['id']}:{ip}:{now.strftime('%Y%m%d%H%M')}"
                    if insert_alert(cur,rule,events,{'source_ip':ip,'count':len(events),'window_seconds':seconds},key): fired+=1
        elif kind=='replay_by':
            groups={}
            for e in new_events: groups.setdefault((e['provider'],e['event_id']),[]).append(e)
            for (provider,eventid),events in groups.items():
                if len({e['signature'] for e in events})>1 or len({e['payload_hash'] for e in events})>1:
                    if insert_alert(cur,rule,events,{'provider':provider,'event_id':eventid,'distinct_signatures':len({e['signature'] for e in events}),'distinct_payloads':len({e['payload_hash'] for e in events})},f"{rule['id']}:{provider}:{eventid}"): fired+=1
        elif kind=='amount_baseline':
            successes=[e for e in new_events if e['event_type']=='payment.success' and e['amount'] is not None]
            samples=cur.execute("SELECT amount FROM events WHERE event_type='payment.success' AND amount IS NOT NULL AND created_at >= now()-interval '24 hours' AND created_at < now()-interval '1 minute'").fetchall()
            values=[float(x['amount']) for x in samples]
            if len(values)>=rule['aggregation']['minimum_samples']:
                mean=sum(values)/len(values); std=(sum((x-mean)**2 for x in values)/len(values))**0.5
            else: mean=None; std=None
            for e in successes:
                amount=float(e['amount']); anomaly=amount<=0 or (mean is not None and amount>mean+rule['aggregation']['z_score']*std)
                if anomaly:
                    context={'amount':amount,'baseline_mean':mean,'baseline_stddev':std,'sample_count':len(values)}
                    if insert_alert(cur,rule,[e],context,f"{rule['id']}:{e['id']}"): fired+=1
    return fired

def main():
    rules=load_rules(); print(f'loaded {len(rules)} rules',flush=True)
    while True:
        try:
            with db() as c:
                fired=evaluate_once(c,rules)
                if fired: print(json.dumps({'event':'alerts_fired','count':fired}),flush=True)
        except Exception as e: print(json.dumps({'event':'detector_error','error':str(e)}),flush=True)
        time.sleep(POLL)
if __name__=='__main__': main()
