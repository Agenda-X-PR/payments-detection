import argparse, hashlib, hmac, json, os, time, urllib.error, urllib.request, uuid
from datetime import datetime, timezone

API=os.getenv('API_URL','http://localhost:8002').rstrip('/')
SECRET=os.getenv('WEBHOOK_SECRET','replace-with-at-least-32-random-characters')

def send(event_id,event_type='payment.success',amount=1250.0,ip='198.51.100.42',valid=True,provider='demo'):
    payload={'event_id':event_id,'event_type':event_type,'amount':amount,'currency':'NGN','order_id':'ord_'+event_id,'created_at':datetime.now(timezone.utc).isoformat()}
    raw=json.dumps(payload,separators=(',',':')).encode()
    sig=hmac.new(SECRET.encode(),raw,hashlib.sha256).hexdigest() if valid else 'invalid-demo-signature'
    req=urllib.request.Request(f'{API}/webhooks/{provider}',data=raw,headers={'Content-Type':'application/json','X-Webhook-Signature':sig,'X-Event-Id':event_id,'X-Event-Type':event_type,'X-Source-IP':ip},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=10) as response: return json.loads(response.read())
    except urllib.error.HTTPError as e: raise RuntimeError(f'API returned {e.code}: {e.read().decode()}')

def main():
    parser=argparse.ArgumentParser(description='Synthetic local-only webhook test harness')
    subs=parser.add_subparsers(dest='mode',required=True)
    normal=subs.add_parser('normal'); normal.add_argument('--rate',default='20/min'); normal.add_argument('--duration',default='15s')
    attack=subs.add_parser('attack'); attack.add_argument('kind',choices=['velocity','replay','sigfail','amount']); attack.add_argument('--count',type=int,default=15); attack.add_argument('--window',default='10s'); attack.add_argument('--event-id',default='evt_replay_demo'); attack.add_argument('--value',type=float,default=10000000)
    a=parser.parse_args()
    if a.mode=='normal':
        rate=float(a.rate.split('/')[0]); interval=60/rate; duration=float(a.duration[:-1]) if a.duration.endswith('s') else float(a.duration)
        n=max(1,int(duration/interval)); print(f'Sending {n} synthetic normal events to {API}')
        for i in range(n): send('normal_'+uuid.uuid4().hex[:12]); time.sleep(interval)
    elif a.kind=='velocity':
        print(f'Sending {a.count} synthetic events to {API}')
        for i in range(a.count): send(f'velocity_{uuid.uuid4().hex[:10]}')
    elif a.kind=='replay':
        print(f'Sending same synthetic event ID twice with changed body/signature to {API}')
        send(a.event_id,amount=1250); send(a.event_id,amount=8750)
    elif a.kind=='sigfail':
        print(f'Sending {a.count} synthetic invalid-signature events to {API}')
        for i in range(a.count): send(f'sigfail_{uuid.uuid4().hex[:10]}',valid=False,event_type='payment.failed')
    elif a.kind=='amount':
        print(f'Sending synthetic amount anomaly to {API}')
        send('amount_'+uuid.uuid4().hex[:10],amount=a.value)
    print('Done. Wait up to the detector polling interval, then inspect the dashboard/API.')
if __name__=='__main__': main()
