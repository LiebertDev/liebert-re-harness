"""Offline PCAP/PCAPNG packet/conversation inspection (GAP-005) via dpkt
(BSD license, pure Python, zero native/driver dependency). Reads an
already-captured file only -- never opens a live capture device, never
touches Npcap. Both classic .pcap (dpkt.pcap.Reader) and .pcapng
(dpkt.pcapng.Reader, bundled in dpkt itself) are supported; format is
chosen by real magic bytes, not extension. Ethernet-linked captures only
(the common case); other link types are reported, not silently misparsed."""
from __future__ import annotations
import hashlib,io,json,socket
from collections import Counter
from tools_workspace import safe_path,relative

def _j(x):return json.dumps(x,ensure_ascii=False,indent=2,default=str)

_PROTO_NAMES={1:'ICMP',6:'TCP',17:'UDP',58:'ICMPv6'}
_TCP_FLAG_BITS=[(0x01,'FIN'),(0x02,'SYN'),(0x04,'RST'),(0x08,'PSH'),(0x10,'ACK'),(0x20,'URG')]

def _tcp_flags(flags):
    return '|'.join(name for bit,name in _TCP_FLAG_BITS if flags&bit) or '-'

def _addr(ip_data):
    import dpkt
    if isinstance(ip_data,dpkt.ip.IP):return socket.inet_ntoa(ip_data.src),socket.inet_ntoa(ip_data.dst),ip_data.p
    if isinstance(ip_data,dpkt.ip6.IP6):return socket.inet_ntop(socket.AF_INET6,ip_data.src),socket.inet_ntop(socket.AF_INET6,ip_data.dst),ip_data.nxt
    return None,None,None

_PCAPNG_MAGIC=b'\x0a\x0d\x0d\x0a'

def _decode_packets(data):
    import dpkt,dpkt.pcapng
    is_ng=data[:4]==_PCAPNG_MAGIC
    reader=dpkt.pcapng.Reader(io.BytesIO(data)) if is_ng else dpkt.pcap.Reader(io.BytesIO(data))
    if reader.datalink()!=dpkt.pcap.DLT_EN10MB:raise ValueError(f'UNSUPPORTED_LINKTYPE_{reader.datalink()}')
    rows=[]
    for ts,buf in reader:
        row={'timestamp':ts,'length':len(buf)}
        try:eth=dpkt.ethernet.Ethernet(buf)
        except Exception:rows.append({**row,'protocol':'MALFORMED_ETHERNET'});continue
        src,dst,proto=_addr(eth.data)
        if src is None:
            row['protocol']='NON_IP' if isinstance(eth.data,bytes) else type(eth.data).__name__.upper()
            rows.append(row);continue
        row.update(src_ip=src,dst_ip=dst,protocol=_PROTO_NAMES.get(proto,f'IP_PROTO_{proto}'))
        transport=eth.data.data
        if isinstance(transport,dpkt.tcp.TCP):
            row.update(src_port=transport.sport,dst_port=transport.dport,tcp_flags=_tcp_flags(transport.flags),payload_bytes=len(transport.data))
            row['_raw']=transport.data;row['_seq']=transport.seq
        elif isinstance(transport,dpkt.udp.UDP):
            row.update(src_port=transport.sport,dst_port=transport.dport,payload_bytes=len(transport.data))
            row['_raw']=transport.data
        rows.append(row)
    return rows

def _public_row(row):
    return {k:v for k,v in row.items() if not k.startswith('_')}

_MAX_REASSEMBLY_SPAN=64*1024*1024  # 64MB cap: bounded/fail-closed, not an unbounded allocation

def _reassemble_streams(rows):
    """Group packets into (src,sport,dst,dport,protocol) flows and reassemble
    each flow's payload bytes in order. TCP flows are reassembled by real
    sequence number (relative to the first-seen seq in that direction,
    handling 32-bit wraparound), deduplicating retransmitted/overlapping
    segments and recording any GAP (a byte range never observed in the
    capture) explicitly rather than silently concatenating out of order or
    pretending a partial capture is complete. UDP flows have no sequence
    numbers, so datagrams are concatenated in capture order (documented as
    such, not a byte-exact reassembly guarantee)."""
    flows={}  # key -> list of (seq_or_None, raw_bytes)
    for r in rows:
        if '_raw' not in r or not r['_raw']:continue
        key=(r['src_ip'],r.get('src_port'),r['dst_ip'],r.get('dst_port'),r['protocol'])
        flows.setdefault(key,[]).append((r.get('_seq'),r['_raw']))
    out={}
    for key,segs in flows.items():
        protocol=key[4]
        if protocol=='TCP' and segs[0][0] is not None:
            base=min(s for s,_ in segs)
            span=max(((s-base)&0xFFFFFFFF)+len(b) for s,b in segs)
            if span>_MAX_REASSEMBLY_SPAN:
                out[key]={'payload':None,'total_bytes':span,'error':'REASSEMBLY_SPAN_TOO_LARGE','gaps':None};continue
            buf=bytearray(span);written=bytearray(span)
            for s,b in segs:
                off=(s-base)&0xFFFFFFFF
                buf[off:off+len(b)]=b;written[off:off+len(b)]=b'\x01'*len(b)
            gaps=[];i=0
            while i<len(written):
                if written[i]==0:
                    j=i
                    while j<len(written) and written[j]==0:j+=1
                    gaps.append([i,j]);i=j
                else:i+=1
            out[key]={'payload':bytes(buf),'total_bytes':len(buf),'gaps':gaps}
        else:
            payload=b''.join(b for _,b in segs)
            out[key]={'payload':payload,'total_bytes':len(payload),'gaps':[] if protocol=='TCP' else None}
    return out

def _flow_key_str(key):
    src=f"{key[0]}:{key[1]}" if key[1] is not None else key[0]
    dst=f"{key[2]}:{key[3]}" if key[3] is not None else key[2]
    return f"{src}-{dst}"

def pcap_analyzer(path,operation='summary',max_items=300,query='',max_chars=60000):
    p=safe_path(path);max_items=max(1,min(int(max_items),5000));max_chars=max(1000,min(int(max_chars),400000))
    data=p.read_bytes()
    fmt='PCAPNG' if data[:4]==_PCAPNG_MAGIC else 'PCAP'
    try:rows=_decode_packets(data)
    except Exception as e:return _j({'ok':False,'tool':'pcap_analyzer','path':relative(p),'operation':operation,'format':fmt,'error':f'PCAP_PARSE_ERROR: {e}'})
    base={'ok':True,'tool':'pcap_analyzer','path':relative(p),'operation':operation,'format':fmt,'packet_count':len(rows)}
    if rows:base['capture_start']=rows[0]['timestamp'];base['capture_end']=rows[-1]['timestamp']
    if operation in {'summary','headers'}:
        proto_counts=Counter(r['protocol'] for r in rows)
        ips={x for r in rows if 'src_ip' in r for x in (r['src_ip'],r['dst_ip'])}
        return _j({**base,'protocol_counts':dict(proto_counts),'unique_ip_count':len(ips)})
    if operation=='packets':return _j({**base,'packets':[_public_row(r) for r in rows[:max_items]],'truncated':len(rows)>max_items})
    if operation=='conversations':
        convo=Counter();byte_totals=Counter()
        for r in rows:
            if 'src_ip' not in r:continue
            key=(r['src_ip'],r.get('src_port'),r['dst_ip'],r.get('dst_port'),r['protocol'])
            convo[key]+=1;byte_totals[key]+=r['length']
        vals=[{'src':f"{k[0]}:{k[1]}" if k[1] is not None else k[0],'dst':f"{k[2]}:{k[3]}" if k[3] is not None else k[2],'protocol':k[4],'packet_count':c,'total_bytes':byte_totals[k]} for k,c in convo.most_common(max_items)]
        return _j({**base,'conversations':vals,'truncated':len(convo)>max_items})
    if operation in {'streams','stream_payload'}:
        reassembled=_reassemble_streams(rows)
        if operation=='streams':
            items=[]
            for key,info in reassembled.items():
                payload=info['payload']
                entry={'flow':_flow_key_str(key),'src':f"{key[0]}:{key[1]}" if key[1] is not None else key[0],
                       'dst':f"{key[2]}:{key[3]}" if key[3] is not None else key[2],'protocol':key[4],
                       'total_bytes':info['total_bytes'],'gaps':info['gaps']}
                if payload is not None:
                    entry['sha256']=hashlib.sha256(payload).hexdigest()
                    entry['preview_hex']=payload[:32].hex()
                else:
                    entry['error']=info.get('error')
                items.append(entry)
            items.sort(key=lambda e:-e['total_bytes'])
            return _j({**base,'streams':items[:max_items],'truncated':len(items)>max_items})
        # stream_payload: query must exactly match one flow's 'src:port-dst:port' key (from a prior 'streams' call)
        match=next((info for key,info in reassembled.items() if _flow_key_str(key)==query),None)
        if match is None:
            return _j({**base,'ok':False,'error':'STREAM_NOT_FOUND','hint':"query must be 'src_ip:src_port-dst_ip:dst_port' from a prior operation=streams call"})
        payload=match['payload']
        if payload is None:
            return _j({**base,'ok':False,'error':match.get('error'),'total_bytes':match['total_bytes']})
        hexpayload=payload.hex()
        truncated=len(hexpayload)>max_chars
        return _j({**base,'query':query,'total_bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),
                   'gaps':match['gaps'],'payload_hex':hexpayload[:max_chars],'truncated':truncated})
    return _j({**base,'ok':False,'error':'UNSUPPORTED_PCAP_OPERATION'})
