"""PCAP 实测解析、完整转发表校验与结果导出；不生成模型抓包。"""
from pathlib import Path
import collections, csv, html, json, re, struct

LINKS = [('Client1', 1, 'SW1', 1), ('Client2', 1, 'SW1', 3),
         ('SW1', 2, 'SW2', 1), ('Client3', 1, 'SW2', 3),
         ('SW2', 2, 'SW3', 1), ('Client4', 1, 'SW3', 3), ('Client5', 1, 'SW3', 2)]
EXPECTED = [
    [{}, {}, {}],
    [{1:1}, {1:1}, {1:1}],
    [{1:1,2:3}, {1:1,2:1}, {1:1,2:1}],
    [{1:1,2:3,3:2}, {1:1,2:1,3:3}, {1:1,2:1,3:1}],
    [{1:1,2:3,3:2}, {1:1,2:1,3:3,4:2}, {1:1,2:1,3:1,4:3}],
    [{1:1,2:3,3:2}, {1:1,2:1,3:3,4:2}, {1:1,2:1,3:1,4:3,5:2}],
]


def mac(text):
    return re.sub('[^0-9a-f]', '', text.lower())


def expected_links(step):
    if step <= 3:
        return {a+'-'+b for a,_,b,_ in LINKS}
    if step == 4:
        return {'Client4-SW3','SW2-SW3','Client3-SW2'}
    return {'Client5-SW3','Client4-SW3'}


def tables(folder, step, manifest):
    issues, output = [], {}
    mapping = {mac(v['mac']): int(k[-1]) for k,v in manifest['pcs'].items()}
    for sw in range(1,4):
        name=f'SW{sw}'; text=(folder/f'step-{step}'/f'{name}.txt').read_text(encoding='utf-8')
        rows=re.findall(r'([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+(\d+)\s+-\s+-\s+Eth0/0/(\d+)\s+dynamic',text,re.I)
        actual={}
        for address,vlan,port in rows:
            client=mapping.get(mac(address))
            if client is None or vlan!='1':
                issues.append(f'{name} 出现额外表项 {address} / VLAN {vlan}')
            else:
                actual[client]=int(port)
        wanted=EXPECTED[step][sw-1]
        if actual!=wanted:
            issues.append(f'{name} 实测 {actual}，预期 {wanted}')
        if not re.search(r'Aging time:\s*0\s+seconds',text):
            issues.append(f'{name} 老化时间回读异常')
        output[name]=actual
    return output,issues


def frames(path):
    b=Path(path).read_bytes()
    formats={b'\xd4\xc3\xb2\xa1':('<',1_000_000),b'\xa1\xb2\xc3\xd4':('>',1_000_000),
             b'\x4d\x3c\xb2\xa1':('<',1_000_000_000),b'\xa1\xb2\x3c\x4d':('>',1_000_000_000)}
    if len(b)<24 or b[:4] not in formats:
        raise ValueError('需要 Ethernet PCAP 文件；请在 Wireshark 另存为 pcap。')
    end,scale=formats[b[:4]]
    if struct.unpack_from(end+'I',b,20)[0]!=1:
        raise ValueError('抓包链路类型不是 Ethernet。')
    off=24; number=0
    while off<len(b):
        if off+16>len(b):raise ValueError('PCAP 尾部尚未写完，请先停止抓包。')
        sec,sub,n,wire=struct.unpack_from(end+'IIII',b,off);off+=16
        if off+n>len(b):raise ValueError('PCAP 帧尚未写完，请先停止抓包。')
        packet=b[off:off+n];off+=n;number+=1
        yield number,sec+sub/scale,packet,wire


def inspect(path, manifest):
    mapping={bytes.fromhex(mac(v['mac'])):int(k[-1]) for k,v in manifest['pcs'].items()}
    bridges={bytes.fromhex(mac(v['mac'])):k for k,v in manifest['switches'].items()}
    signatures=set();rows=[]
    sequence=[tuple(x) for x in manifest['sequence']]
    for number,ts,p,wire in frames(path):
        # 由启动阶段的真实 STP BPDU 确认物理接口；不向实验中补发探测帧。
        if len(p)>=44 and p[14:17]==b'\x42\x42\x03' and p[17:19]==b'\0\0':
            sw=bridges.get(p[36:42]);port=int.from_bytes(p[42:44],'big')&0xfff
            if sw and 1<=port<=3:signatures.add((sw,port))
        if len(p)<42 or p[12:14]!=b'\x08\x00':continue
        src=mapping.get(p[6:12]);dst=mapping.get(p[:6]);ip=p[14:]
        if src is None or dst is None or ip[9]!=17:continue
        pair=(src,dst)
        if pair not in sequence:continue
        ihl=(ip[0]&15)*4
        if ihl<20 or len(ip)<ihl+8:continue
        sp,dp,ul,_=struct.unpack_from('!HHHH',ip,ihl)
        payload=ip[ihl+8:ihl+ul]
        step=sequence.index(pair)+1
        rows.append({'frame':number,'step':step,'source':src,'destination':dst,
                     'source_mac':p[6:12].hex(':'),'destination_mac':p[:6].hex(':'),
                     'source_ip':'.'.join(map(str,ip[12:16])),'destination_ip':'.'.join(map(str,ip[16:20])),
                     'ip_length':struct.unpack_from('!H',ip,2)[0],'udp_length':ul,
                     'source_port':sp,'destination_port':dp,'data':payload.hex(),'frame_length':wire})
    matches=[]
    for a,ap,b,bp in LINKS:
        ends={(n,p) for n,p in [(a,ap),(b,bp)] if n.startswith('SW')}
        if signatures and signatures<=ends:matches.append(a+'-'+b)
    link=matches[0] if len(matches)==1 else None
    return {'file':str(Path(path).resolve()),'link':link,'port_signatures':sorted(signatures),'packets':rows}


def check_packets(captures):
    issues=[];by_link=collections.defaultdict(list)
    for cap in captures:
        if cap['link']:by_link[cap['link']].append(cap)
        else:issues.append('抓包链路未识别：'+Path(cap['file']).name)
        for p in cap['packets']:
            wanted=(f'192.0.2.{p["source"]}',f'192.0.2.{p["destination"]}',1,1,29,9,f'{p["step"]:02x}')
            actual=tuple(p[k] for k in ['source_ip','destination_ip','source_port','destination_port','ip_length','udp_length','data'])
            if actual!=wanted:issues.append(f'{Path(cap["file"]).name} 第{p["step"]}步报文字段不符：{actual}')
    for a,_,b,_ in LINKS:
        link=a+'-'+b
        if len(by_link[link])!=1:
            issues.append(f'{link} 需唯一一份完整抓包，现有 {len(by_link[link])} 份');continue
        counts=collections.Counter(p['step'] for p in by_link[link][0]['packets'])
        for step in range(1,6):
            wanted=1 if link in expected_links(step) else 0
            if counts[step]!=wanted:issues.append(f'{link} 第{step}步帧数 {counts[step]}，预期 {wanted}')
    return issues


def write_summary(folder, manifest, steps, captures, issues):
    folder=Path(folder);folder.mkdir(exist_ok=True,parents=True)
    data={'kind':'新副本实测结果','manifest':manifest,'steps':steps,'captures':captures,'issues':issues,
          'passed':len(steps)==6 and not issues}
    (folder/'核对结果.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    rows=['# 交换机自学习实测结果','',f'本轮校验：{"通过" if data["passed"] else "待核查"}。','',
          '## 五台 PC 地址','', '| PC | MAC | IPv4 |','|---|---|---|']
    for name,v in sorted(manifest['pcs'].items()):rows.append(f'| {name} | {v["mac"]} | {v["ip"]} |')
    rows+=['','## 逐步实测 MAC 表','','| 步骤 | SW1 | SW2 | SW3 |','|---|---|---|---|']
    for s in steps:
        texts=['；'.join(f'C{n}→E0/0/{p}' for n,p in sorted(t.items(),key=lambda x:int(x[0]))) or '空' for t in s['tables'].values()]
        rows.append('| '+str(s['step'])+' | '+' | '.join(texts)+' |')
    rows+=['','## 报文与转发观察','','| 链路 | 实测出现的步骤 |','|---|---|']
    for c in captures:rows.append(f'| {c["link"] or Path(c["file"]).name} | '+','.join(str(p['step']) for p in c['packets'])+' |')
    if data['passed']:
        rows+=['','前三步的未知目的单播在七条链路上泛洪。第4步沿 Client4→SW3→SW2→Client3 单播；第5步在 SW3 内由 Client5 转发到 Client4。交换机通过帧的源 MAC 与入端口建立映射。',
               '', '五个指定 UDP 报文的 IPv4 总长度均为29字节，UDP长度为9字节，应用数据为1字节。EtherType为0x0800，源／目的UDP端口均为1，数据依次为01、02、03、04、05。']
    else:
        rows+=['','## 待核查项','']+['- '+x for x in issues]
    text='\n'.join(rows)+'\n';(folder/'实测结果.md').write_text(text,encoding='utf-8')
    with (folder/'逐步实测MAC表.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f);w.writerow(['数据性质','步骤','交换机','PC','MAC','接口'])
        for s in steps:
            for sw,table in s['tables'].items():
                for n,p in table.items():w.writerow(['实测',s['step'],sw,f'Client{n}',manifest['pcs'][f'Client{n}']['mac'],f'E0/0/{p}'])
    escaped=html.escape(text)
    (folder/'结果总览.html').write_text('<!doctype html><meta charset="utf-8"><title>交换机自学习实测结果</title><style>body{max-width:1100px;margin:40px auto;font:18px/1.8 "Microsoft YaHei",sans-serif}pre{white-space:pre-wrap}h1{font-size:28px}</style><h1>交换机自学习实测结果</h1><pre>'+escaped+'</pre>',encoding='utf-8')
    return data
