"""在新一轮实测全部通过、四张截图齐备后，填充现有课程报告副本。"""
from pathlib import Path
from copy import deepcopy
import argparse, json, re, sys
from docx import Document
from docx.shared import Cm, Pt
from docx.oxml.ns import qn
from console_status import Activity, session_log

ROOT=Path(__file__).resolve().parent
PICTURES=[('01-拓扑.png','图1 实验拓扑'),('02-泛洪.png','图2 第1步未知目的单播泛洪'),
          ('03-单播.png','图3 第4步单播与第5步上联链路观察'),('04-本地转发.png','图4 第5步SW3本地转发')]


def set_paragraph(p,text):
    prop=deepcopy(p.runs[0]._r.rPr) if p.runs and p.runs[0]._r.rPr is not None else None
    for child in list(p._p):
        if child.tag!=qn('w:pPr'):p._p.remove(child)
    r=p.add_run(text)
    if prop is not None:r._r.insert(0,prop)


def set_cell(cell,text):
    p=cell.paragraphs[0];set_paragraph(p,text)
    for other in cell.paragraphs[1:]:other._p.getparent().remove(other._p)
    for r in p.runs:
        r.font.size=Pt(10.5);r.font.name='宋体'
        r._r.get_or_add_rPr().rFonts.set(qn('w:eastAsia'),'宋体')


def fill(source,output,data,pictures):
    if not data['passed'] or len(data['steps'])!=6:
        raise ValueError('本轮实测尚未全部通过，不生成完成版报告。')
    if output.exists():raise FileExistsError('报告已存在；请另存后再生成，保留已有修改。')
    d=Document(source);manifest=data['manifest'];seq=manifest['sequence']
    mac_table=next(t for t in d.tables if t.cell(0,0).text.strip()=='主机')
    actual=next(t for t in d.tables if 'SW1地址' in re.sub(r'\s','',''.join(c.text for c in t.rows[0].cells)))
    packet=next(t for t in d.tables if '出现该帧的链路' in ''.join(c.text for c in t.rows[0].cells))
    for row,name in enumerate([f'Client{x}' for x in range(1,6)],1):set_cell(mac_table.cell(row,1),manifest['pcs'][name]['mac'])
    for step in range(1,6):
        s=data['steps'][step]
        for col,sw in enumerate(['SW1','SW2','SW3'],1):
            entries='；'.join(f'C{n}:E{p}' for n,p in sorted(s['tables'][sw].items(),key=lambda x:int(x[0])))
            action=('泛洪' if step<=3 else '单播' if sw=='SW3' or (step==4 and sw=='SW2') else '保持原表')
            set_cell(actual.cell(step,col),entries+'\n'+action)
        src,dst=seq[step-1]
        set_cell(packet.cell(step,1),manifest['pcs'][f'Client{src}']['mac']+'\n→'+manifest['pcs'][f'Client{dst}']['mac'])
        links=[c['link'] for c in data['captures'] if any(p['step']==step for p in c['packets'])]
        set_cell(packet.cell(step,2),'；'.join(links))
        set_cell(packet.cell(step,3),f'IPv4: 192.0.2.{src}→192.0.2.{dst}\nIP长度29；UDP 1→1，长度9\n数据{step:02x}')
    for table in [actual,packet]:
        for row in table.rows:
            for h in row._tr.findall('./'+qn('w:trPr')+'/'+qn('w:trHeight')):h.set(qn('w:hRule'),'atLeast')
    captions={p.text:p for p in d.paragraphs}
    anchor=captions.get('拓扑及抓包图：')
    if anchor is None:raise ValueError('报告图片锚点缺失，停止以保留模板结构。')
    for filename,title in pictures:
        # 在原图片锚点前插入图片与题注，章节、封面、守则、页脚不变。
        p=anchor.insert_paragraph_before('');p.paragraph_format.first_line_indent=Pt(0)
        p.add_run().add_picture(str(filename),width=Cm(14.2))
        p=anchor.insert_paragraph_before(title);p.paragraph_format.first_line_indent=Pt(0)
    set_paragraph(anchor,'')
    for p in d.paragraphs:
        if p.text=='现场观察：':
            set_paragraph(p,'现场观察：五次指定UDP发送后的三台MAC表均与逐步学习结果一致。前三步在七条链路出现指定帧；第4步仅沿Client4→SW3→SW2→Client3转发；第5步在SW3的Client5与Client4端口之间转发。')
        elif p.text.startswith('————————————————'):
            set_paragraph(p,'')
    d.core_properties.author='';d.core_properties.last_modified_by=''
    d.save(output)
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template',type=Path,required=True,help='本地课程报告底稿副本')
    parser.add_argument('--student-id',required=True,help='已确认的学号，仅写入本地文件名')
    parser.add_argument('--name',required=True,help='已确认的姓名，仅写入本地文件名')
    args=parser.parse_args()
    if not args.student_id.isdigit() or any(c in args.name for c in '<>:"/\\|?*'):
        raise ValueError('学号或姓名格式无效')
    run_id=(ROOT/'最新一轮.txt').read_text(encoding='ascii').strip()
    if not re.fullmatch(r'\d{8}-\d{6}-\d{6}',run_id):raise ValueError('最新一轮标记无效。')
    folder=ROOT/'records'/run_id
    data=json.loads((folder/'results/核对结果.json').read_text(encoding='utf-8'))
    missing=[name for name,_ in PICTURES if not (folder/'screenshots'/name).is_file()]
    if missing:raise ValueError('请把必要截图放入 '+str(folder/'screenshots')+'：'+'、'.join(missing))
    pictures=[(folder/'screenshots'/name,title) for name,title in PICTURES]
    output=folder/f'实验2-{args.student_id}-{args.name}.docx'
    if output.resolve()==args.template.resolve():raise ValueError('输出须另存为报告副本')
    fill(args.template,output,data,pictures)
    print('报告已生成：'+str(output))
    print('请在Word查看图片和分页，并按现场补齐封面的同组人、地点、日期。')


if __name__=='__main__':
    with session_log(ROOT):
        try:
            with Activity('核对实测结果、填充表格和四张截图、保存Word报告'):
                main()
        except Exception as e:print('整理停止：'+str(e));sys.exit(1)
