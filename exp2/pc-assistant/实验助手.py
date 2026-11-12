"""用户启动的新副本助手：回读预填、单次发送、逐步校验、收存实测抓包。"""
from pathlib import Path
from datetime import datetime
import argparse, hashlib, json, os, shutil, socket, subprocess, sys, time, traceback

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from collect_switches import collect
from evidence import tables, inspect, check_packets, write_summary
from console_status import Activity, confirm, disable_quick_edit, session_log
from capture_sessions import active_paths, checkpoint, export_window


def read_manifest():
    return json.loads((ROOT/'manifest.json').read_text(encoding='utf-8'))


def wait_ready(manifest, timeout=180):
    workspace=Path(os.environ['LOCALAPPDATA'])/'eNSP/VBoxServer/workspaces'
    end=time.monotonic()+timeout
    states=[]
    with Activity(f'检查设备就绪（最多{timeout}秒）',total=3) as activity:
        while time.monotonic()<end:
            ready=0;states=[]
            for sw,v in manifest['switches'].items():
                cfg=workspace/v['id']/'slot17/hardcfg.tcl'
                if not cfg.is_file():
                    states.append(f'{sw}：等待新工程启动资源');continue
                if ('SetDeviceID '+v['id']) not in cfg.read_text(encoding='utf-8',errors='replace'):
                    states.append(f'{sw}：运行资源与新工程ID不符');continue
                try:
                    with socket.create_connection(('127.0.0.1',v['port']),timeout=.3):pass
                except OSError:
                    states.append(f'{sw}：等待Console {v["port"]}');continue
                states.append(f'{sw}：Console已就绪');ready+=1
            activity.update('；'.join(states),ready,3)
            if ready==3:break
            time.sleep(1)
        else:
            raise RuntimeError('设备等待超时：'+'；'.join(states)+'。此阶段尚未清表或发包。请检查新工程是否已启动。')
    with Activity('核对三个Console所属进程（最多15秒）') as activity:
        ports=','.join(map(str,manifest['ports']))
        command=f'@(Get-NetTCPConnection -State Listen -LocalPort {ports} | Select-Object -ExpandProperty OwningProcess -Unique) | ConvertTo-Json -Compress'
        try:
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],capture_output=True,check=True,timeout=15)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError('查询Console所属进程超过15秒，已停止；此阶段尚未清表或发包。') from exc
        pids=json.loads(result.stdout.decode('utf-8-sig').strip())
        if isinstance(pids,int):pids=[pids]
        if len(pids)!=1:raise RuntimeError('新副本三个 Console 的进程归属不一致，停止。')
        activity.update('三个Console属于同一个eNSP进程')
        return pids[0]


def temp_pcaps():
    result=set()
    for p in Path(os.environ['TEMP']).glob('wireshark*'):
        if not p.is_file():continue
        try:
            with p.open('rb') as f:magic=f.read(4)
        except OSError:continue
        if magic in [b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d']:
            result.add(p)
    return result


def live_captures():
    return active_paths(temp_pcaps())


def capture_status():
    return f'已检测到 {len(live_captures())}/7 份正在运行的抓包（先开抓包、后开助手也可）'


def require_captures():
    """在任何PC参数设置、清表和发包之前拦住未准备好的抓包。"""
    while True:
        selected=live_captures()
        count=len(selected)
        if count==7:
            print('[抓包准备检查通过] 已检测到7份正在运行的抓包；可沿用助手启动前已经打开的窗口。',flush=True)
            return selected
        print(f'\n[抓包尚未准备好] 目前 {count}/7 份；尚未修改PC参数、清表或发包。',flush=True)
        print('本助手不会自动弹出Wireshark。请在eNSP中右键每条黑色连线，选择“开始抓包/抓包”。',flush=True)
        print('七条链路：Client1—SW1、Client2—SW1、SW1—SW2、Client3—SW2、SW2—SW3、Client4—SW3、Client5—SW3。',flush=True)
        if count>7:
            print('检测到多余抓包。请保存并关闭重复窗口，使本轮每条链路只保留一份。',flush=True)
        else:
            print('正常情况下会打开七个Wireshark窗口；若没有弹出，请在eNSP的工具设置中指定本机wireshark.exe路径。',flush=True)
        confirm('七条链路抓包准备好后，按回车重新检查',status=capture_status)


def import_captures(destination, selections, manifest, progress=None):
    captures=[];issues=[]
    if not selections:
        issues.append('本轮没有记录抓包选择，请保留七份实测PCAP并核查。')
        return captures,issues
    raw_folder=destination/'raw';raw_folder.mkdir(exist_ok=True)
    for n,selection in enumerate(selections,1):
        p=Path(selection['file'])
        if progress:progress(f'收存第{n}/{len(selections)}份：{p.name}',n-1,len(selections))
        target=destination/f'链路待识别-{n:02d}.pcap'
        try:
            stat=p.stat()
            if [stat.st_dev,stat.st_ino]!=selection['file_identity']:
                raise ValueError('抓包文件已被替换，请勿在实验中关闭或重开捕获。')
            raw=raw_folder/(f'{n:02d}-'+p.name+'.pcap')
            shutil.copyfile(p,raw)
            old_info=inspect(raw,manifest)
            export_window(raw,target,selection)
            result=inspect(target,manifest)
            result['link']=old_info['link'] or selection['link_hint'] or result['link']
            result['raw_file']=str(raw.resolve())
            result['excluded_previous_frames']=selection['start_frame']
            if result['link']:
                named=destination/(result['link']+'.pcap')
                if named.exists():
                    issues.append(f'{result["link"]} 有重复抓包，已保留原文件供核查。')
                else:
                    target.rename(named);result['file']=str(named.resolve())
            captures.append(result)
        except (OSError,ValueError) as e:
            issues.append(target.name+'：'+str(e))
        if progress:progress(f'第{n}份已收存并解析',n,len(selections))
    issues.extend(check_packets(captures))
    return captures,issues


def check_project(manifest):
    from build_copy import load
    topo=load(ROOT/manifest['project']);devs=topo.findall('./devices/dev')
    assert len(devs)==8
    assert sum(d.get('model')=='PC' for d in devs)==5
    assert len(topo.findall('./lines/line'))==7
    assert sorted(int(d.get('com_port')) for d in devs if d.get('model')=='S3700')==manifest['ports']
    ids={d.get('name'):d.get('id') for d in devs}
    for name,v in {**manifest['switches'],**manifest['pcs']}.items():assert ids[name]==v['id']
    print('静态核对通过：独立 ID、端口 2120～2122、五台 PC、七条链路。未连接设备、未发送报文。')


def recheck(folder,manifest):
    folder=folder.resolve()
    if ROOT not in folder.parents:raise ValueError('核对目录须位于新副本内部。')
    state=json.loads((folder/'state.json').read_text(encoding='utf-8'))
    steps=state['steps'];issues=list(state['table_issues']);captures=[]
    paths=sorted((folder/'captures').glob('*.pcap'))
    with Activity('重新核对已保存抓包',total=len(paths) or None) as activity:
        for n,p in enumerate(paths,1):
            activity.update('解析 '+p.name,n-1,len(paths))
            try:
                cap=inspect(p,manifest)
                if not cap['link'] and p.stem in ['Client1-SW1','Client2-SW1','SW1-SW2','Client3-SW2','SW2-SW3','Client4-SW3','Client5-SW3']:
                    cap['link']=p.stem
                captures.append(cap)
            except ValueError as e:issues.append(p.name+'：'+str(e))
            activity.update(p.name+' 已解析',n,len(paths))
    issues+=check_packets(captures)
    data=write_summary(folder/'results',manifest,steps,captures,issues)
    print('核对通过。' if data['passed'] else '仍有待核查项，请查看结果总览。')
    return 0 if data['passed'] else 1


def run(manifest):
    from pc_windows import PCWindows
    print('交换机自学习 简化版\n')
    print('1. 在 eNSP 打开本目录的“交换机自学习_简化版.topo”，启动全部设备。')
    print('2. 依次打开五台 PC，均切到“UDP发包工具”，保持五个窗口打开，不点击发送。')
    print('3. 本助手不自动弹出Wireshark：请在七条链路上分别右键→“开始抓包/抓包”，每条各一份。')
    print('   已经开启的七份链路抓包可以继续使用，不必为了重启助手而重复开启。')
    print('   PC累计发送计数无需清零；助手会记录本轮起点，再核对每步只增加1。')
    confirm('准备设备、五个UDP页和七条链路抓包',status=capture_status)
    process_id=wait_ready(manifest)
    selected=require_captures()
    ui=PCWindows(Path(manifest['project']).stem,process_id)
    dialogs=[];send_counts={}
    # 所有 PC 先一次性准备好，再初始化交换机；五步间不关闭窗口、不改地址。
    with Activity('预填五个PC的UDP参数',total=5) as activity:
        for step,(src,dst) in enumerate(manifest['sequence'],1):
            source=manifest['pcs'][f'Client{src}'];destination=manifest['pcs'][f'Client{dst}']
            ui.progress=lambda detail:activity.update(f'Client{src}→Client{dst} / {detail}',step-1,5)
            dialog=ui.find(f'Client{src}',source['mac'])
            before=ui.prepare(dialog,source,destination,step)
            dialogs.append(dialog)
            send_counts[f'Client{src}']={'before':before,'after':None,'sent_this_round':0}
            activity.update(f'Client{src}→Client{dst} 参数回读通过',step,5)
            print(f'Client{src} → Client{dst} 参数已填写并回读：29字节、端口1、数据{step:02x}；累计计数{before}作为本轮起点。',flush=True)
    with Activity('固定七份抓包并记录本轮起始位置',total=7) as activity:
        selections=checkpoint(selected,manifest,progress=activity.update)
    run_id=datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    folder=ROOT/'records'/run_id;folder.mkdir(parents=True)
    for sub in ['captures','results','screenshots']:(folder/sub).mkdir()
    (ROOT/'最新一轮.txt').write_text(run_id,encoding='ascii')
    (folder/'capture_selection.json').write_text(json.dumps(selections,ensure_ascii=False,indent=2),encoding='utf-8')
    issues=[];steps=[];captures=[]
    try:
        with Activity('第0步：初始化并回读三台交换机') as activity:
            collect(manifest['ports'],0,True,folder,progress=activity.update)
            actual,errors=tables(folder,0,manifest)
            steps.append({'step':0,'tables':actual});issues+=errors
            if errors:raise RuntimeError('初始化校验不通过：'+'；'.join(errors))
            activity.update('三台空表、STP关闭、老化时间0，回读通过')
        for step,dialog in enumerate(dialogs,1):
            src,dst=manifest['sequence'][step-1]
            with Activity(f'第{step}/5步：Client{src}→Client{dst}，发送并采集') as activity:
                ui.progress=lambda detail:activity.update(detail)
                audit=send_counts[f'Client{src}']
                audit['after']=ui.send_once(dialog,expected_before=audit['before'])
                audit['sent_this_round']=audit['after']-audit['before']
                time.sleep(.25)
                collect(manifest['ports'],step,False,folder,progress=activity.update)
                actual,errors=tables(folder,step,manifest)
                steps.append({'step':step,'tables':actual});issues+=errors
                if errors:raise RuntimeError(f'第{step}步完整表校验失败：'+'；'.join(errors))
                activity.update('三台完整MAC表校验通过')
            print(f'[实验进度 {step}/5] 第 {step} 步发送一次，三台交换机完整 MAC 表校验通过。',flush=True)
    except Exception as e:
        issues.append(str(e))
        (folder/'diagnostic.txt').write_text(traceback.format_exc(),encoding='utf-8')
        print('\n实验在异常处停止：'+str(e))
    finally:
        (folder/'state.json').write_text(json.dumps({'steps':steps,'table_issues':issues,'send_counts':send_counts},ensure_ascii=False,indent=2),encoding='utf-8')
    print('\n请在七个 Wireshark 窗口分别点击红色“停止”。保持窗口打开，助手会直接收存文件。')
    confirm('请停止七个Wireshark抓包，保持窗口打开，完成后按回车')
    with Activity('收存并解析七条链路实测抓包',total=7) as activity:
        captures,capture_issues=import_captures(folder/'captures',selections,manifest,progress=activity.update)
    issues+=capture_issues
    with Activity('整理实测表格、报文核对与结果说明') as activity:
        data=write_summary(folder/'results',manifest,steps,captures,issues)
        activity.update('结果已写入本轮 results 目录')
    print('\n本轮目录：'+str(folder))
    if data['passed']:
        print('五步 MAC 表、七条链路路径和报文字段全部通过。现在按 README.md 的截图清单保存现场截图。')
    else:
        print('本轮有待核查项，已保留真实记录。请查看 results\\实测结果.md；不要直接重复点击发送。')
    try:os.startfile(folder/'results/结果总览.html')
    except OSError:pass
    return 0 if data['passed'] else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--recheck',type=Path)
    parser.add_argument('--demo-progress',action='store_true',help='只演示状态显示，不连接设备、不发包')
    args=parser.parse_args();manifest=read_manifest()
    if args.check:check_project(manifest);return 0
    if args.demo_progress:
        print('进度显示演示：不是实验记录，不连接设备、不发包。')
        with Activity('演示：设备准备',total=3,interval=.2) as activity:
            for n in range(1,4):
                time.sleep(.25);activity.update(f'演示检查项{n}完成',n,3)
        return 0
    if args.recheck:return recheck(args.recheck,manifest)
    return run(manifest)


if __name__=='__main__':
    with session_log(ROOT):
        try:
            disable_quick_edit()
            sys.exit(main())
        except KeyboardInterrupt:
            print('\n[用户已退出] 助手停止；已有记录保留，后续发送不会继续。',flush=True)
            sys.exit(130)
        except Exception as e:
            print('\n[助手已停止] '+str(e),flush=True)
            print('请按提示处理后重新开始整轮；已有记录保留在 records 中。',flush=True)
            traceback.print_exc()
            sys.exit(1)
