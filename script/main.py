import pyshark
from collections import Counter
from collections import defaultdict

import argparse


iter = 50
cof = 1.0
tab = "\t"
 # stas2[fc_ds][bssid][da][fc_type][fc_subtype] += 1
 # stas3[fc_ds][bssid][sa][fc_type][fc_subtype] += 1
def print_dict_4(stas2, total_packets_stat2,ds=True):
    for fc_ds, bssid_dict in stas2.items():
        ds_count = sum(sum(
            sum(
                sum(subtype_dict.values()) for subtype_dict in type_dict.values()
            ) for type_dict in da_dict.values()
        ) for da_dict in bssid_dict.values() )
        ds_ratio = ds_count / total_packets_stat2 * 100
        fc_ds_str = fc_ds if fc_ds is not None else "None"
        print(tab + f"fc_ds: {fc_ds_str:<5} count: {ds_count:<5} ratio: {ds_ratio:>6.2f}%")
        
        for bssid, da_dict in bssid_dict.items():
            bssid_count = sum (sum(
                sum(subtype_dict.values()) for subtype_dict in type_dict.values()
            ) for type_dict in da_dict.values())
            bssid_ratio = bssid_count / total_packets_stat2 * 100
            bssid_str = bssid if bssid is not None else "None"
            if bssid_count < 20*cof:
                continue
            print(tab*2 + f"bssid: {bssid_str:<17} count: {bssid_count:<5} ratio: {bssid_ratio:>6.2f}%")
            
            for da, type_dict in da_dict.items():
                da_count = sum(
                    sum(subtype_dict.values()) for subtype_dict in type_dict.values()
                )
                da_ratio = da_count / total_packets_stat2 * 100
                da_str = da if da is not None else "None"
                if da_count < 10*cof:
                    continue
                if ds ==True:
                    print(tab*3 + f"da: {da_str:<17} count: {da_count:<5} ratio: {da_ratio:>6.2f}%")
                else :
                    print(tab*3 + f"sa: {da_str:<17} count: {da_count:<5} ratio: {da_ratio:>6.2f}%")
                
                for fc_type, subtype_dict in type_dict.items():
                    type_count = sum(subtype_dict.values())
                    type_ratio = type_count / total_packets_stat2 * 100
                    fc_type_str = fc_type if fc_type is not None else "None"
                    if type_count < 10*cof:
                        continue
                    print(tab*4 + f"fc_type: {fc_type_str:<5} count: {type_count:<5} ratio: {type_ratio:>6.2f}%")
                    
                    for fc_subtype, count in subtype_dict.items():
                        subtype_ratio = count / total_packets_stat2 * 100
                        fc_subtype_str = fc_subtype if fc_subtype is not None else "None"
                        if type_count < 10*cof:
                            continue
                        print(tab*5 + f"fc_subtype: {fc_subtype_str:<5} count: {count:<5} ratio: {subtype_ratio:>6.2f}%")
                    print('')
                print('')
            print('')
        print('')
    print('')

def print_dict_3(stats, total_packets):
    for fc_ds, type_dict in stats.items():
        ds_count = sum(
            sum(subtype_dict.values()) for subtype_dict in type_dict.values()
        )
        ds_ratio = ds_count / total_packets * 100
        fc_ds_str = fc_ds if fc_ds is not None else "None"
        print(tab + f"fc_ds: {fc_ds_str:<5} count: {ds_count:<5} ratio: {ds_ratio:>6.2f}%")
        
        for fc_type, subtype_dict in type_dict.items():
            type_count = sum(subtype_dict.values())
            type_ratio = type_count / total_packets * 100
            fc_type_str = fc_type if fc_type is not None else "None"
            if type_count < 50*cof:
                continue
            print(tab*2 + f"fc_type: {fc_type_str:<5} count: {type_count:<5} ratio: {type_ratio:>6.2f}%")
            
            for fc_subtype, count in subtype_dict.items():
                subtype_ratio = count / total_packets * 100
                fc_subtype_str = fc_subtype if fc_subtype is not None else "None"
                if count < 10*cof:
                    continue
                print(tab*3 + f"fc_subtype: {fc_subtype_str:<5} count: {count:<5} ratio: {subtype_ratio:>6.2f}%")
            print('')
        print('')
    print("")

def analyze_cap_file(file_path):
    """
    解析 .cap 文件并统计指定字段的取值及其频率。
    
    :param file_path: .cap 文件路径
    :param field_name: 要统计的字段名，例如 "wlan.fc.type_subtype"
    """

    # 使用 pyshark 解析 CAP 文件
    cap = pyshark.FileCapture(file_path, only_summaries=False)
    value_counter = Counter()
    
    # print(f"正在解析文件：{file_path}")
    # total = len(cap)
    # index = 0
    # print(dir (cap[0]['WLAN']))

    # print(cap[0]['WLAN'].get_field('fc_ds'))
    # print(cap[0]['WLAN'].get_field('fc.type'))
    # print(cap[0]['WLAN'].get_field('fc.subtype'))
    
    
    stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    stas2 = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(int)))))
    stas3 = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(int)))))


    index = 0
    total_retry = 0 
    for packet in cap:
        index += 1
        if index % 1000 == 0:
            print(f"已解析 {index}个数据包")
            if index / 1000 >= iter:
                break
        layer = packet['WLAN']

            # 检查字段是否存在于数据包中

        fc_ds = layer.get_field('fc_ds')
        fc_type = layer.get_field('fc.type')
        fc_subtype = layer.get_field('fc.subtype')

        fc_retry = layer.get_field('fc_retry')

        bssid = layer.get_field('bssid')
        da = layer.get_field('da')
        sa = layer.get_field('sa')
        
        
        #print(fc_retry=="True")


        if fc_retry == "True":
            stas2[fc_ds][bssid][da][fc_type][fc_subtype] += 1
            stas3[fc_ds][bssid][sa][fc_type][fc_subtype] += 1
            total_retry += 1




        # 更新计数
        stats[fc_ds][fc_type][fc_subtype] += 1

        # if fc_ds is None :
        #     print(packet)
            

    # 计算总包数
    total_packets = sum(
        sum(
            sum(subtype_dict.values()) for subtype_dict in type_dict.values()
        ) for type_dict in stats.values()
    )



    # print_dict_3(stats, total_packets)

    
    # 打印结果
    print("total_packets: ", total_packets)
    print("total_retry: ", total_retry)
    print("retry ratio: ", total_retry/total_packets*100)

    print("DA")
    print_dict_4(stas2, total_retry,ds=True)

    print("SA")
    print_dict_4(stas3, total_retry,ds=False)


# 示例用法
if __name__ == "__main__":
    # 输入文件路径和字段名

    arg = argparse.ArgumentParser()

    arg.add_argument("--input-path", type=str, default='../Bad_Total.cap', help="Path to the .cap file to analyze")
    arg.add_argument("--cof", type=float, default=1.0, help="cof")
    arg.add_argument("--iter", type=int, default=30, help="iter")

    args = arg.parse_args()
    cap_file_path = args.input_path
    cof = args.cof
    iter = args.iter

    analyze_cap_file(cap_file_path)