#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复 CSV 文件以供 neo4j-admin import 使用

修复内容：
1. 将 \" 转换为标准的 "" (RFC 4180)
2. 处理字段中的实际 TAB 字符
3. 处理多行字段
4. 修复表头格式
5. 确保字段数量一致
sudo /opt/neo4j/bin/neo4j-admin import \
  --database=wordpress \
  --force \
  --id-type=STRING \
  --delimiter=TAB \
  --quote='"' \
  --multiline-fields=true \
  --nodes=wordpress_fixed/nodes.csv \
  --relationships=wordpress_fixed/rels.csv \
  --relationships=wordpress_fixed/cpg_edges.csv \
  --skip-duplicate-nodes=true \
  --skip-bad-relationships=true

"""

import sys
import csv
import re
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, total=None, desc=None):
        return iterable


def fix_csv_file(input_file, output_file, file_type='nodes', node_id_type='string'):
    """
    修复 CSV 文件
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
        file_type: 'nodes' 或 'rels'
        node_id_type: 节点 ID 类型（用于关系文件）
    """
    print(f"\n修复文件: {input_file}")
    print(f"输出到: {output_file}")
    print(f"类型: {file_type}")
    if file_type == 'rels':
        print(f"节点 ID 类型: {node_id_type}")
    print()
    
    # 统计行数
    with open(input_file, 'r', encoding='utf-8', errors='replace') as f:
        total_lines = sum(1 for _ in f)
    
    fixed_count = 0
    error_count = 0
    detected_id_type = node_id_type
    
    with open(input_file, 'r', encoding='utf-8', errors='replace') as infile, \
         open(output_file, 'w', encoding='utf-8', newline='') as outfile:
        
        # 读取原始表头
        header_line = infile.readline().strip()
        
        # 修复表头
        if file_type == 'nodes':
            fixed_header, detected_id_type = fix_node_header(header_line)
        else:
            fixed_header = fix_rel_header(header_line, node_id_type)
        
        print(f"原始表头: {header_line[:100]}...")
        print(f"修复表头: {fixed_header[:100]}...")
        print()
        
        # 写入修复后的表头
        outfile.write(fixed_header + '\n')
        
        # 解析表头以确定字段数
        headers = parse_header(fixed_header)
        expected_field_count = len(headers)
        
        print(f"预期字段数: {expected_field_count}")
        print(f"字段列表: {headers[:5]}...")
        print()
        
        # 处理数据行
        for line_num, line in enumerate(tqdm(infile, total=total_lines-1, desc="修复"), 1):
            try:
                # 修复这一行
                fixed_line = fix_data_line(line, expected_field_count, file_type)
                
                if fixed_line:
                    outfile.write(fixed_line + '\n')
                    fixed_count += 1
                    
            except Exception as e:
                error_count += 1
                if error_count <= 10:
                    print(f"\n⚠ 行 {line_num} 错误: {e}")
                continue
    
    print()
    print(f"✓ 修复完成")
    print(f"  成功: {fixed_count:,} 行")
    if error_count > 0:
        print(f"  错误: {error_count:,} 行")
    print()
    
    return detected_id_type


def fix_node_header(header):
    """
    修复节点文件表头
    返回: (修复后的表头, ID类型)
    """
    # 分割字段
    fields = header.split('\t')
    
    fixed_fields = []
    id_type = 'string'  # 默认类型
    
    for field in fields:
        field = field.strip().strip('"')
        
        # 修复类型名称：string_array → string[]
        field = field.replace('string_array', 'string[]')
        field = field.replace('int_array', 'int[]')
        field = field.replace('long_array', 'long[]')
        field = field.replace('float_array', 'float[]')
        field = field.replace('double_array', 'double[]')
        field = field.replace('boolean_array', 'boolean[]')
        
        # 修复常见的表头格式
        if field.lower() == 'id' or field.lower().startswith('id:'):
            # ID 字段：统一使用 :ID（不带类型）
            # neo4j-admin import 会根据 --id-type 参数决定类型
            field = 'id:ID'
            # 记录原始类型用于关系文件
            if ':int' in field.lower():
                id_type = 'int'
            elif ':long' in field.lower():
                id_type = 'long'
        elif 'label' in field.lower() and ':' not in field:
            field = ':LABEL'
        elif field.lower() == 'labels:label' or field.lower() == 'label:label':
            # 特殊处理 labels:label
            field = ':LABEL'
        elif 'type' in field.lower() and 'string' not in field.lower() and ':' not in field:
            # 避免将 :TYPE 添加到节点文件
            if field == 'type':
                field = 'type:string'
        elif ':' in field:
            # 已经有类型标注，保持不变
            pass
        else:
            # 普通字段，添加 string 类型
            if field and field not in [':LABEL', ':ID', 'id:ID']:
                field = field + ':string'
        
        fixed_fields.append(field)
    
    return '\t'.join(fixed_fields), id_type


def fix_rel_header(header, node_id_type='int'):
    """
    修复关系文件表头
    
    Args:
        header: 原始表头
        node_id_type: 节点 ID 的类型（从节点文件中获取）- 不使用，保留参数兼容性
    """
    # 分割字段
    fields = header.split('\t')
    
    fixed_fields = []
    for field in fields:
        field = field.strip().strip('"')
        
        # 修复类型名称：string_array → string[]
        field = field.replace('string_array', 'string[]')
        field = field.replace('int_array', 'int[]')
        field = field.replace('long_array', 'long[]')
        field = field.replace('float_array', 'float[]')
        field = field.replace('double_array', 'double[]')
        field = field.replace('boolean_array', 'boolean[]')
        
        # 修复常见的表头格式
        if 'start' in field.lower():
            # 不指定类型，让 Neo4j 自动匹配
            field = ':START_ID'
        elif 'end' in field.lower():
            # 不指定类型，让 Neo4j 自动匹配
            field = ':END_ID'
        elif 'type' in field.lower() and ':TYPE' not in field:
            field = ':TYPE'
        elif ':' in field:
            # 已经有类型标注，保持不变
            pass
        else:
            # 普通字段，添加 string 类型
            if field:
                field = field + ':string'
        
        fixed_fields.append(field)
    
    return '\t'.join(fixed_fields)


def parse_header(header):
    """解析表头，返回字段列表"""
    return header.split('\t')


def fix_data_line(line, expected_field_count, file_type):
    """
    修复数据行
    
    主要修复：
    1. \" → ""
    2. 处理字段中的实际 TAB
    3. 确保字段数量正确
    """
    line = line.rstrip('\n\r')
    if not line.strip():
        return None
    
    # 步骤 1: 修复转义引号 \" → ""
    # 但要小心不要破坏已经正确的 ""
    line = fix_escape_quotes(line)
    
    # 步骤 2: 分割字段
    fields = split_fields(line)
    
    # 步骤 3: 处理字段数量
    if len(fields) < expected_field_count:
        # 补齐空字段
        fields.extend([''] * (expected_field_count - len(fields)))
    elif len(fields) > expected_field_count:
        # 合并多余的字段（通常是 code 字段包含 TAB）
        fields = merge_extra_fields(fields, expected_field_count)
    
    # 步骤 4: 清理和标准化每个字段
    fixed_fields = []
    for field in fields:
        field = clean_field(field)
        fixed_fields.append(field)
    
    # 步骤 5: 重新组合为 CSV 行
    return '\t'.join(fixed_fields)


def fix_escape_quotes(text):
    """
    修复转义引号
    \" → ""
    但保留已经正确的 ""
    """
    # 这是一个复杂的问题，需要小心处理
    # 策略：在引号内的 \" 替换为 ""
    
    result = []
    i = 0
    in_quotes = False
    
    while i < len(text):
        char = text[i]
        
        if char == '"':
            # 检查是否是转义的引号 \"
            if i > 0 and text[i-1] == '\\':
                # 这是 \"，替换为 ""
                result[-1] = '"'  # 移除反斜杠
                result.append('"')
                i += 1
                continue
            else:
                # 普通引号，切换状态
                in_quotes = not in_quotes
                result.append(char)
        else:
            result.append(char)
        
        i += 1
    
    return ''.join(result)


def split_fields(line):
    """
    分割字段，处理引号内的 TAB
    """
    fields = []
    current_field = []
    in_quotes = False
    
    for char in line:
        if char == '"':
            in_quotes = not in_quotes
            current_field.append(char)
        elif char == '\t' and not in_quotes:
            # 字段分隔符
            fields.append(''.join(current_field))
            current_field = []
        else:
            current_field.append(char)
    
    # 添加最后一个字段
    if current_field:
        fields.append(''.join(current_field))
    
    return fields


def merge_extra_fields(fields, expected_count):
    """
    合并多余的字段
    通常是 code 字段（第6个）包含了 TAB
    """
    if len(fields) <= expected_count:
        return fields
    
    # 假设前5个字段是固定的
    result = fields[:5]
    
    # 合并中间的字段（code 字段）
    extra_count = len(fields) - expected_count
    code_parts = fields[5:5+extra_count+1]
    result.append('\t'.join(code_parts))
    
    # 添加剩余字段
    result.extend(fields[5+extra_count+1:])
    
    return result


def clean_field(field):
    """
    清理字段
    1. 去除首尾空白
    2. 确保引号正确
    3. 处理空字段
    """
    field = field.strip()
    
    # 如果字段为空
    if not field:
        return ''
    
    # 如果字段已经被引号包围
    if field.startswith('"') and field.endswith('"'):
        # 移除外层引号，清理内容，重新添加引号
        content = field[1:-1]
        
        # 确保内部的引号是双写的
        # 如果有单个 "，替换为 ""
        content = content.replace('""', '\x00')  # 临时标记
        content = content.replace('"', '""')     # 单引号变双引号
        content = content.replace('\x00', '""')  # 恢复标记
        
        return f'"{content}"'
    else:
        # 字段没有引号
        # 如果包含特殊字符（TAB, 换行, 引号），需要加引号
        if '\t' in field or '\n' in field or '"' in field or ',' in field:
            # 转义内部引号
            content = field.replace('"', '""')
            return f'"{content}"'
        else:
            return field


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='修复 CSV 文件以供 neo4j-admin import 使用')
    parser.add_argument('--nodes', default='nodes.csv', help='节点 CSV 文件')
    parser.add_argument('--rels', nargs='+', 
                       default=['rels.csv', 'cpg_edges.csv'], 
                       help='关系 CSV 文件')
    parser.add_argument('--output-dir', default='wordpress_fixed', help='输出目录')
    
    args = parser.parse_args()
    
    # 创建输出目录
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    print("=" * 70)
    print(" 修复 CSV 文件以供 neo4j-admin import 使用")
    print("=" * 70)
    
    # 修复节点文件，并获取 ID 类型
    nodes_input = Path(args.nodes)
    nodes_output = output_dir / nodes_input.name
    node_id_type = fix_csv_file(str(nodes_input), str(nodes_output), 'nodes')
    
    print(f"✓ 检测到节点 ID 类型: {node_id_type}\n")
    
    # 修复关系文件，使用相同的 ID 类型
    for rels_file in args.rels:
        rels_input = Path(rels_file)
        rels_output = output_dir / rels_input.name
        fix_csv_file(str(rels_input), str(rels_output), 'rels', node_id_type)
    
    print("=" * 70)
    print(" 所有文件修复完成！")
    print("=" * 70)
    print()
    print(f"修复后的文件位于: {output_dir}")
    print()
    print("下一步: 使用 neo4j-admin import 导入")
    print()
    print("示例命令:")
    print(f"sudo /opt/neo4j/bin/neo4j-admin import \\")
    print(f"  --database=wordpress \\")
    print(f"  --delimiter=TAB \\")
    print(f"  --quote='\"' \\")
    print(f"  --multiline-fields=true \\")
    print(f"  --nodes={output_dir}/nodes.csv \\")
    for rels_file in args.rels:
        rels_name = Path(rels_file).name
        print(f"  --relationships={output_dir}/{rels_name} \\")
    print(f"  --skip-duplicate-nodes=true \\")
    print(f"  --skip-bad-relationships=true")
    print()


if __name__ == "__main__":
    main()

