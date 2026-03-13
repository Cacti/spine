import os
import re
import sys

# Prefixes to strip from the start of the format string
PREFIXES = ["DEBUG: ", "ERROR: ", "WARNING: ", "FATAL: ", "STATS: ", "NOTE: ", "DEVEL: ", "DEV: "]

def strip_prefix(inner_content):
    inner_content = inner_content.strip()
    for p in PREFIXES:
        if inner_content.startswith(f'"{p}'):
            return '"' + inner_content[len(p)+1:]
        elif inner_content.startswith(f"'{p}"):
            return "'" + inner_content[len(p)+1:]
    return inner_content

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    new_content = content

    # 1. Handle SPINE_LOG_DEV(host_id, level, ("format", args))
    # Match until the last )) before the next semicolon or end of statement.
    # We'll use a regex that looks for the pattern and then finds the balanced closing ))
    
    def find_balanced(text, start_index):
        # find the ((
        open_pos = text.find('((', start_index)
        if open_pos == -1: return None, None
        
        # find the matching ))
        stack = 0
        for i in range(open_pos, len(text) - 1):
            if text[i:i+2] == '((':
                stack += 1
                # i += 1 # skip next
            elif text[i:i+2] == '))':
                stack -= 1
                if stack == 0:
                    return open_pos, i + 2
        return None, None

    # Handle SPINE_LOG_DEV separately because it has 3 args where the last is ((...))
    dev_pattern = re.compile(r'SPINE_LOG_DEV\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*\(')
    offset = 0
    while True:
        match = dev_pattern.search(new_content, offset)
        if not match: break
        
        # Find the balanced parens for the 3rd argument
        # The 3rd arg starts with ( and should end with )
        # Wait, the legacy was SPINE_LOG_DEV(id, level, (format, args))
        # So it's 3 args, the 3rd is (format, args)
        
        # start searching from the start of the 3rd arg's (
        arg3_start = match.start(0) + match.string[match.start(0):].find(', (') + 2
        
        stack = 0
        arg3_end = -1
        for i in range(arg3_start, len(new_content)):
            if new_content[i] == '(':
                stack += 1
            elif new_content[i] == ')':
                stack -= 1
                if stack == 0:
                    arg3_end = i + 1
                    break
        
        if arg3_end != -1:
            host_id = match.group(1).strip()
            level = match.group(2).strip()
            inner = new_content[arg3_start+1:arg3_end-1].strip()
            inner = strip_prefix(inner)
            
            replacement = f'SPINE_LOG_DEV({host_id}, {level}, {inner})'
            new_content = new_content[:match.start(0)] + replacement + new_content[arg3_end+1:]
            offset = match.start(0) + len(replacement)
        else:
            offset = match.end(0)

    # 2. Handle standard SPINE_LOG[_XXX]((format, args))
    std_pattern = re.compile(r'(SPINE_LOG(?:_LOW|_MEDIUM|_HIGH|_DEBUG|_DEVDBG)?)\s*\(\s*\(')
    offset = 0
    while True:
        match = std_pattern.search(new_content, offset)
        if not match: break
        
        macro = match.group(1)
        inner_start = match.end(0)
        
        stack = 1 # we already matched one ( beyond the macro's (
        inner_end = -1
        for i in range(inner_start, len(new_content)):
            if new_content[i] == '(':
                stack += 1
            elif new_content[i] == ')':
                stack -= 1
                if stack == 0:
                    inner_end = i
                    break
        
        # We need one more ) for the macro call itself
        if inner_end != -1 and inner_end + 1 < len(new_content) and new_content[inner_end+1] == ')':
            inner = new_content[inner_start:inner_end].strip()
            inner = strip_prefix(inner)
            
            replacement = f'{macro}({inner})'
            new_content = new_content[:match.start(0)] + replacement + new_content[inner_end+2:]
            offset = match.start(0) + len(replacement)
        else:
            offset = match.end(0)

    if new_content != content:
        with open(filepath, 'w') as f:
            f.write(new_content)
        return True
    return False

def main():
    root_dir = '.'
    count = 0
    for root, dirs, files in os.walk(root_dir):
        if '.git' in root or '.deps' in root or '.worktrees' in root:
            continue
        for file in files:
            if file.endswith(('.c', '.h')):
                if file == 'refactor_logs.py':
                    continue
                filepath = os.path.join(root, file)
                if process_file(filepath):
                    print(f"Processed {filepath}")
                    count += 1
    print(f"Total files updated: {count}")

if __name__ == "__main__":
    main()
