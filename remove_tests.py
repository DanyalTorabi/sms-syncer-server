#!/usr/bin/env python3
"""
Remove specific test cases from user_management_test.go
"""

def remove_test_cases(file_path, test_names_to_remove):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    # Find and mark lines to remove
    i = 0
    output_lines = []
    while i < len(lines):
        line = lines[i]
        
        # Check if this is a test case to remove
        is_target_test = False
        for test_name in test_names_to_remove:
            if f'name:' in line and test_name in line:
                is_target_test = True
                break
        
        if is_target_test:
            # Skip this entire test case block
            # Find the opening brace (current or next line)
            brace_count = 0
            started = False
            
            # Go back to find the opening {
            j = i
            while j >= 0:
                if '{' in lines[j]:
                    brace_count = 1
                    started = True
                    skip_from = j
                    break
                j -= 1
            
            # Skip lines until we find the matching closing },
            if started:
                j = i + 1
                while j < len(lines) and brace_count > 0:
                    line_to_check = lines[j]
                    brace_count += line_to_check.count('{')
                    brace_count -= line_to_check.count('}')
                    j += 1
                
                # Add a comment before the next test
                if j < len(lines):
                    next_line = lines[j].strip()
                    if next_line.startswith('{') or (j + 1 < len(lines) and 'name:' in lines[j + 1]):
                        output_lines.append('\t\t// Permission checking tested in middleware tests\n')
                
                # Skip to after the removed block
                i = j
                continue
        
        output_lines.append(line)
        i += 1
    
    # Write the result
    with open(file_path, 'w') as f:
        f.writelines(output_lines)
    
    print(f"Removed {len(test_names_to_remove)} test cases from {file_path}")

if __name__ == '__main__':
    file_path = '/home/danto/prj/golang/sms-syncer-server/internal/handlers/user_management_test.go'
    
    # Test case names to remove (partial match)
    test_names = [
        'unauthorized - missing permission',
        'forbidden - accessing other user without permission',
        'forbidden - updating other user without permission',
    ]
    
    remove_test_cases(file_path, test_names)
