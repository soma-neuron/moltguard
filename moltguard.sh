#!/bin/bash
# moltguard - Skill file security scanner

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

scan_file() {
    local file="$1"
    echo ""
    echo "========================================"
    echo "Scanning: $file"
    echo "========================================"
    
    local critical=0
    local high=0
    local line_num=0
    
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        
        # Check for credential theft
        if echo "$line" | grep -qi "api_key\|\.env\|clawdbot.*credential"; then
            if echo "$line" | grep -qi "cat\|grep\|read"; then
                echo -e "${RED}CRITICAL (Line $line_num): Credential theft attempt${NC}"
                echo "  $line"
                critical=$((critical + 1))
            fi
        fi
        
        # Check for exfiltration
        if echo "$line" | grep -qi "webhook.site\|requestbin"; then
            echo -e "${RED}CRITICAL (Line $line_num): Known exfiltration endpoint${NC}"
            echo "  $line"
            critical=$((critical + 1))
        fi
        
        # Check for prompt injection
        if echo "$line" | grep -qi "\[IGNORE\]"; then
            echo -e "${ORANGE}HIGH (Line $line_num): Prompt injection - [IGNORE] tag${NC}"
            echo "  $line"
            high=$((high + 1))
        fi
        
        if echo "$line" | grep -qi "previous instructions"; then
            echo -e "${ORANGE}HIGH (Line $line_num): Prompt injection - override attempt${NC}"
            echo "  $line"
            high=$((high + 1))
        fi
        
    done < "$file"
    
    echo ""
    if [ $critical -eq 0 ] && [ $high -eq 0 ]; then
        echo -e "${GREEN}SAFE: No issues found${NC}"
    elif [ $critical -gt 0 ]; then
        echo -e "${RED}CRITICAL: $critical critical, $high high-risk issues${NC}"
        echo -e "${RED}DO NOT INSTALL${NC}"
    else
        echo -e "${ORANGE}WARNING: $high high-risk issues${NC}"
    fi
    echo "========================================"
}

if [ $# -eq 0 ]; then
    echo "Usage: moltguard.sh <skill-file.md>"
    exit 1
fi

for file in "$@"; do
    if [ -f "$file" ]; then
        scan_file "$file"
    else
        echo "File not found: $file"
    fi
done
