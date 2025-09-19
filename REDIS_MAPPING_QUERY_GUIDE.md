# Redis Mapping Query Guide

This document explains how external services can query endpoint mappings stored in Redis by the Heimdall Admin Service.

## Redis Data Structure

### Core Data (Permanent Storage)

```redis
# All mapping details
heimdall:mappings:all -> Hash
  field: "mapping_{id}"
  value: JSON string with mapping details

# Pattern lists by HTTP method (ordered by specificity)
heimdall:mappings:patterns:GET -> List
heimdall:mappings:patterns:POST -> List
heimdall:mappings:patterns:PUT -> List
heimdall:mappings:patterns:DELETE -> List
  [mapping_1, mapping_3, mapping_7, ...]
```

### Cache Layer (Automatic TTL)

```redis
# Fast lookup cache (TTL: configurable, default 5 minutes)
heimdall:mappings:lookup:{METHOD}:{EXACT_PATH} -> String
  "mapping_{id}"
```

## Query Algorithm for External Services

### Method 1: Fast Path Lookup (Recommended)

For most use cases, try the fast path first:

```bash
# Step 1: Check cache for exact path match
CACHE_KEY="heimdall:mappings:lookup:GET:/api/v1/users/123"
MAPPING_ID=$(redis-cli GET "$CACHE_KEY")

if [ -n "$MAPPING_ID" ]; then
    # Step 2: Get mapping details
    MAPPING_DATA=$(redis-cli HGET "heimdall:mappings:all" "$MAPPING_ID")
    echo "$MAPPING_DATA" | jq .
else
    # Cache miss - need pattern matching (see Method 2)
fi
```

### Method 2: Pattern Matching (Fallback)

When cache misses, iterate through patterns:

```bash
METHOD="GET"
REQUEST_PATH="/api/v1/users/123"

# Step 1: Get all patterns for the HTTP method
PATTERNS=$(redis-cli LRANGE "heimdall:mappings:patterns:$METHOD" 0 -1)

# Step 2: Test each pattern until match found
for MAPPING_ID in $PATTERNS; do
    # Get the mapping details
    MAPPING_DATA=$(redis-cli HGET "heimdall:mappings:all" "$MAPPING_ID")
    PATH_PATTERN=$(echo "$MAPPING_DATA" | jq -r .path_pattern)
    
    # Test if request path matches the pattern (pseudo-code)
    if [[ "$REQUEST_PATH" =~ $PATH_PATTERN ]]; then
        echo "Match found: $MAPPING_DATA"
        
        # Optional: Cache the result for future lookups
        redis-cli SETEX "heimdall:mappings:lookup:$METHOD:$REQUEST_PATH" 300 "$MAPPING_ID"
        break
    fi
done
```

## Example Mapping Data Structure

```json
{
  "id": 1,
  "method": "GET",
  "path_pattern": "/heimdall-admin/api/v1/users/(.*)",
  "action_id": 5,
  "action_name": "user:read",
  "description": "Get user information",
  "created_at": "2025-09-19T10:00:00Z",
  "updated_at": "2025-09-19T10:00:00Z"
}
```

## Language-Specific Examples

### Python Example

```python
import redis
import json
import re

def get_required_action(method: str, path: str) -> dict:
    r = redis.Redis(host='localhost', port=6379, db=0)
    
    # Step 1: Try cache
    cache_key = f"heimdall:mappings:lookup:{method}:{path}"
    mapping_id = r.get(cache_key)
    
    if mapping_id:
        # Step 2: Get mapping details
        mapping_data = r.hget("heimdall:mappings:all", mapping_id)
        return json.loads(mapping_data)
    
    # Step 3: Pattern matching fallback
    pattern_key = f"heimdall:mappings:patterns:{method}"
    mapping_ids = r.lrange(pattern_key, 0, -1)
    
    for mapping_id in mapping_ids:
        mapping_data = r.hget("heimdall:mappings:all", mapping_id)
        mapping = json.loads(mapping_data)
        
        if re.match(mapping["path_pattern"], path):
            # Cache the result
            r.setex(cache_key, 300, mapping_id)  # 5 min TTL
            return mapping
    
    return None  # No match found

# Usage
action_info = get_required_action("GET", "/api/v1/users/123")
if action_info:
    print(f"Required action: {action_info['action_name']}")
```

### Go Example

```go
package main

import (
    "encoding/json"
    "regexp"
    "github.com/go-redis/redis/v8"
)

type Mapping struct {
    ID          int    `json:"id"`
    Method      string `json:"method"`
    PathPattern string `json:"path_pattern"`
    ActionID    int    `json:"action_id"`
    ActionName  string `json:"action_name"`
    Description string `json:"description"`
}

func GetRequiredAction(rdb *redis.Client, method, path string) (*Mapping, error) {
    // Step 1: Try cache
    cacheKey := fmt.Sprintf("heimdall:mappings:lookup:%s:%s", method, path)
    mappingID, err := rdb.Get(ctx, cacheKey).Result()
    
    if err == nil {
        // Step 2: Get mapping details
        mappingData, err := rdb.HGet(ctx, "heimdall:mappings:all", mappingID).Result()
        if err == nil {
            var mapping Mapping
            json.Unmarshal([]byte(mappingData), &mapping)
            return &mapping, nil
        }
    }
    
    // Step 3: Pattern matching fallback
    patternKey := fmt.Sprintf("heimdall:mappings:patterns:%s", method)
    mappingIDs, err := rdb.LRange(ctx, patternKey, 0, -1).Result()
    if err != nil {
        return nil, err
    }
    
    for _, mappingID := range mappingIDs {
        mappingData, err := rdb.HGet(ctx, "heimdall:mappings:all", mappingID).Result()
        if err != nil {
            continue
        }
        
        var mapping Mapping
        json.Unmarshal([]byte(mappingData), &mapping)
        
        matched, _ := regexp.MatchString(mapping.PathPattern, path)
        if matched {
            // Cache the result
            rdb.SetEX(ctx, cacheKey, mappingID, 5*time.Minute)
            return &mapping, nil
        }
    }
    
    return nil, nil // No match found
}
```

## Performance Characteristics

- **Cache Hit**: O(1) - Single Redis GET + HGET
- **Cache Miss**: O(n) - Where n is the number of patterns for the HTTP method
- **Memory Usage**: Scales with number of unique paths accessed
- **Cache Efficiency**: High for repeated access patterns

## Notes

- Patterns are stored in order of specificity (most specific first)
- Cache keys include both method and exact path for precision
- All core mapping data persists permanently (no TTL)
- Only the lookup cache has TTL for automatic cleanup
- When mappings change, the core data is updated (not deleted)