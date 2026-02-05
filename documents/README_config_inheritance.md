# Configuration Inheritance System

This system allows you to create reusable base configurations and extend them for specific flows, eliminating duplication and making maintenance easier.

**Update:** You can now also define all personas and settings directly in the flow file if you prefer, and using a single base config (e.g., `base_config.json`) is fully supported. The `banking_config.json` file is now optional—most users can use just `base_config.json` plus flow-specific overrides.

## 📁 File Structure

```
configs/
├── base_config.json          # Common settings for all flows
└── banking_config.json       # (Optional) Banking-specific settings

documents/
└── README_config_inheritance.md  # (this file)

flows/
├── idor_xss_flow.json        # Extends base_config.json or defines all settings
└── banking_topup_flow.json   # Extends base_config.json or defines all settings
```

## 🔧 How It Works

### 1. Base Configuration (`configs/base_config.json`)

Contains common settings used across multiple flows:

```json
{
  "TARGET": "http://127.0.0.1:5000",
  "personas": {
    "user_A": {
      "username": "user_A@test.com",
      "password": "UserAPassword123"
    },
    "user_B": {
      "username": "user_B@test.com", 
      "password": "UserBPassword123"
    }
  },
  "VARIABLE_CONFIG": {
    "username": "flow",
    "password": "flow",
    "session_id": "flow"
  },
  "state": {
    "description": "default description"
  }
}
```

### 2. Extended Configuration (`configs/banking_config.json`) *(Optional)*

Extends base config and adds banking-specific settings:

```json
{
  "extends": "base_config.json",
  "personas": {
    "banking_user_A": {
      "username": "banking_user_A@test.com",
      "password": "BankingUserAPass123",
      "accountId": "ACC_101_001",
      "phoneNumber": "+1234567890"
    }
  },
  "VARIABLE_CONFIG": {
    "accountId": "flow",
    "phoneNumber": "flow",
    "transactionId": "flow"
  }
}
```

### 3. Flow Configuration (`flows/banking_topup_flow.json`)

You can now either extend a config or define all settings directly in the flow file:

```json
{
  "extends": "../configs/base_config.json", // or omit and define everything here
  "personas": {
    "banking_user_A": {
      "username": "banking_user_A@test.com",
      "password": "BankingUserAPass123",
      "accountId": "ACC_101_001",
      "phoneNumber": "+1234567890"
    }
  },
  "steps": [
    {
      "name": "Step 1: Login",
      "request": "1_login.txt",
      "required": true,
      "extract": {
        "session_id": { "json": "token" }
      }
    }
  ]
}
```

## 🎯 Benefits

### ✅ **Eliminates Duplication**
- Common settings defined once in base config
- No need to repeat TARGET, personas, VARIABLE_CONFIG across files

### ✅ **Easy Maintenance**
- Update base config to change all flows
- Override specific settings in extended configs or directly in flow files

### ✅ **Clear Hierarchy**
- Base → Extended → Flow specific (or just Base → Flow)
- Easy to understand what overrides what

### ✅ **Flexible Overrides**
- Deep merge supports nested object overrides
- Can override any setting at any level

## 🔄 Inheritance Chain

```
base_config.json
    ↓ (extends, optional)
banking_config.json  
    ↓ (extends, optional)
banking_topup_flow.json
```
Or simply:
```
base_config.json
    ↓
banking_topup_flow.json (with all settings)
```

**Merge Process:**
1. Load `base_config.json`
2. Load `banking_config.json` and merge with base (if used)
3. Load `banking_topup_flow.json` and merge with previous config(s)
4. Final config contains all settings with overrides applied

## 🚀 Usage Examples

### Running a Flow with Inheritance

```bash
# Run the banking top-up flow
python main.py run flows/banking_topup_flow.json

# Run the original IDOR/XSS flow  
python main.py run flows/idor_xss_flow.json
```

### Creating New Flows

1. **Create base config** (if needed):
   ```json
   {
     "TARGET": "http://127.0.0.1:5000",
     "personas": {...},
     "VARIABLE_CONFIG": {...}
   }
   ```

2. **Create extended config** (optional):
   ```json
   {
     "extends": "base_config.json",
     "personas": {
       "custom_user": {...}
     }
   }
   ```

3. **Create flow config** (can extend or define all settings):
   ```json
   {
     "extends": "../configs/custom_config.json",
     "steps": [...]
   }
   ```
   or
   ```json
   {
     "TARGET": "http://127.0.0.1:5000",
     "personas": {...},
     "steps": [...]
   }
   ```

## 🔍 Debugging

Enable verbose mode to see inheritance loading:

```bash
python main.py -v run flows/banking_topup_flow.json
```

Output:
```
[INFO] Loaded configuration from configs/base_config.json
[INFO] Loaded configuration from configs/banking_config.json (extends configs/base_config.json)
[INFO] Loaded configuration from flows/banking_topup_flow.json (extends configs/banking_config.json)
```

## 📝 Best Practices

1. **Keep base config minimal** - Only include truly common settings
2. **Use descriptive names** - `banking_config.json`, `ecommerce_config.json`
3. **Document overrides** - Comment why you're overriding base settings
4. **Test inheritance** - Verify merged configs work as expected
5. **Version control** - Track changes to base configs carefully 