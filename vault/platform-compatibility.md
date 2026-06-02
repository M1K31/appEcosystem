# Platform Compatibility

## Supported Platforms
| Platform | Status | Notes |
|----------|--------|-------|
| Intel macOS (Homebrew) | Fully supported | Primary development platform |
| ARM Linux (Pi 4+) | Fully supported | Pure Python dependencies |
| Intel Linux | Fully supported | Standard pip install |

## Python Version
- Minimum: 3.10
- Recommended: 3.12

## Dependencies
All dependencies are pure Python or have pre-built wheels for all platforms:
- fastapi, uvicorn, pydantic, pyyaml, httpx, zeroconf

## Raspberry Pi Notes
No special configuration needed. All dependencies install cleanly via pip on Raspberry Pi OS Bookworm.
