import asyncio
import glob
import os
import subprocess
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

class FlowContent(BaseModel):
    content: str
    path: str

@app.get("/projects")
async def list_projects():
    projects_dir = PROJECT_ROOT / "projects"
    if not projects_dir.exists():
        return []
    projects = [d.name for d in projects_dir.iterdir() if d.is_dir()]
    return sorted(projects)

@app.get("/flows/{project_name}")
async def list_flows(project_name: str):
    flows_dir = PROJECT_ROOT / "projects" / project_name / "flows"
    if not flows_dir.exists():
        return []
    
    flows = []
    # Support both .yaml and .json
    for ext in ["*.yaml", "*.yml", "*.json"]:
        flows.extend(glob.glob(str(flows_dir / ext)))
    
    # Return relative paths
    result = []
    for f in sorted(flows):
        path_obj = Path(f)
        try:
            rel_path = path_obj.relative_to(PROJECT_ROOT)
            result.append({"name": path_obj.name, "path": str(rel_path).replace("\\", "/")})
        except ValueError:
            pass # Should not happen
            
    return result

@app.get("/file")
async def get_file(path: str):
    # Security check: ensure path is within project root
    # Sanitize path to prevent traversal
    safe_path = (PROJECT_ROOT / path).resolve()
    if not str(safe_path).startswith(str(PROJECT_ROOT)):
         raise HTTPException(status_code=403, detail="Access denied")
    
    if not safe_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    content = safe_path.read_text(encoding="utf-8")
    return {"content": content, "path": path}

@app.post("/file")
async def save_file(flow: FlowContent):
    safe_path = (PROJECT_ROOT / flow.path).resolve()
    if not str(safe_path).startswith(str(PROJECT_ROOT)):
         raise HTTPException(status_code=403, detail="Access denied")
    
    with open(safe_path, "w", encoding="utf-8") as f:
        f.write(flow.content)
    
    return {"status": "saved"}

@app.websocket("/ws/run")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        command = data.get("command") # "run" or "fuzz"
        flow_path = data.get("flow_path")
        
        if not command or not flow_path:
            await websocket.send_text("Error: Missing command or flow_path")
            await websocket.close()
            return
            
        # Basic validation of command to avoid arbitrary execution
        if command not in ["run", "fuzz", "baseline"]:
             await websocket.send_text(f"Error: Invalid command {command}")
             await websocket.close()
             return

        cmd_args = ["python", "-u", "main.py", command, flow_path] # -u for unbuffered output
        # Add --async if desired, or let user specify? backend can force it for now or not.
        # Note: if we run sync, it blocks the thread, but we are in subprocess so it's fine.
        
        # Run subprocess and stream output
        process = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(PROJECT_ROOT)
        )

        while True:
            line = await process.stdout.readline()
            if not line:
                break
            await websocket.send_text(line.decode('utf-8', errors='replace'))

        await process.wait()
        await websocket.send_text(f"\nExample process finished with exit code {process.returncode}")
        await websocket.close()

    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print(f"Error: {e}")
        try:
            await websocket.send_text(f"Error: {str(e)}")
            await websocket.close()
        except:
            pass

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
