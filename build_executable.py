"""
Phase 5: PyInstaller Build Script
Compiles AeroGuard IDS into standalone Windows .exe with optional LLM bundling.
"""

import PyInstaller.__main__  # type: ignore
import os
import sys
import shutil
from pathlib import Path

def build_executable(include_ollama: bool = False):
    """
    Build production-ready .exe using PyInstaller.
    
    Args:
        include_ollama: Bundle local Ollama model (~2GB) for offline capability
    """
    
    project_root = Path(__file__).parent
    dist_dir = project_root / "dist"
    build_dir = project_root / "build"
    
    # Clean previous builds
    for directory in [dist_dir, build_dir]:
        if directory.exists():
            shutil.rmtree(directory)
            print(f"Cleaned {directory}")
    
    # Core dependencies
    hidden_imports = [
        "streamlit",
        "nfstream",
        "pyshark",
        "scapy",
        "psutil",
        "joblib",
        "sklearn",
        "google.generativeai",
        "requests",
        "fastapi",
        "uvicorn",
        "jwt"
    ]
    
    # Collect data files
    datas = [
        (str(project_root / "nstream_model.pkl"), "."),
        (str(project_root / "nstream_scaler.pkl"), "."),
        (str(project_root / "nstream_features.pkl"), "."),
        (str(project_root / "nstream_app_encoder.pkl"), "."),
        (str(project_root / "whitelist.json"), "."),
        (str(project_root / "config.json"), "."),
    ]
    
    if include_ollama:
        print("⚠️  Including Ollama model (this will significantly increase bundle size)")
        datas.append((str(project_root / ".ollama"), "."))
    
    # Build command
    build_args = [
        "--name=AeroGuard",
        f"--distpath={dist_dir}",
        f"--buildpath={build_dir}",
        "--onefile",
        "--windowed",
        "--console",
        f"--icon={project_root / 'icon.ico'}" if (project_root / "icon.ico").exists() else "",
        "--collect-all=streamlit",
        "--collect-all=nfstream",
        "--hidden-import=sklearn",
        *[f"--hidden-import={lib}" for lib in hidden_imports],
        *[f"--add-data={data}" for data in datas],
        "--bootloader-ignore-signals",
        str(project_root / "app.py"),
    ]
    
    # Remove empty strings
    build_args = [arg for arg in build_args if arg]
    
    print("🔨 Building AeroGuard IDS executable...")
    print(f"PyInstaller args: {build_args}")
    
    try:
        PyInstaller.__main__.run(build_args)
        exe_path = dist_dir / "AeroGuard.exe"
        
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"\n✅ Build successful!")
            print(f"📦 Executable: {exe_path}")
            print(f"📊 Size: {size_mb:.2f} MB")
            return str(exe_path)
        else:
            print("❌ Build completed but .exe not found")
            return None
            
    except Exception as e:
        print(f"❌ Build failed: {e}")
        return None

if __name__ == "__main__":
    include_ollama = "--with-ollama" in sys.argv
    
    if include_ollama:
        print("Building with bundled Ollama support (Lightweight variant)...")
    else:
        print("Building standard variant (Cloud-only LLM)...")
    
    exe_path = build_executable(include_ollama=include_ollama)
    
    if exe_path:
        print(f"\n🎉 AeroGuard IDS is ready for deployment!")
        print(f"Located at: {exe_path}")
