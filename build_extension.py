import os
import shutil
import zipfile
from datetime import datetime

def build_extension():
    print("🔨 Building Inspy Security Chrome Extension...")
    print("=" * 50)
    
    # Create build directory
    build_dir = "build"
    extension_dir = os.path.join(build_dir, "InspyGuard_extension")
    
    # Clean and create build directory
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)
    os.makedirs(extension_dir)
    
    # Copy extension files
    extension_files = [
        "manifest.json",
        "popup.html", 
        "popup.js",
        "content.js",
        "background.js",
        "icon16.png"
    ]
    
    utils_dir = os.path.join(extension_dir, "utils")
    os.makedirs(utils_dir)
    
    copied_files = []
    for file in extension_files:
        src = os.path.join("InspyGuard_extension", file)
        dst = os.path.join(extension_dir, file)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            copied_files.append(file)
            print(f"✅ Copied {file}")
        else:
            print(f"❌ Missing {file}")
    
    # Copy utils directory
    utils_src = os.path.join("InspyGuard_extension", "utils", "rules.js")
    utils_dst = os.path.join(utils_dir, "rules.js")
    if os.path.exists(utils_src):
        shutil.copy2(utils_src, utils_dst)
        copied_files.append("utils/rules.js")
        print("✅ Copied utils/rules.js")
    
    # Create ZIP package
    zip_path = os.path.join(build_dir, "InspyGuard_extension.zip")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(extension_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arc_path = os.path.relpath(file_path, extension_dir)
                zipf.write(file_path, arc_path)
    
    print(f"\n📦 Extension built successfully!")
    print(f"   Build directory: {build_dir}/")
    print(f"   Extension folder: {extension_dir}/")
    print(f"   ZIP package: {zip_path}")
    print(f"   Files included: {len(copied_files)}")
    
    return build_dir, extension_dir, zip_path

if __name__ == "__main__":
    build_extension()