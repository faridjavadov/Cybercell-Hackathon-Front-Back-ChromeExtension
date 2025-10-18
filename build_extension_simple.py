import os
import shutil

def build_extension():
    print("Building Chrome Extension...")
    print("=" * 50)
    
    build_dir = "build"
    extension_dir = os.path.join(build_dir, "InspyGuard_extension")
    
    # Clean and create build directory
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)
    os.makedirs(extension_dir)
    
    # List of files to copy
    extension_files = [
        "manifest.json",
        "popup.html", 
        "popup.js",
        "content.js",
        "background.js",
        "icon16.png",
        "verify.js",
        "inject.js"
    ]
    
    # Create utils directory
    utils_dir = os.path.join(extension_dir, "utils")
    os.makedirs(utils_dir)
    
    # Copy files
    copied_files = []
    for file in extension_files:
        src = os.path.join("InspyGuard_extension", file)
        dst = os.path.join(extension_dir, file)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            copied_files.append(file)
            print(f"Copied {file}")
        else:
            print(f"Missing {file}")
    
    # Copy utils file
    utils_src = os.path.join("InspyGuard_extension", "utils", "rules.js")
    utils_dst = os.path.join(utils_dir, "rules.js")
    if os.path.exists(utils_src):
        shutil.copy2(utils_src, utils_dst)
        copied_files.append("utils/rules.js")
        print("Copied utils/rules.js")
    
    print(f"Extension built successfully!")
    print(f"Build directory: {build_dir}/")
    print(f"Extension folder: {extension_dir}/")
    print(f"Files included: {len(copied_files)}")
    
    return True

if __name__ == "__main__":
    build_extension()