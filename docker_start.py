import subprocess
import sys
import time
import requests
import os

def run_command(command, cwd=None):
    """Run a command and return success status"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            cwd=cwd, 
            capture_output=True, 
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def check_docker():
    """Check if Docker is installed and running"""
    print("Checking Docker...")
    success, stdout, stderr = run_command("docker --version")
    if not success:
        print("ERROR: Docker is not installed or not in PATH")
        return False
    
    print(f"SUCCESS: Docker found: {stdout.strip()}")
    
    # Check if Docker daemon is running
    success, stdout, stderr = run_command("docker info")
    if not success:
        print("ERROR: Docker daemon is not running")
        print("   Please start Docker Desktop or Docker daemon")
        return False
    
    print("SUCCESS: Docker daemon is running")
    return True

def build_and_start():
    """Build and start all services"""
    print("Building and starting Inspy Security with Docker...")
    print("=" * 60)
    
    # Check Docker
    if not check_docker():
        return False
    
    # Build frontend first
    print("\nBuilding React Frontend...")
    success, stdout, stderr = run_command("cd frontend && npx vite build")
    if not success:
        print(f"ERROR: Frontend build failed: {stderr}")
        return False
    print("SUCCESS: Frontend built successfully")
    
    # Build extension
    print("\nBuilding Chrome Extension...")
    success, stdout, stderr = run_command("python build_extension_simple.py")
    if not success:
        print(f"ERROR: Extension build failed: {stderr}")
        return False
    print("SUCCESS: Extension built successfully")
    
    # Build and start Docker containers
    print("\nBuilding Docker containers...")
    success, stdout, stderr = run_command("docker-compose build")
    if not success:
        print(f"ERROR: Docker build failed: {stderr}")
        return False
    print("SUCCESS: Docker containers built successfully")
    
    # Start services
    print("\nStarting services...")
    success, stdout, stderr = run_command("docker-compose up -d")
    if not success:
        print(f"ERROR: Failed to start services: {stderr}")
        return False
    print("SUCCESS: Services started successfully")
    
    # Wait for services to be ready
    print("\nWaiting for services to be ready...")
    time.sleep(10)
    
    # Test services
    print("\nTesting services...")
    
    # Test backend
    try:
        response = requests.get("http://localhost:8000/", timeout=10)
        if response.status_code == 200:
            print("SUCCESS: Backend is running at http://localhost:8000")
        else:
            print(f"WARNING: Backend responded with status: {response.status_code}")
    except Exception as e:
        print(f"WARNING: Backend test failed: {e}")
    
    # Test frontend
    try:
        response = requests.get("http://localhost:3000/", timeout=10)
        if response.status_code == 200:
            print("SUCCESS: Frontend is running at http://localhost:3000")
        else:
            print(f"WARNING: Frontend responded with status: {response.status_code}")
    except Exception as e:
        print(f"WARNING: Frontend test failed: {e}")
    
    print("\nInspy Security System is ready!")
    print("=" * 60)
    print("Access Points:")
    print("   Frontend Dashboard: http://localhost:3000")
    print("   Backend API: http://localhost:8000")
    print("   API Documentation: http://localhost:8000/docs")
    print("   Chrome Extension: build/InspyGuard_extension/")
    print("\nNext Steps:")
    print("   1. Load the Chrome extension from build/InspyGuard_extension/")
    print("   2. Visit the dashboard at http://localhost:3000")
    print("   3. Test file uploads to see real-time security monitoring")
    print("\nTo stop: docker-compose down")
    
    return True

def stop_services():
    """Stop all Docker services"""
    print("Stopping services...")
    success, stdout, stderr = run_command("docker-compose down")
    if success:
        print("SUCCESS: Services stopped successfully")
    else:
        print(f"ERROR: Failed to stop services: {stderr}")

def show_logs():
    """Show logs from all services"""
    print("Showing service logs...")
    success, stdout, stderr = run_command("docker-compose logs -f")
    if not success:
        print(f"ERROR: Failed to show logs: {stderr}")

def main():
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "stop":
            stop_services()
        elif command == "logs":
            show_logs()
        elif command == "restart":
            stop_services()
            time.sleep(2)
            build_and_start()
        else:
            print("Usage: python docker_start.py [start|stop|logs|restart]")
    else:
        build_and_start()

if __name__ == "__main__":
    main()
