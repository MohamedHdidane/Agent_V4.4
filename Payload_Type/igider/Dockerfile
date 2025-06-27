FROM itsafeaturemythic/mythic_python_base:latest

WORKDIR /Mythic/

# Install PyInstaller and dependencies for executable building
RUN pip3 install pyinstaller

# Install cross-compilation tools for Windows executables on Linux
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
    wine \
    wine32 \
    wine64 \
    && rm -rf /var/lib/apt/lists/*


# Configure Wine for PyInstaller Windows builds
RUN wine --version || true

# Install Windows Python in Wine for cross-compilation (optional)
# RUN wget https://www.python.org/ftp/python/3.9.18/python-3.9.18-amd64.exe \
#     && wine python-3.9.18-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 \
#     && rm python-3.9.18-amd64.exe

# Install UPX for executable compression
RUN apt-get update && apt-get install -y upx-ucl && rm -rf /var/lib/apt/lists/*

# Create directory for build artifacts
RUN mkdir -p /tmp/build_cache

# Set environment variables for PyInstaller
ENV PYINSTALLER_CACHE_DIR=/tmp/build_cache
ENV WINE_PREFIX=/root/.wine

CMD ["python3", "main.py"]