#!/bin/bash
# compile_tools.sh

echo "=== Compiling Penetration Testing Tools ==="

echo "1. Compiling http_hammer..."
gcc -O3 -march=native -pthread -D BUFFER_SIZE=512 http_hammer.c -o http_hammer
if [ $? -eq 0 ]; then
  echo "✓ http_hammer compiled successfully"
  chmod +x http_hammer
else
  echo "✗ http_hammer compilation failed"
  exit 1
fi

echo "2. Compiling slowloris..."
gcc -O3 -march=native -pthread slowloris.c -o slowloris
if [ $? -eq 0 ]; then
  echo "✓ slowloris compiled successfully"
  chmod +x slowloris
else
  echo "✗ slowloris compilation failed"
  exit 1
fi

echo "3. Verifying binaries..."
file http_hammer slowloris

echo "=== Compilation Complete ==="
echo "Binaries created: http_hammer, slowloris"
