#!/usr/bin/env bash

for f in captures/*.pcap; do
  out="alerts/$(basename "$f" .pcap).csv"
  ./build/pcap2alerts "$f" rules.txt "$out"
done

for f in alerts/*.csv; do
  n=$(($(wc -l < "$f") - 1))
  printf "%5d  %s\n" "$n" "$(basename "$f")"
done | sort -nr | head